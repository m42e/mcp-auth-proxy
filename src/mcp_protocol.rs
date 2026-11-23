use anyhow::Result;
use serde_json::{json, Map, Value};

pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

const CLIENT_NAME: &str = "mcp-auth-proxy";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Outcome of evaluating an MCP `server/discover` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    ModernWithTools,
    ModernNoTools,
    Legacy(&'static str),
    MethodNotFound,
}

/// Build a modern MCP request with the required per-request client metadata.
pub fn modern_request(method: &str, id: Value, version: &str) -> Value {
    let mut params = Map::new();
    params.insert(
        "_meta".to_string(),
        json!({
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {
                "name": CLIENT_NAME,
                "version": CLIENT_VERSION,
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
    );

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": Value::Object(params),
    })
}

/// Build a legacy `initialize` JSON-RPC request.
pub fn legacy_initialize_request(id: Value, version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": id,
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {
                "name": CLIENT_NAME,
                "version": CLIENT_VERSION,
            }
        }
    })
}

/// Build a `notifications/initialized` JSON-RPC notification.
pub fn initialized_notification() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
}

/// Build a legacy `tools/list` JSON-RPC request.
pub fn legacy_tools_list_request(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": id,
    })
}

/// Pick the newest legacy protocol revision from a server's advertised versions.
pub fn latest_legacy_version<'a>(
    versions: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    let versions: Vec<&str> = versions.into_iter().collect();
    ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
        .into_iter()
        .find(|version| versions.contains(version))
}

/// Read supported versions from either a discovery result or an unsupported-version error.
pub fn supported_versions(response: &Value) -> Vec<String> {
    response
        .pointer("/result/supportedVersions")
        .or_else(|| response.pointer("/error/data/supported"))
        .or_else(|| response.pointer("/error/data/supportedVersions"))
        .and_then(Value::as_array)
        .map(|versions| {
            versions
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Evaluate a JSON-RPC response from `server/discover` uniformly across transports.
pub fn evaluate_discovery_response(response: &Value) -> Result<DiscoveryOutcome> {
    if let Some(error) = response.get("error") {
        let error_code = error.get("code").and_then(Value::as_i64);
        if error_code == Some(-32022) {
            let versions = supported_versions(response);
            if versions.iter().any(|v| v == MODERN_PROTOCOL_VERSION) {
                return Ok(DiscoveryOutcome::ModernWithTools);
            }
            if let Some(legacy) = latest_legacy_version(versions.iter().map(String::as_str)) {
                return Ok(DiscoveryOutcome::Legacy(legacy));
            }
            anyhow::bail!(
                "upstream does not support MCP protocol version {}; supported versions: {}",
                MODERN_PROTOCOL_VERSION,
                versions.join(", ")
            );
        }
        if error_code == Some(-32601) {
            return Ok(DiscoveryOutcome::MethodNotFound);
        }
        anyhow::bail!("MCP discovery failed: {error}");
    }

    let versions = supported_versions(response);
    if versions.iter().any(|v| v == MODERN_PROTOCOL_VERSION) {
        if response.pointer("/result/capabilities/tools").is_some() {
            return Ok(DiscoveryOutcome::ModernWithTools);
        }
        return Ok(DiscoveryOutcome::ModernNoTools);
    }

    if let Some(legacy) = latest_legacy_version(versions.iter().map(String::as_str)) {
        return Ok(DiscoveryOutcome::Legacy(legacy));
    }

    anyhow::bail!("MCP discovery returned no protocol version compatible with this proxy")
}

/// Extract JSON-RPC messages from an SSE response body.
pub fn parse_sse_jsonrpc_messages(body: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n");
    text.split("\n\n")
        .filter_map(|event| {
            let data = event_data_string(event);
            if data.is_empty() {
                None
            } else {
                serde_json::from_str::<Value>(&data).ok()
            }
        })
        .collect()
}

/// Extract the `data:` payload lines from a single SSE event block.
pub fn event_data_string(event: &str) -> String {
    event
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Extract `result.tools` array from a JSON-RPC response, failing on JSON-RPC errors.
pub fn extract_tools_result(response: &Value, context_label: &str) -> Result<Vec<Value>> {
    if let Some(error) = response.get("error") {
        anyhow::bail!("{context_label} failed: {error}");
    }
    Ok(response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::{evaluate_discovery_response, parse_sse_jsonrpc_messages, DiscoveryOutcome};
    use serde_json::json;

    #[test]
    fn evaluates_modern_legacy_and_fallback_discovery() {
        let modern = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "supportedVersions": ["2026-07-28"],
                "capabilities": { "tools": {} }
            }
        });
        assert_eq!(
            evaluate_discovery_response(&modern).unwrap(),
            DiscoveryOutcome::ModernWithTools
        );

        let legacy_err = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32022,
                "data": { "supported": ["2025-06-18", "2024-11-05"] }
            }
        });
        assert_eq!(
            evaluate_discovery_response(&legacy_err).unwrap(),
            DiscoveryOutcome::Legacy("2025-06-18")
        );

        let not_found = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}});
        assert_eq!(
            evaluate_discovery_response(&not_found).unwrap(),
            DiscoveryOutcome::MethodNotFound
        );
    }

    #[test]
    fn parses_multiline_sse_jsonrpc_events() {
        let sse = b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1}\r\n\r\n";
        let msgs = parse_sse_jsonrpc_messages(sse);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["id"], 1);
    }
}
