use serde_json::{json, Map, Value};

pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

const CLIENT_NAME: &str = "mcp-auth-proxy";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
