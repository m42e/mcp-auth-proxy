use serde_json::Value;
use tracing::info;

const MAX_LOG_CHARS: usize = 16 * 1024;

pub fn log_request(upstream: &str, transport: &str, payload: &[u8]) {
    info!(
        upstream = %upstream,
        transport = %transport,
        direction = "request",
        payload = %format_payload(payload),
        "logged MCP traffic"
    );
}

pub fn log_response(upstream: &str, transport: &str, status: Option<u16>, payload: &[u8]) {
    info!(
        upstream = %upstream,
        transport = %transport,
        direction = "response",
        status,
        payload = %format_payload(payload),
        "logged MCP traffic"
    );
}

pub fn log_streaming_response(
    upstream: &str,
    transport: &str,
    status: u16,
    content_type: Option<&str>,
) {
    info!(
        upstream = %upstream,
        transport = %transport,
        direction = "response",
        status,
        content_type = content_type.unwrap_or("unknown"),
        payload = "<streaming response body not captured>",
        "logged MCP traffic"
    );
}

pub fn log_notification_ack(upstream: &str, transport: &str) {
    info!(
        upstream = %upstream,
        transport = %transport,
        direction = "response",
        payload = "<notification forwarded; no response expected>",
        "logged MCP traffic"
    );
}

fn format_payload(payload: &[u8]) -> String {
    if payload.is_empty() {
        return "<empty>".to_string();
    }

    let formatted = match serde_json::from_slice::<Value>(payload) {
        Ok(value) => serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| String::from_utf8_lossy(payload).into_owned()),
        Err(_) => String::from_utf8_lossy(payload).into_owned(),
    };

    truncate(formatted)
}

fn truncate(mut text: String) -> String {
    if text.len() <= MAX_LOG_CHARS {
        return text;
    }

    let omitted = text.len() - MAX_LOG_CHARS;
    text.truncate(MAX_LOG_CHARS);
    text.push_str(&format!("\n... <truncated {} chars>", omitted));
    text
}