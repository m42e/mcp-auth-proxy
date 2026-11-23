use serde_json::Value;
use tracing::info;

const MAX_LOG_BYTES: usize = 16 * 1024;

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

    truncate_at(formatted, MAX_LOG_BYTES)
}

fn truncate_at(mut text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }

    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let omitted = text.len() - end;
    text.truncate(end);
    text.push_str(&format!("\n... <truncated {omitted} bytes>"));
    text
}

#[cfg(test)]
mod tests {
    use super::truncate_at;

    #[test]
    fn leaves_short_text_unchanged() {
        assert_eq!(truncate_at("hello".to_string(), 16), "hello");
    }

    #[test]
    fn truncates_on_utf8_char_boundary_without_panicking() {
        // Each crab emoji is 4 UTF-8 bytes; total 12 bytes.
        let text = "🦀🦀🦀".to_string();
        let truncated = truncate_at(text, 6);
        assert!(truncated.starts_with("🦀\n... <truncated 8 bytes>"));
    }

    #[test]
    fn truncates_ascii_at_exact_limit() {
        let text = "abcdef".to_string();
        let truncated = truncate_at(text, 4);
        assert_eq!(truncated, "abcd\n... <truncated 2 bytes>");
    }
}
