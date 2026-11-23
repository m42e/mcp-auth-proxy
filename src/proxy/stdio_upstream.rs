use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http::StatusCode;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::mcp_logging;
use crate::mcp_protocol::{
    evaluate_discovery_response, extract_tools_result, initialized_notification,
    legacy_initialize_request, legacy_tools_list_request, modern_request, DiscoveryOutcome,
    LATEST_LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION,
};

const MAX_STDIO_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Stdio upstream transport — bridges HTTP to a child process speaking JSON-RPC over stdio.
pub struct StdioUpstream {
    upstream_name: String,
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    log_mcp_traffic: bool,
    process: Arc<Mutex<Option<ManagedProcess>>>,
    next_request_id: AtomicU64,
}

struct ManagedProcess {
    child: Option<Child>,
    stdin: tokio::io::BufWriter<tokio::process::ChildStdin>,
    pending: Arc<RwLock<HashMap<Value, PendingRequest>>>,
    reader_handle: tokio::task::JoinHandle<()>,
}

impl ManagedProcess {
    async fn shutdown(mut self) {
        self.reader_handle.abort();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.reader_handle.abort();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            if matches!(child.try_wait(), Ok(None)) {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let _ = child.wait().await;
                    });
                }
            }
        }
    }
}

struct PendingRequest {
    sender: tokio::sync::mpsc::UnboundedSender<Value>,
    source_id: Value,
    client_session: Option<String>,
    progress_token: Option<Value>,
    source_progress_token: Option<Value>,
}

struct StdioCancelGuard {
    process: Arc<Mutex<Option<ManagedProcess>>>,
    request_id: Value,
    completed: Arc<AtomicBool>,
}

impl Drop for StdioCancelGuard {
    fn drop(&mut self) {
        if self.completed.load(Ordering::Acquire) {
            return;
        }

        let process = self.process.clone();
        let request_id = self.request_id.clone();

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                cancel_request(
                    &process,
                    &request_id,
                    true,
                    Some("HTTP response stream closed"),
                )
                .await;
            });
        }
    }
}

async fn cancel_request(
    process: &Arc<Mutex<Option<ManagedProcess>>>,
    upstream_request_id: &Value,
    send_notification: bool,
    reason: Option<&str>,
) {
    let mut process = process.lock().await;
    if let Some(managed) = process.as_mut() {
        let _ = managed.pending.write().await.remove(upstream_request_id);
        if send_notification {
            let mut params = serde_json::json!({ "requestId": upstream_request_id });
            if let Some(reason) = reason {
                params["reason"] = Value::String(reason.to_string());
            }
            let cancel = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": params,
            });
            let _ = write_json_line(&mut managed.stdin, &cancel).await;
        }
    }
}

async fn write_json_line(
    stdin: &mut tokio::io::BufWriter<tokio::process::ChildStdin>,
    message: &Value,
) -> Result<()> {
    let bytes = serde_json::to_vec(message).context("failed to serialize message")?;
    stdin
        .write_all(&bytes)
        .await
        .context("failed to write to stdio upstream stdin")?;
    stdin
        .write_all(b"\n")
        .await
        .context("failed to write newline to stdio upstream stdin")?;
    stdin
        .flush()
        .await
        .context("failed to flush stdio upstream stdin")?;
    Ok(())
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<usize> {
    buf.clear();
    let n = reader
        .take((max_bytes + 1) as u64)
        .read_until(b'\n', buf)
        .await?;
    if buf.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stdio message exceeded {max_bytes} bytes"),
        ));
    }
    Ok(n)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Result<Response> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .context("failed to build JSON response")
}

fn sse_response<S>(stream: S) -> Result<Response>
where
    S: futures_util::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + 'static,
{
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .context("failed to build SSE response")
}

impl StdioUpstream {
    pub fn new(
        upstream_name: String,
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
        log_mcp_traffic: bool,
    ) -> Self {
        Self {
            upstream_name,
            command,
            args,
            env,
            log_mcp_traffic,
            process: Arc::new(Mutex::new(None)),
            next_request_id: AtomicU64::new(1),
        }
    }

    fn next_request_id(&self) -> Value {
        // HTTP clients choose IDs independently; remap them before multiplexing onto one stdio channel.
        Value::from(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Ensure the child process is running, spawning it if needed.
    async fn ensure_process(&self) -> Result<()> {
        let mut proc_guard = self.process.lock().await;
        if proc_guard.is_some() {
            // Check if still alive
            if let Some(ref mut managed) = *proc_guard {
                match managed.child.as_mut().map(|child| child.try_wait()) {
                    Some(Ok(Some(status))) => {
                        warn!(status = %status, "stdio child process exited — restarting");
                        *proc_guard = None;
                    }
                    Some(Ok(None)) => return Ok(()), // Still running
                    Some(Err(e)) => {
                        warn!(error = %e, "failed to check child process status — restarting");
                        *proc_guard = None;
                    }
                    None => {
                        *proc_guard = None;
                    }
                }
            }
        }

        info!(command = %self.command, "spawning stdio upstream process");

        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);
        cmd.env_clear();
        cmd.envs(build_child_env(std::env::vars(), &self.env));
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::inherit());

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to spawn stdio upstream: {} {}",
                self.command,
                self.args.join(" ")
            )
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture child stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture child stdout"))?;

        let stdin = tokio::io::BufWriter::new(stdin);
        let pending: Arc<RwLock<HashMap<Value, PendingRequest>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Spawn reader task
        let pending_clone = pending.clone();
        let upstream_name = self.upstream_name.clone();
        let log_mcp_traffic = self.log_mcp_traffic;
        let reader_handle = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line_buf = Vec::new();

            loop {
                match read_bounded_line(&mut reader, &mut line_buf, MAX_STDIO_MESSAGE_BYTES).await {
                    Ok(0) => {
                        debug!("stdio upstream stdout closed");
                        break;
                    }
                    Ok(_) => {
                        let Ok(line) = std::str::from_utf8(&line_buf) else {
                            warn!("stdio upstream emitted non-UTF-8 line");
                            continue;
                        };
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<Value>(trimmed) {
                            Ok(msg) => {
                                if log_mcp_traffic {
                                    mcp_logging::log_response(
                                        &upstream_name,
                                        "stdio",
                                        Some(200),
                                        trimmed.as_bytes(),
                                    );
                                }
                                if let Some(id) = msg.get("id") {
                                    let mut pending = pending_clone.write().await;
                                    if let Some(request) = pending.remove(id) {
                                        let mut response = msg;
                                        response["id"] = request.source_id;
                                        let _ = request.sender.send(response);
                                    } else {
                                        debug!(id = %id, "received response for unknown request id");
                                    }
                                } else {
                                    let subscription_id = msg
                                        .pointer(
                                            "/params/_meta/io.modelcontextprotocol~1subscriptionId",
                                        )
                                        .cloned();
                                    let progress_token =
                                        msg.pointer("/params/progressToken").cloned();
                                    let subscription_request = if let Some(id) = subscription_id {
                                        let pending = pending_clone.read().await;
                                        pending.get(&id).map(|request| {
                                            (
                                                request.sender.clone(),
                                                request.source_id.clone(),
                                                request.source_progress_token.clone(),
                                            )
                                        })
                                    } else if let Some(token) = progress_token {
                                        let pending = pending_clone.read().await;
                                        pending
                                            .values()
                                            .find(|request| {
                                                request.progress_token.as_ref() == Some(&token)
                                            })
                                            .map(|request| {
                                                (
                                                    request.sender.clone(),
                                                    request.source_id.clone(),
                                                    request.source_progress_token.clone(),
                                                )
                                            })
                                    } else {
                                        None
                                    };

                                    if let Some((sender, source_id, source_progress_token)) =
                                        subscription_request
                                    {
                                        let mut notification = msg;
                                        if notification
                                            .pointer("/params/_meta/io.modelcontextprotocol~1subscriptionId")
                                            .is_some()
                                        {
                                            notification["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = source_id;
                                        }
                                        if let Some(source_token) = source_progress_token {
                                            if notification
                                                .pointer("/params/progressToken")
                                                .is_some()
                                            {
                                                notification["params"]["progressToken"] =
                                                    source_token;
                                            }
                                        }
                                        let _ = sender.send(notification);
                                    } else {
                                        debug!(
                                            method = msg
                                                .get("method")
                                                .and_then(|m| m.as_str())
                                                .unwrap_or("unknown"),
                                            "received uncorrelated notification from stdio upstream"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, line = %trimmed, "failed to parse JSON from stdio upstream");
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "error reading from stdio upstream");
                        break;
                    }
                }
            }

            // Wake in-flight HTTP requests if the subprocess exits or its stdout closes.
            pending_clone.write().await.clear();
        });

        *proc_guard = Some(ManagedProcess {
            child: Some(child),
            stdin,
            pending,
            reader_handle,
        });

        Ok(())
    }

    pub async fn forward(
        &self,
        request: Request<Body>,
        _auth_headers: &[(String, String)],
    ) -> Result<Response> {
        self.ensure_process().await?;

        let (parts, body) = request.into_parts();
        let accept_sse = parts
            .headers
            .get(http::header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("text/event-stream"))
            .unwrap_or(false);
        let client_session = parts
            .headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        let body_bytes = match axum::body::to_bytes(body, MAX_STDIO_MESSAGE_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds maximum allowed size",
                )
                    .into_response());
            }
        };

        if body_bytes.is_empty() {
            return Ok((StatusCode::BAD_REQUEST, "empty request body").into_response());
        }

        let mut msg: Value =
            serde_json::from_slice(&body_bytes).context("request body is not valid JSON")?;

        if self.log_mcp_traffic {
            mcp_logging::log_request(&self.upstream_name, "stdio", &body_bytes);
        }

        let is_notification = msg.get("id").is_none();
        let request_id = msg.get("id").cloned();
        let upstream_request_id = request_id.as_ref().map(|_| self.next_request_id());
        let source_progress_token = msg.pointer("/params/_meta/progressToken").cloned();
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cancellable = !matches!(method, "initialize" | "server/discover");
        let cancelled_request_id = (method == "notifications/cancelled")
            .then(|| msg.pointer("/params/requestId").cloned())
            .flatten();
        let log_level = msg.pointer("/params/_meta/io.modelcontextprotocol~1logLevel");
        let stream_response = accept_sse
            && method != "initialize"
            && (method == "subscriptions/listen"
                || source_progress_token.is_some()
                || log_level.is_some());

        // Send to child process
        let mut proc_guard = self.process.lock().await;
        let managed = proc_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

        if let Some(cancelled_id) = cancelled_request_id {
            let mut pending = managed.pending.write().await;
            if let Some(upstream_id) = pending
                .iter()
                .find(|(_, request)| {
                    request.source_id == cancelled_id && request.client_session == client_session
                })
                .map(|(upstream_id, _)| upstream_id.clone())
            {
                let _ = pending.remove(&upstream_id);
                msg["params"]["requestId"] = upstream_id;
            }
        }

        let rx = if let (Some(source_id), Some(upstream_id)) =
            (request_id.as_ref(), upstream_request_id.as_ref())
        {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            msg["id"] = upstream_id.clone();
            if source_progress_token.is_some() {
                msg["params"]["_meta"]["progressToken"] = upstream_id.clone();
            }
            managed.pending.write().await.insert(
                upstream_id.clone(),
                PendingRequest {
                    sender: tx,
                    source_id: source_id.clone(),
                    client_session,
                    progress_token: source_progress_token.as_ref().map(|_| upstream_id.clone()),
                    source_progress_token,
                },
            );
            Some(rx)
        } else {
            None
        };

        // Write message to stdin
        write_json_line(&mut managed.stdin, &msg).await?;

        drop(proc_guard); // Release lock while waiting for response

        if is_notification {
            // Notifications don't expect a response
            if self.log_mcp_traffic {
                mcp_logging::log_notification_ack(&self.upstream_name, "stdio");
            }
            return Ok((StatusCode::ACCEPTED, "").into_response());
        }

        let Some(mut rx) = rx else {
            anyhow::bail!("missing response channel for request");
        };
        let Some(source_request_id) = request_id else {
            anyhow::bail!("missing request id");
        };
        let Some(upstream_request_id) = upstream_request_id else {
            anyhow::bail!("missing upstream request id");
        };

        if stream_response {
            let completed = Arc::new(AtomicBool::new(false));
            let cancel_guard = StdioCancelGuard {
                process: self.process.clone(),
                request_id: upstream_request_id,
                completed: completed.clone(),
            };

            // Surface immediate protocol errors with their required HTTP status before opening SSE.
            let first_message =
                match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                    Ok(Some(message)) if message.get("id") == Some(&source_request_id) => {
                        completed.store(true, Ordering::Release);
                        let status = streamable_http_status(&msg, &message);
                        let body = serde_json::to_vec(&message)
                            .context("failed to serialize stdio response")?;
                        return json_response(status, body);
                    }
                    Ok(Some(message)) => Some(message),
                    Ok(None) => anyhow::bail!("stdio reader task dropped"),
                    Err(_) => None,
                };

            let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(15));
            keepalive.tick().await;
            let stream = futures_util::stream::unfold(
                (
                    rx,
                    cancel_guard,
                    source_request_id,
                    completed,
                    keepalive,
                    first_message,
                    false,
                ),
                |(
                    mut rx,
                    cancel_guard,
                    source_request_id,
                    completed,
                    mut keepalive,
                    mut first_message,
                    done,
                )| async move {
                    if done {
                        return None;
                    }
                    let message = if let Some(message) = first_message.take() {
                        message
                    } else {
                        let next = tokio::select! {
                            _ = keepalive.tick() => None,
                            message = rx.recv() => Some(message),
                        };
                        match next {
                            None => {
                                return Some((
                                    Ok::<Bytes, std::io::Error>(Bytes::from(":\n\n")),
                                    (
                                        rx,
                                        cancel_guard,
                                        source_request_id,
                                        completed,
                                        keepalive,
                                        first_message,
                                        false,
                                    ),
                                ));
                            }
                            Some(Some(message)) => message,
                            Some(None) => return None,
                        }
                    };
                    let is_final = message.get("id") == Some(&source_request_id);
                    if is_final {
                        completed.store(true, Ordering::Release);
                    }
                    let data = match serde_json::to_string(&message) {
                        Ok(data) => data,
                        Err(error) => {
                            return Some((
                                Err(std::io::Error::other(error.to_string())),
                                (
                                    rx,
                                    cancel_guard,
                                    source_request_id,
                                    completed,
                                    keepalive,
                                    first_message,
                                    true,
                                ),
                            ));
                        }
                    };
                    Some((
                        Ok::<Bytes, std::io::Error>(Bytes::from(format!("data: {data}\n\n"))),
                        (
                            rx,
                            cancel_guard,
                            source_request_id,
                            completed,
                            keepalive,
                            first_message,
                            is_final,
                        ),
                    ))
                },
            );

            return sse_response(stream);
        }

        let response_result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let message = rx
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("stdio reader task dropped"))?;
                if message.get("id") == Some(&source_request_id) {
                    return Ok::<Value, anyhow::Error>(message);
                }
            }
        })
        .await;

        let response_msg = match response_result {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => {
                cancel_request(&self.process, &upstream_request_id, false, None).await;
                return Err(error);
            }
            Err(_) => {
                cancel_request(
                    &self.process,
                    &upstream_request_id,
                    cancellable,
                    Some("request timed out"),
                )
                .await;
                anyhow::bail!("timeout waiting for stdio upstream response");
            }
        };

        let response_body =
            serde_json::to_vec(&response_msg).context("failed to serialize response")?;

        json_response(streamable_http_status(&msg, &response_msg), response_body)
    }
}

fn streamable_http_status(request: &Value, response: &Value) -> StatusCode {
    let protocol_version = request
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol_version < MODERN_PROTOCOL_VERSION {
        return StatusCode::OK;
    }

    let error_code = response.pointer("/error/code").and_then(Value::as_i64);
    if error_code.is_some_and(|code| (-32099..=-32020).contains(&code)) {
        return StatusCode::BAD_REQUEST;
    }
    if error_code == Some(-32601) {
        if request.get("method").and_then(Value::as_str) == Some("server/discover") {
            // A legacy backend's unknown-method error is the modern-probe fallback signal.
            return StatusCode::BAD_REQUEST;
        }
        return StatusCode::NOT_FOUND;
    }

    StatusCode::OK
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        // Best-effort process cleanup
        if let Some(process) = Arc::get_mut(&mut self.process) {
            drop(process.get_mut().take());
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let process = self.process.clone();
            runtime.spawn(async move {
                if let Some(managed) = process.lock().await.take() {
                    managed.shutdown().await;
                }
            });
        }
    }
}

impl StdioUpstream {
    async fn shutdown(&self) {
        if let Some(managed) = self.process.lock().await.take() {
            managed.shutdown().await;
        }
    }
    /// Send a JSON-RPC message and wait for the response.
    pub async fn send_jsonrpc(&self, msg: &Value) -> Result<Value> {
        self.send_jsonrpc_with_timeout(msg, std::time::Duration::from_secs(30))
            .await
    }

    async fn send_jsonrpc_with_timeout(
        &self,
        msg: &Value,
        timeout: std::time::Duration,
    ) -> Result<Value> {
        self.ensure_process().await?;

        let source_request_id = msg
            .get("id")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC message must have an id"))?;
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cancellable = !matches!(method, "initialize" | "server/discover");
        let upstream_request_id = self.next_request_id();
        let source_progress_token = msg.pointer("/params/_meta/progressToken").cloned();
        let mut outgoing = msg.clone();
        outgoing["id"] = upstream_request_id.clone();
        if source_progress_token.is_some() {
            outgoing["params"]["_meta"]["progressToken"] = upstream_request_id.clone();
        }

        let mut proc_guard = self.process.lock().await;
        let managed = proc_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        managed.pending.write().await.insert(
            upstream_request_id.clone(),
            PendingRequest {
                sender: tx,
                source_id: source_request_id.clone(),
                client_session: None,
                progress_token: source_progress_token
                    .as_ref()
                    .map(|_| upstream_request_id.clone()),
                source_progress_token,
            },
        );

        write_json_line(&mut managed.stdin, &outgoing).await?;

        drop(proc_guard);

        let response_result = tokio::time::timeout(timeout, async {
            loop {
                let response = rx
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("reader task dropped"))?;
                if response.get("id") == Some(&source_request_id) {
                    return Ok::<Value, anyhow::Error>(response);
                }
            }
        })
        .await;

        let response = match response_result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                cancel_request(&self.process, &upstream_request_id, false, None).await;
                return Err(error);
            }
            Err(_) => {
                cancel_request(&self.process, &upstream_request_id, cancellable, None).await;
                anyhow::bail!("timeout waiting for response")
            }
        };

        Ok(response)
    }

    /// Fetch tools using modern discovery, with a legacy initialize fallback for older servers.
    pub async fn fetch_tools(&self) -> Result<Vec<Value>> {
        // Keep cache discovery isolated: a legacy initialize handshake must not consume the
        // long-lived stdio process used to forward client requests.
        let discovery_process = StdioUpstream::new(
            self.upstream_name.clone(),
            self.command.clone(),
            self.args.clone(),
            self.env.clone(),
            self.log_mcp_traffic,
        );
        let result = discovery_process.fetch_tools_on_process().await;
        discovery_process.shutdown().await;
        result
    }

    async fn fetch_tools_on_process(&self) -> Result<Vec<Value>> {
        let discover = modern_request(
            "server/discover",
            serde_json::json!("discover-1000000"),
            MODERN_PROTOCOL_VERSION,
        );
        self.log_json_request(&discover, "server/discover")?;
        let discovery = match self
            .send_jsonrpc_with_timeout(&discover, std::time::Duration::from_secs(3))
            .await
        {
            Ok(response) => Some(response),
            Err(error) => {
                warn!(error = %error, "modern MCP discovery failed; trying legacy initialization");
                None
            }
        };

        if let Some(response) = discovery.as_ref() {
            match evaluate_discovery_response(response) {
                Ok(DiscoveryOutcome::ModernWithTools) => {
                    return self.fetch_modern_tools(MODERN_PROTOCOL_VERSION).await;
                }
                Ok(DiscoveryOutcome::ModernNoTools) => return Ok(Vec::new()),
                Ok(DiscoveryOutcome::Legacy(version)) => {
                    return self.fetch_legacy_tools(version).await;
                }
                Ok(DiscoveryOutcome::MethodNotFound) => {}
                Err(error) => return Err(error),
            }
        }

        self.fetch_legacy_tools(LATEST_LEGACY_PROTOCOL_VERSION)
            .await
    }

    async fn fetch_modern_tools(&self, version: &str) -> Result<Vec<Value>> {
        let tools_request =
            modern_request("tools/list", serde_json::json!("tools-1000002"), version);
        self.log_json_request(&tools_request, "modern tools/list")?;

        let response = self.send_jsonrpc(&tools_request).await?;
        extract_tools_result(&response, "modern tools/list")
    }

    async fn fetch_legacy_tools(&self, version: &str) -> Result<Vec<Value>> {
        let init_msg = legacy_initialize_request(serde_json::json!(1000001), version);
        self.log_json_request(&init_msg, "initialize")?;

        let init_resp = self.send_jsonrpc(&init_msg).await?;
        if let Some(err) = init_resp.get("error") {
            anyhow::bail!("initialize failed: {err}");
        }

        // Step 2: notifications/initialized (no id → notification)
        self.ensure_process().await?;
        {
            let mut proc_guard = self.process.lock().await;
            let managed = proc_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

            let notif = initialized_notification();
            self.log_json_request(&notif, "initialized notification")?;
            write_json_line(&mut managed.stdin, &notif).await?;
        }

        if self.log_mcp_traffic {
            mcp_logging::log_notification_ack(&self.upstream_name, "stdio");
        }

        // Step 3: tools/list
        let tools_msg = legacy_tools_list_request(serde_json::json!(1000002));
        self.log_json_request(&tools_msg, "tools/list")?;

        let tools_resp = self.send_jsonrpc(&tools_msg).await?;
        extract_tools_result(&tools_resp, "tools/list")
    }

    fn log_json_request(&self, msg: &Value, label: &str) -> Result<()> {
        if self.log_mcp_traffic {
            let payload = serde_json::to_vec(msg)
                .with_context(|| format!("failed to serialize {label} request"))?;
            mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
        }
        Ok(())
    }
}

const SAFE_INHERITED_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "USERNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "NPM_CONFIG_CACHE",
    "UV_CACHE_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "OS",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "WINDIR",
];

/// Filter inherited parent environment variables to a safe allowlist and merge explicit overrides.
fn build_child_env<I>(
    parent_vars: I,
    extra_env: &HashMap<String, String>,
) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: HashMap<String, String> = parent_vars
        .into_iter()
        .filter(|(key, _)| {
            SAFE_INHERITED_ENV_VARS
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(allowed))
        })
        .collect();
    for (key, value) in extra_env {
        env.insert(key.clone(), value.clone());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::{build_child_env, read_bounded_line, streamable_http_status};
    use crate::mcp_protocol::MODERN_PROTOCOL_VERSION;
    use http::StatusCode;
    use std::collections::HashMap;
    use tokio::io::BufReader;

    #[test]
    fn strips_parent_vault_secrets_from_child_env() {
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/test".to_string()),
            (
                "http_proxy".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ),
            (
                "OP_SERVICE_ACCOUNT_TOKEN".to_string(),
                "op-secret".to_string(),
            ),
            ("BW_SESSION".to_string(), "bw-session".to_string()),
            ("BW_PASSWORD".to_string(), "bw-pass".to_string()),
            ("KEEPASS_PASSWORD".to_string(), "kp-pass".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "aws-secret".to_string(),
            ),
            ("AWS_SESSION_TOKEN".to_string(), "aws-token".to_string()),
        ];
        let mut extra = HashMap::new();
        extra.insert("CUSTOM_API_KEY".to_string(), "explicit".to_string());
        extra.insert("HOME".to_string(), "/override".to_string());

        let child_env = build_child_env(parent, &extra);

        assert_eq!(child_env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(
            child_env.get("http_proxy").map(String::as_str),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(child_env.get("HOME").map(String::as_str), Some("/override"));
        assert_eq!(
            child_env.get("CUSTOM_API_KEY").map(String::as_str),
            Some("explicit")
        );
        assert!(!child_env.contains_key("OP_SERVICE_ACCOUNT_TOKEN"));
        assert!(!child_env.contains_key("BW_SESSION"));
        assert!(!child_env.contains_key("BW_PASSWORD"));
        assert!(!child_env.contains_key("KEEPASS_PASSWORD"));
        assert!(!child_env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!child_env.contains_key("AWS_SESSION_TOKEN"));
    }

    #[tokio::test]
    async fn read_bounded_line_rejects_oversized_messages() {
        let data = b"{\"ok\":true}\n{\"too_big\":\"0123456789\"}\n";
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();

        let n = read_bounded_line(&mut reader, &mut buf, 16).await.unwrap();
        assert_eq!(n, 12);
        assert_eq!(buf, b"{\"ok\":true}\n");

        let err = read_bounded_line(&mut reader, &mut buf, 16)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn maps_modern_error_codes_to_http_status() {
        let modern_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION
                }
            }
        });
        let err_missing = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}});
        assert_eq!(
            streamable_http_status(&modern_req, &err_missing),
            StatusCode::NOT_FOUND
        );

        let err_proto = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32022}});
        assert_eq!(
            streamable_http_status(&modern_req, &err_proto),
            StatusCode::BAD_REQUEST
        );

        let legacy_req = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"});
        assert_eq!(
            streamable_http_status(&legacy_req, &err_missing),
            StatusCode::OK
        );
    }
}
