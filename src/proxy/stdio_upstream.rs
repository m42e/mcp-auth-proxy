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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::mcp_logging;
use crate::mcp_protocol::{
    latest_legacy_version, modern_request, supported_versions, LATEST_LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
};

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
    child: Child,
    stdin: tokio::io::BufWriter<tokio::process::ChildStdin>,
    pending: Arc<RwLock<HashMap<Value, PendingRequest>>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

struct PendingRequest {
    sender: tokio::sync::mpsc::UnboundedSender<Value>,
    source_id: Value,
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
        let cancel = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": request_id.clone(),
                "reason": "HTTP response stream closed",
            }
        });

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut process = process.lock().await;
                if let Some(managed) = process.as_mut() {
                    let _ = managed.pending.write().await.remove(&request_id);
                    if let Ok(bytes) = serde_json::to_vec(&cancel) {
                        let _ = managed.stdin.write_all(&bytes).await;
                        let _ = managed.stdin.write_all(b"\n").await;
                        let _ = managed.stdin.flush().await;
                    }
                }
            });
        }
    }
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
                match managed.child.try_wait() {
                    Ok(Some(status)) => {
                        warn!(status = %status, "stdio child process exited — restarting");
                        *proc_guard = None;
                    }
                    Ok(None) => return Ok(()), // Still running
                    Err(e) => {
                        warn!(error = %e, "failed to check child process status — restarting");
                        *proc_guard = None;
                    }
                }
            }
        }

        info!(command = %self.command, "spawning stdio upstream process");

        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);
        cmd.envs(&self.env);
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
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        debug!("stdio upstream stdout closed");
                        break;
                    }
                    Ok(_) => {
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
                                        pending.get(&id).map(|request| {
                                            (
                                                request.sender.clone(),
                                                request.source_id.clone(),
                                                request.source_progress_token.clone(),
                                            )
                                        })
                                    } else if let Some(token) = progress_token {
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
            child,
            stdin,
            pending,
            _reader_handle: reader_handle,
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

        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .context("failed to read request body")?;

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
                .find(|(_, request)| &request.source_id == &cancelled_id)
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
                    progress_token: source_progress_token.as_ref().map(|_| upstream_id.clone()),
                    source_progress_token,
                },
            );
            Some(rx)
        } else {
            None
        };

        // Write message to stdin
        let msg_bytes = serde_json::to_vec(&msg).context("failed to serialize message")?;
        managed
            .stdin
            .write_all(&msg_bytes)
            .await
            .context("failed to write to stdio upstream stdin")?;
        managed
            .stdin
            .write_all(b"\n")
            .await
            .context("failed to write newline to stdio upstream stdin")?;
        managed
            .stdin
            .flush()
            .await
            .context("failed to flush stdio upstream stdin")?;

        drop(proc_guard); // Release lock while waiting for response

        if is_notification {
            // Notifications don't expect a response
            if self.log_mcp_traffic {
                mcp_logging::log_notification_ack(&self.upstream_name, "stdio");
            }
            return Ok((StatusCode::ACCEPTED, "").into_response());
        }

        let mut rx = rx.unwrap();
        let source_request_id = request_id.unwrap();
        let upstream_request_id = upstream_request_id.unwrap();

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
                        return Ok(Response::builder()
                            .status(status)
                            .header("Content-Type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                            .into_response());
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
                ),
                |(
                    mut rx,
                    cancel_guard,
                    source_request_id,
                    completed,
                    mut keepalive,
                    mut first_message,
                )| async move {
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
                                    ),
                                ));
                            }
                            Some(Some(message)) => message,
                            Some(None) => return None,
                        }
                    };
                    if message.get("id") == Some(&source_request_id) {
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
                        ),
                    ))
                },
            );

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Accel-Buffering", "no")
                .body(Body::from_stream(stream))
                .unwrap()
                .into_response());
        }

        let response_msg = tokio::time::timeout(std::time::Duration::from_secs(30), async {
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
        .await
        .context("timeout waiting for stdio upstream response")??;

        let response_body =
            serde_json::to_vec(&response_msg).context("failed to serialize response")?;

        Ok(Response::builder()
            .status(streamable_http_status(&msg, &response_msg))
            .header("Content-Type", "application/json")
            .body(Body::from(response_body))
            .unwrap()
            .into_response())
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
            if let Some(mut managed) = process.get_mut().take() {
                let _ = managed.child.start_kill();
            }
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let process = self.process.clone();
            runtime.spawn(async move {
                if let Some(mut managed) = process.lock().await.take() {
                    let _ = managed.child.start_kill();
                }
            });
        }
    }
}

impl StdioUpstream {
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
                progress_token: source_progress_token
                    .as_ref()
                    .map(|_| upstream_request_id.clone()),
                source_progress_token,
            },
        );

        let msg_bytes = serde_json::to_vec(&outgoing).context("failed to serialize message")?;
        managed
            .stdin
            .write_all(&msg_bytes)
            .await
            .context("failed to write to stdin")?;
        managed
            .stdin
            .write_all(b"\n")
            .await
            .context("failed to write newline")?;
        managed
            .stdin
            .flush()
            .await
            .context("failed to flush stdin")?;

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
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                let mut proc_guard = self.process.lock().await;
                if let Some(managed) = proc_guard.as_mut() {
                    let _ = managed.pending.write().await.remove(&upstream_request_id);
                    if cancellable {
                        let cancel = serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": { "requestId": upstream_request_id }
                        });
                        if let Ok(bytes) = serde_json::to_vec(&cancel) {
                            let _ = managed.stdin.write_all(&bytes).await;
                            let _ = managed.stdin.write_all(b"\n").await;
                            let _ = managed.stdin.flush().await;
                        }
                    }
                }
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
        discovery_process.fetch_tools_on_process().await
    }

    async fn fetch_tools_on_process(&self) -> Result<Vec<Value>> {
        let discover = modern_request(
            "server/discover",
            serde_json::json!("discover-1000000"),
            MODERN_PROTOCOL_VERSION,
        );
        if self.log_mcp_traffic {
            let payload = serde_json::to_vec(&discover)
                .context("failed to serialize server/discover request")?;
            mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
        }
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
            let versions = supported_versions(response);
            if response.get("error").is_some()
                && response.pointer("/error/code").and_then(Value::as_i64) == Some(-32022)
            {
                if versions.iter().any(|v| v == MODERN_PROTOCOL_VERSION) {
                    return self.fetch_modern_tools(MODERN_PROTOCOL_VERSION).await;
                }
                if let Some(version) = latest_legacy_version(versions.iter().map(String::as_str)) {
                    return self.fetch_legacy_tools(version).await;
                }
                anyhow::bail!(
                    "upstream does not support MCP protocol version {}; supported versions: {}",
                    MODERN_PROTOCOL_VERSION,
                    versions.join(", ")
                );
            }

            if response.get("error").is_none() {
                if response
                    .pointer("/result/supportedVersions")
                    .and_then(Value::as_array)
                    .is_some()
                {
                    if versions.iter().any(|v| v == MODERN_PROTOCOL_VERSION) {
                        if response.pointer("/result/capabilities/tools").is_some() {
                            return self.fetch_modern_tools(MODERN_PROTOCOL_VERSION).await;
                        }
                        return Ok(Vec::new());
                    }
                    if let Some(version) =
                        latest_legacy_version(versions.iter().map(String::as_str))
                    {
                        return self.fetch_legacy_tools(version).await;
                    }
                    anyhow::bail!(
                        "MCP discovery returned no protocol version compatible with this proxy"
                    );
                }
            }
        }

        self.fetch_legacy_tools(LATEST_LEGACY_PROTOCOL_VERSION)
            .await
    }

    async fn fetch_modern_tools(&self, version: &str) -> Result<Vec<Value>> {
        let tools_request =
            modern_request("tools/list", serde_json::json!("tools-1000002"), version);
        if self.log_mcp_traffic {
            let payload = serde_json::to_vec(&tools_request)
                .context("failed to serialize modern tools/list request")?;
            mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
        }

        let response = self.send_jsonrpc(&tools_request).await?;
        if response.get("error").is_some() {
            anyhow::bail!(
                "modern tools/list failed: {}",
                response.get("error").unwrap()
            );
        }

        Ok(response
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    async fn fetch_legacy_tools(&self, version: &str) -> Result<Vec<Value>> {
        let init_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1000001,
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-auth-proxy",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });

        if self.log_mcp_traffic {
            let payload =
                serde_json::to_vec(&init_msg).context("failed to serialize initialize request")?;
            mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
        }

        let init_resp = self.send_jsonrpc(&init_msg).await?;
        if init_resp.get("error").is_some() {
            anyhow::bail!("initialize failed: {}", init_resp.get("error").unwrap());
        }

        // Step 2: notifications/initialized (no id → notification)
        // We must send this directly since send_jsonrpc expects an id.
        self.ensure_process().await?;
        {
            let mut proc_guard = self.process.lock().await;
            let managed = proc_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

            let notif = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            });
            if self.log_mcp_traffic {
                let payload = serde_json::to_vec(&notif)
                    .context("failed to serialize initialized notification")?;
                mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
            }
            let notif_bytes = serde_json::to_vec(&notif)?;
            managed.stdin.write_all(&notif_bytes).await?;
            managed.stdin.write_all(b"\n").await?;
            managed.stdin.flush().await?;
        }

        if self.log_mcp_traffic {
            mcp_logging::log_notification_ack(&self.upstream_name, "stdio");
        }

        // Step 3: tools/list
        let tools_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1000002
        });

        if self.log_mcp_traffic {
            let payload =
                serde_json::to_vec(&tools_msg).context("failed to serialize tools/list request")?;
            mcp_logging::log_request(&self.upstream_name, "stdio", &payload);
        }

        let tools_resp = self.send_jsonrpc(&tools_msg).await?;
        if tools_resp.get("error").is_some() {
            anyhow::bail!("tools/list failed: {}", tools_resp.get("error").unwrap());
        }

        let tools = tools_resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(tools)
    }
}
