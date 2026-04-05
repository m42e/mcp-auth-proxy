use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::mcp_logging;

/// Stdio upstream transport — bridges HTTP to a child process speaking JSON-RPC over stdio.
pub struct StdioUpstream {
    upstream_name: String,
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    log_mcp_traffic: bool,
    process: Mutex<Option<ManagedProcess>>,
}

struct ManagedProcess {
    child: Child,
    stdin: tokio::io::BufWriter<tokio::process::ChildStdin>,
    pending: Arc<RwLock<HashMap<Value, tokio::sync::oneshot::Sender<Value>>>>,
    _reader_handle: tokio::task::JoinHandle<()>,
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
            process: Mutex::new(None),
        }
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
        let pending: Arc<RwLock<HashMap<Value, tokio::sync::oneshot::Sender<Value>>>> =
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
                                    if let Some(sender) = pending.remove(id) {
                                        let _ = sender.send(msg);
                                    } else {
                                        debug!(id = %id, "received response for unknown request id");
                                    }
                                } else {
                                    // Notification — log but discard for now
                                    debug!(method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("unknown"), "received notification from stdio upstream");
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

        // Read request body as JSON
        let body_bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .context("failed to read request body")?;

        if body_bytes.is_empty() {
            return Ok((StatusCode::BAD_REQUEST, "empty request body").into_response());
        }

        let msg: Value =
            serde_json::from_slice(&body_bytes).context("request body is not valid JSON")?;

        if self.log_mcp_traffic {
            mcp_logging::log_request(&self.upstream_name, "stdio", &body_bytes);
        }

        let is_notification = msg.get("id").is_none();
        let request_id = msg.get("id").cloned();

        // Send to child process
        let mut proc_guard = self.process.lock().await;
        let managed = proc_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

        let rx = if let Some(ref id) = request_id {
            let (tx, rx) = tokio::sync::oneshot::channel();
            managed.pending.write().await.insert(id.clone(), tx);
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

        // Wait for response
        let rx = rx.unwrap();
        let response_msg = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .context("timeout waiting for stdio upstream response")?
            .context("stdio reader task dropped")?;

        let response_body =
            serde_json::to_vec(&response_msg).context("failed to serialize response")?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(response_body))
            .unwrap()
            .into_response())
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        // Best-effort process cleanup
        if let Some(mut managed) = self.process.get_mut().take() {
            let _ = managed.child.start_kill();
        }
    }
}

impl StdioUpstream {
    /// Send a JSON-RPC message and wait for the response.
    pub async fn send_jsonrpc(&self, msg: &Value) -> Result<Value> {
        self.ensure_process().await?;

        let request_id = msg
            .get("id")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC message must have an id"))?;

        let mut proc_guard = self.process.lock().await;
        let managed = proc_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("stdio process not available"))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        managed
            .pending
            .write()
            .await
            .insert(request_id.clone(), tx);

        let msg_bytes = serde_json::to_vec(msg).context("failed to serialize message")?;
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

        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .context("timeout waiting for response")?
            .context("reader task dropped")?;

        Ok(response)
    }

    /// Fetch the list of tools from the upstream MCP server via the full MCP handshake.
    ///
    /// Sends initialize → notifications/initialized → tools/list over stdio.
    pub async fn fetch_tools(&self) -> Result<Vec<Value>> {
        // Step 1: initialize
        let init_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1000001,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-auth-proxy",
                    "version": "0.1.0"
                }
            }
        });

        if self.log_mcp_traffic {
            let payload = serde_json::to_vec(&init_msg).context("failed to serialize initialize request")?;
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
            let payload = serde_json::to_vec(&tools_msg).context("failed to serialize tools/list request")?;
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
