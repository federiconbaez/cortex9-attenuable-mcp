//! Authorization layer in front of `mcp-server-rs`'s Streamable HTTP
//! transport. Every request is verified before it reaches
//! [`HttpState::handle`]; the body that was authorized is the body that is
//! dispatched (no re-serialization in between).

use crate::verifier::{Allowed, Denied, Verifier};
use mcp_server::Server;
use mcp_server::tools::{Tool, ToolContext, ToolResult, text_result};
use mcp_server::transport::http::{HttpConfig, HttpResponse, HttpState};
use serde_json::{Value, json};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Demo tool with a dangerous-looking interface and no side effects: it
/// records the call and echoes it. Used by tests and the attack suite to
/// show argument-level restrictions (`/repo`, `/branch`, `/force`).
pub struct RepoPush {
    pub log: Arc<Mutex<Vec<Value>>>,
}

impl Tool for RepoPush {
    fn name(&self) -> &str {
        "repo.push"
    }
    fn definition(&self) -> Value {
        json!({
            "name": "repo.push",
            "description": "Demo: pretend to push a branch (records the call, no side effects).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "maxLength": 200},
                    "branch": {"type": "string", "maxLength": 200},
                    "force": {"type": "boolean"}
                },
                "required": ["repo", "branch"]
            }
        })
    }
    fn call(&self, args: &Value, _ctx: &ToolContext) -> ToolResult {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(args.clone());
        Ok(text_result(format!("pushed {args}")))
    }
}

/// `mcp-server-rs` with its built-in tools plus [`RepoPush`].
pub fn demo_server(log: Arc<Mutex<Vec<Value>>>) -> Server {
    let mut tools = mcp_server::tools::builtin();
    tools.push(Box::new(RepoPush { log }));
    Server::with_tools(tools)
}

/// Callback invoked with every authorization decision.
pub type AuditHook = Box<dyn Fn(&Result<Allowed, Denied>) + Send + Sync>;

pub struct AuthenticatedMcp {
    pub verifier: Verifier,
    pub state: HttpState,
    pub max_body: usize,
    /// Optional audit hook for allowed/denied decisions.
    pub audit: Option<AuditHook>,
}

fn denied_response(d: &Denied) -> HttpResponse {
    // Header values must be visible ASCII; Biscuit messages contain "n°".
    let desc: String = d
        .reason
        .chars()
        .map(|c| match c {
            '"' | '\\' => '\'',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '?',
        })
        .take(300)
        .collect();
    HttpResponse {
        status: d.status,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            (
                "WWW-Authenticate".into(),
                format!(
                    "DPoP error=\"{}\", error_description=\"{desc}\", algs=\"EdDSA\"",
                    d.error
                ),
            ),
        ],
        body: Some(json!({"error": d.error, "error_description": d.reason})),
    }
}

impl AuthenticatedMcp {
    pub fn new(verifier: Verifier, server: Server, cfg: HttpConfig) -> Self {
        let max_body = cfg.max_body;
        Self {
            verifier,
            state: HttpState::new(server, cfg),
            max_body,
            audit: None,
        }
    }

    /// Handle one request at time `now` (unix seconds).
    pub fn handle_at(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
        now: u64,
    ) -> HttpResponse {
        if method != "POST" {
            // GET (SSE) and DELETE (session close) are not authorized by this
            // layer; refuse them rather than pass them through unchecked.
            return HttpResponse {
                status: 405,
                headers: vec![("Allow".into(), "POST".into())],
                body: None,
            };
        }
        if body.len() > self.max_body {
            return HttpResponse {
                status: 413,
                headers: Vec::new(),
                body: None,
            };
        }
        let decision = self.verifier.verify(method, headers, body, now);
        if let Some(a) = &self.audit {
            a(&decision);
        }
        match decision {
            Ok(_) => self.state.handle(method, path, headers, body),
            Err(d) => denied_response(&d),
        }
    }

    pub fn handle(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> HttpResponse {
        self.handle_at(method, path, headers, body, unix_now())
    }

    /// Serve on a tiny_http listener with `workers` threads (blocks).
    pub fn serve(self: Arc<Self>, http: Arc<tiny_http::Server>, workers: usize) {
        let handles: Vec<_> = (0..workers.max(1))
            .map(|_| {
                let http = http.clone();
                let me = self.clone();
                std::thread::spawn(move || {
                    while let Ok(req) = http.recv() {
                        me.serve_one(req);
                    }
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }

    fn serve_one(&self, mut req: tiny_http::Request) {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_string(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let method = req.method().as_str().to_string();
        let url = req.url().to_string();
        let mut body = Vec::new();
        let limit = self.max_body as u64 + 1;
        let resp = match req.as_reader().take(limit).read_to_end(&mut body) {
            Ok(_) => self.handle(&method, &url, &headers, &body),
            Err(_) => HttpResponse {
                status: 400,
                headers: Vec::new(),
                body: None,
            },
        };
        let data = resp
            .body
            .as_ref()
            .map(|b| b.to_string().into_bytes())
            .unwrap_or_default();
        let mut out = tiny_http::Response::from_data(data).with_status_code(resp.status);
        for (k, v) in &resp.headers {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                out.add_header(h);
            }
        }
        let _ = req.respond(out);
    }
}
