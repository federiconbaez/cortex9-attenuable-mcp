//! Confused-deputy / escalation suite (measurement (a) of the acceptance
//! criterion). Every case is a real HTTP-level request through
//! [`AuthenticatedMcp`] into `mcp-server-rs`. Attack cases must be refused
//! *and* must not reach the tool; control cases must be executed. A suite
//! that refused everything would fail on the controls.

use crate::dpop::{self, ProofClaims};
use crate::jwk;
use crate::middleware::{AuthenticatedMcp, demo_server};
use crate::token::{self, ArgValue, Attenuation, Grant};
use crate::verifier::{Config, Verifier};
use biscuit_auth::Biscuit;
use biscuit_auth::builder::BlockBuilder;
use ed25519_dalek::SigningKey;
use mcp_server::transport::http::{HttpConfig, HttpResponse};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub const URL: &str = "http://127.0.0.1:8808/mcp";
pub const AUD: &str = "mcp://demo";
pub const MODERN: &str = "2026-07-28";
/// Fixed clock for reproducibility (2026-10-29T00:00:00Z).
pub const NOW: u64 = 1_793_232_000;

/// Keys and tokens of the scenario: an orchestrator agent `a` holds the
/// root token; it delegates to subagent `b` a token for `repo.push` on
/// `acme/site`, branches `feature/*`, only `/repo` and `/branch`, for 10
/// minutes, locked to `b`'s key. `c` is an attacker.
pub struct World {
    pub root: SigningKey,
    pub a: SigningKey,
    pub b: SigningKey,
    pub c: SigningKey,
    pub root_token: Biscuit,
    pub delegated: Biscuit,
    pub three_levels: Biscuit,
}

pub fn b_restrictions(b_jkt: &str) -> Attenuation {
    Attenuation {
        tools: vec!["repo.push".into()],
        arg_eq: vec![("/repo".into(), ArgValue::Str("acme/site".into()))],
        arg_prefix: vec![("/branch".into(), "feature/".into())],
        only_args: Some(vec!["/repo".into(), "/branch".into()]),
        expires_at: Some(NOW + 600),
        lock_holder: Some(b_jkt.to_string()),
        ..Default::default()
    }
}

impl World {
    pub fn new() -> Self {
        let root = jwk::generate();
        let a = jwk::generate();
        let b = jwk::generate();
        let c = jwk::generate();
        let a_jkt = jwk::thumbprint(&a.verifying_key());
        let b_jkt = jwk::thumbprint(&b.verifying_key());
        let root_token = token::mint(
            &root,
            &Grant {
                holder_jkt: a_jkt,
                audience: AUD.into(),
                tools: vec!["echo".into(), "repo.push".into(), "calc".into()],
                expires_at: Some(NOW + 3600),
            },
        )
        .expect("mint");
        let delegated =
            token::delegate(&root_token, &a, &b_jkt, &b_restrictions(&b_jkt)).expect("delegate");
        // Three attenuation levels: A narrows its own token, delegates to
        // B, and B narrows further to one branch.
        let narrowed = token::attenuate(
            &root_token,
            &Attenuation {
                tools: vec!["echo".into(), "repo.push".into()],
                expires_at: Some(NOW + 1800),
                ..Default::default()
            },
        )
        .expect("attenuate");
        let level2 =
            token::delegate(&narrowed, &a, &b_jkt, &b_restrictions(&b_jkt)).expect("delegate");
        let three_levels = token::attenuate(
            &level2,
            &Attenuation {
                arg_eq: vec![("/branch".into(), ArgValue::Str("feature/x".into()))],
                ..Default::default()
            },
        )
        .expect("attenuate");
        Self {
            root,
            a,
            b,
            c,
            root_token,
            delegated,
            three_levels,
        }
    }

    pub fn verifier(&self) -> Verifier {
        Verifier::new(Config::new(
            token::biscuit_public(&self.root).unwrap(),
            AUD,
            URL,
        ))
    }

    pub fn app(&self) -> (AuthenticatedMcp, Arc<Mutex<Vec<Value>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let app = AuthenticatedMcp::new(
            self.verifier(),
            demo_server(log.clone()),
            HttpConfig::default(),
        );
        (app, log)
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// A JSON-RPC body for `tools/call` in stateless (2026-07-28) mode.
pub fn call_body(tool: &str, args: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":tool,"arguments":args,
            "_meta":{"io.modelcontextprotocol/protocolVersion":MODERN}}})
    .to_string()
    .into_bytes()
}

pub fn method_body(method: &str) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":1,"method":method,
        "params":{"_meta":{"io.modelcontextprotocol/protocolVersion":MODERN}}})
    .to_string()
    .into_bytes()
}

/// An HTTP request.
#[derive(Clone)]
pub struct Req {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub now: u64,
}

pub fn mcp_headers(mcp_method: &str, name: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
        ("MCP-Protocol-Version".to_string(), MODERN.to_string()),
        ("Mcp-Method".to_string(), mcp_method.to_string()),
    ];
    if let Some(n) = name {
        h.push(("Mcp-Name".to_string(), n.to_string()));
    }
    h
}

/// Signed request: token presented with a fresh DPoP proof from `key`.
pub fn signed(
    token: &Biscuit,
    key: &SigningKey,
    body: Vec<u8>,
    mcp_method: &str,
    name: Option<&str>,
) -> Req {
    let tok = token.to_base64().unwrap();
    let proof = dpop::create(
        key,
        &ProofClaims {
            htm: "POST",
            htu: URL,
            iat: NOW,
            access_token: &tok,
            body: Some(&body),
            jti: None,
        },
    );
    let mut headers = mcp_headers(mcp_method, name);
    headers.push(("Authorization".into(), format!("DPoP {tok}")));
    headers.push(("DPoP".into(), proof));
    Req {
        method: "POST".into(),
        headers,
        body,
        now: NOW,
    }
}

pub fn call(token: &Biscuit, key: &SigningKey, tool: &str, args: Value) -> Req {
    signed(token, key, call_body(tool, args), "tools/call", Some(tool))
}

fn set_header(r: &mut Req, name: &str, value: String) {
    r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    r.headers.push((name.to_string(), value));
}

fn header_of(r: &Req, name: &str) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn reproof(r: &mut Req, key: &SigningKey, f: impl FnOnce(&mut Value)) {
    let tok = header_of(r, "authorization")
        .trim_start_matches("DPoP ")
        .to_string();
    let mut payload = json!({"jti": dpop::random_jti(), "htm":"POST","htu":URL,"iat":NOW,
        "ath": crate::b64::sha256_b64(tok.as_bytes()),
        "rbh": crate::b64::sha256_b64(&r.body)});
    f(&mut payload);
    let header =
        json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":jwk::public_jwk(&key.verifying_key())});
    set_header(r, "DPoP", dpop::sign_raw(key, &header, &payload));
}

/// One case: build requests; all but the last are sent first (setup, e.g.
/// the legitimate request that a replay copies). The last is judged.
pub struct Case {
    pub id: &'static str,
    pub class: &'static str,
    pub expect_allow: bool,
    pub build: fn(&World) -> Vec<Req>,
}

fn push_args() -> Value {
    json!({"repo":"acme/site","branch":"feature/login"})
}

pub fn cases() -> Vec<Case> {
    vec![
        // ---- controls: must be executed ----
        Case {
            id: "C1",
            class: "control",
            expect_allow: true,
            build: |w| vec![call(&w.root_token, &w.a, "echo", json!({"text":"hi"}))],
        },
        Case {
            id: "C2",
            class: "control",
            expect_allow: true,
            build: |w| vec![call(&w.delegated, &w.b, "repo.push", push_args())],
        },
        Case {
            id: "C3",
            class: "control",
            expect_allow: true,
            build: |w| {
                vec![signed(
                    &w.delegated,
                    &w.b,
                    method_body("tools/list"),
                    "tools/list",
                    None,
                )]
            },
        },
        Case {
            id: "C4",
            class: "control",
            expect_allow: true,
            build: |w| {
                vec![call(
                    &w.three_levels,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/site","branch":"feature/x"}),
                )]
            },
        },
        Case {
            id: "C5",
            class: "control",
            expect_allow: true,
            build: |w| {
                vec![call(
                    &w.root_token,
                    &w.a,
                    "repo.push",
                    json!({"repo":"any/repo","branch":"main","force":true}),
                )]
            },
        },
        Case {
            id: "C6",
            class: "control",
            expect_allow: true,
            build: |w| {
                // Two different requests with fresh proofs: no false replay.
                vec![
                    call(&w.delegated, &w.b, "repo.push", push_args()),
                    call(&w.delegated, &w.b, "repo.push", push_args()),
                ]
            },
        },
        // ---- other tool ----
        Case {
            id: "T1",
            class: "other_tool",
            expect_allow: false,
            build: |w| vec![call(&w.delegated, &w.b, "echo", json!({"text":"hi"}))],
        },
        Case {
            id: "T2",
            class: "other_tool",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "calc",
                    json!({"expression":"1+1"}),
                )]
            },
        },
        Case {
            id: "T3",
            class: "other_tool",
            expect_allow: false,
            build: |w| vec![call(&w.delegated, &w.b, "Repo.push", push_args())],
        },
        Case {
            id: "T4",
            class: "other_tool",
            expect_allow: false,
            build: |w| {
                vec![signed(
                    &w.delegated,
                    &w.b,
                    method_body("resources/read"),
                    "resources/read",
                    None,
                )]
            },
        },
        Case {
            id: "T5",
            class: "other_tool",
            expect_allow: false,
            build: |w| {
                let body = serde_json::to_vec(&json!([
                    serde_json::from_slice::<Value>(&call_body("repo.push", push_args())).unwrap(),
                    serde_json::from_slice::<Value>(&call_body("echo", json!({"text":"x"})))
                        .unwrap()
                ]))
                .unwrap();
                vec![signed(
                    &w.delegated,
                    &w.b,
                    body,
                    "tools/call",
                    Some("repo.push"),
                )]
            },
        },
        // ---- other argument ----
        Case {
            id: "A1",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/other","branch":"feature/x"}),
                )]
            },
        },
        Case {
            id: "A2",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/site","branch":"main"}),
                )]
            },
        },
        Case {
            id: "A3",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/site","branch":"feature/x","force":true}),
                )]
            },
        },
        Case {
            id: "A4",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/site","branch":"feature/x","opts":{"repo":"evil/x"}}),
                )]
            },
        },
        Case {
            id: "A5",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"repo.push","arguments":{"repo":"acme/site","branch":"feature/x","repo":"evil/x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.to_vec();
                vec![signed(
                    &w.delegated,
                    &w.b,
                    body,
                    "tools/call",
                    Some("repo.push"),
                )]
            },
        },
        Case {
            id: "A6",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"repo":["acme/site"],"branch":"feature/x"}),
                )]
            },
        },
        Case {
            id: "A7",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.delegated,
                    &w.b,
                    "repo.push",
                    json!({"branch":"feature/x"}),
                )]
            },
        },
        Case {
            id: "A8",
            class: "other_arg",
            expect_allow: false,
            build: |w| {
                vec![call(
                    &w.three_levels,
                    &w.b,
                    "repo.push",
                    json!({"repo":"acme/site","branch":"feature/y"}),
                )]
            },
        },
        // ---- re-delegation / holder change ----
        Case {
            id: "D1",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                let c_jkt = jwk::thumbprint(&w.c.verifying_key());
                let t =
                    token::delegate(&w.delegated, &w.b, &c_jkt, &Attenuation::default()).unwrap();
                vec![call(&t, &w.c, "repo.push", push_args())]
            },
        },
        Case {
            id: "D2",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                // Without a holder lock, a max_holder_changes=1 check still
                // stops a second hop.
                let b_jkt = jwk::thumbprint(&w.b.verifying_key());
                let c_jkt = jwk::thumbprint(&w.c.verifying_key());
                let t1 = token::delegate(
                    &w.root_token,
                    &w.a,
                    &b_jkt,
                    &Attenuation {
                        tools: vec!["echo".into()],
                        max_holder_changes: Some(1),
                        ..Default::default()
                    },
                )
                .unwrap();
                let t2 = token::delegate(&t1, &w.b, &c_jkt, &Attenuation::default()).unwrap();
                vec![call(&t2, &w.c, "echo", json!({"text":"x"}))]
            },
        },
        Case {
            id: "D3",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                // Thief appends an ordinary block claiming to be the holder.
                let c_jkt = jwk::thumbprint(&w.c.verifying_key());
                let t = w
                    .delegated
                    .append(
                        BlockBuilder::new().context(format!("{}{c_jkt}", token::CONTEXT_PREFIX)),
                    )
                    .unwrap();
                vec![call(&t, &w.c, "repo.push", push_args())]
            },
        },
        Case {
            id: "D4",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                // Thief signs the holder change with their own key.
                let c_jkt = jwk::thumbprint(&w.c.verifying_key());
                let t =
                    token::delegate(&w.root_token, &w.c, &c_jkt, &Attenuation::default()).unwrap();
                vec![call(&t, &w.c, "echo", json!({"text":"x"}))]
            },
        },
        Case {
            id: "D5",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                // Escalation: a later block asserts a right; scoping hides it.
                let t = w
                    .delegated
                    .append(BlockBuilder::new().code("right(\"calc\");").unwrap())
                    .unwrap();
                vec![call(&t, &w.b, "calc", json!({"expression":"1+1"}))]
            },
        },
        Case {
            id: "D6",
            class: "redelegation",
            expect_allow: false,
            build: |w| {
                // The delegator (A) keeps using B's narrowed token with its
                // own key: the token now belongs to B.
                vec![call(&w.delegated, &w.a, "repo.push", push_args())]
            },
        },
        // ---- replay / key binding ----
        Case {
            id: "R1",
            class: "replay",
            expect_allow: false,
            build: |w| vec![call(&w.delegated, &w.c, "repo.push", push_args())],
        },
        Case {
            id: "R2",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let tok = header_of(&r, "authorization")
                    .trim_start_matches("DPoP ")
                    .to_string();
                set_header(&mut r, "Authorization", format!("Bearer {tok}"));
                r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("dpop"));
                vec![r]
            },
        },
        Case {
            id: "R3",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let r = call(&w.delegated, &w.b, "repo.push", push_args());
                vec![r.clone(), r]
            },
        },
        Case {
            id: "R4",
            class: "replay",
            expect_allow: false,
            build: |w| {
                // Captured proof used first by the attacker with another body.
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                r.body = call_body(
                    "repo.push",
                    json!({"repo":"acme/site","branch":"feature/evil"}),
                );
                vec![r]
            },
        },
        Case {
            id: "R5",
            class: "replay",
            expect_allow: false,
            build: |w| {
                // Proof made for the root token, presented with B's token.
                let r_root = call(&w.root_token, &w.b, "repo.push", push_args());
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                set_header(&mut r, "DPoP", header_of(&r_root, "dpop"));
                vec![r]
            },
        },
        Case {
            id: "R6",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let b = w.b.clone();
                reproof(&mut r, &b, |p| {
                    p["htu"] = json!("http://127.0.0.1:9999/mcp")
                });
                vec![r]
            },
        },
        Case {
            id: "R7",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let b = w.b.clone();
                reproof(&mut r, &b, |p| p["htm"] = json!("GET"));
                vec![r]
            },
        },
        Case {
            id: "R8",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let b = w.b.clone();
                reproof(&mut r, &b, |p| p["iat"] = json!(NOW - 120));
                vec![r]
            },
        },
        Case {
            id: "R9",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let b = w.b.clone();
                reproof(&mut r, &b, |p| p["iat"] = json!(NOW + 60));
                vec![r]
            },
        },
        Case {
            id: "R10",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let tok = header_of(&r, "authorization")
                    .trim_start_matches("DPoP ")
                    .to_string();
                let payload = json!({"jti":"x1","htm":"POST","htu":URL,"iat":NOW,
                    "ath": crate::b64::sha256_b64(tok.as_bytes()), "rbh": crate::b64::sha256_b64(&r.body)});
                let h = crate::b64::encode(json!({"typ":"dpop+jwt","alg":"none","jwk":jwk::public_jwk(&w.b.verifying_key())}).to_string().as_bytes());
                let p = crate::b64::encode(payload.to_string().as_bytes());
                set_header(&mut r, "DPoP", format!("{h}.{p}."));
                vec![r]
            },
        },
        Case {
            id: "R11",
            class: "replay",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                let second = header_of(&call(&w.delegated, &w.b, "repo.push", push_args()), "dpop");
                r.headers.push(("DPoP".into(), second));
                vec![r]
            },
        },
        // ---- token validity ----
        Case {
            id: "V1",
            class: "token",
            expect_allow: false,
            build: |w| {
                let mut r = call(&w.delegated, &w.b, "repo.push", push_args());
                r.now = NOW + 601;
                let b = w.b.clone();
                reproof(&mut r, &b, |p| p["iat"] = json!(NOW + 601));
                vec![r]
            },
        },
        Case {
            id: "V2",
            class: "token",
            expect_allow: false,
            build: |w| {
                let other_root = jwk::generate();
                let t = token::mint(
                    &other_root,
                    &Grant {
                        holder_jkt: jwk::thumbprint(&w.a.verifying_key()),
                        audience: AUD.into(),
                        tools: vec!["echo".into()],
                        expires_at: None,
                    },
                )
                .unwrap();
                vec![call(&t, &w.a, "echo", json!({"text":"x"}))]
            },
        },
        Case {
            id: "V3",
            class: "token",
            expect_allow: false,
            build: |w| {
                let mut bytes = w.delegated.to_vec().unwrap();
                let mid = bytes.len() / 3;
                bytes[mid] ^= 0x01;
                let tok = crate::b64::encode(&bytes);
                let body = call_body("repo.push", push_args());
                let proof = dpop::create(
                    &w.b,
                    &ProofClaims {
                        htm: "POST",
                        htu: URL,
                        iat: NOW,
                        access_token: &tok,
                        body: Some(&body),
                        jti: None,
                    },
                );
                let mut headers = mcp_headers("tools/call", Some("repo.push"));
                headers.push(("Authorization".into(), format!("DPoP {tok}")));
                headers.push(("DPoP".into(), proof));
                vec![Req {
                    method: "POST".into(),
                    headers,
                    body,
                    now: NOW,
                }]
            },
        },
        Case {
            id: "V4",
            class: "token",
            expect_allow: false,
            build: |w| {
                let t = token::mint(
                    &w.root,
                    &Grant {
                        holder_jkt: jwk::thumbprint(&w.a.verifying_key()),
                        audience: "mcp://other-server".into(),
                        tools: vec!["echo".into()],
                        expires_at: None,
                    },
                )
                .unwrap();
                vec![call(&t, &w.a, "echo", json!({"text":"x"}))]
            },
        },
    ]
}

/// Outcome of one case.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub id: &'static str,
    pub class: &'static str,
    pub expect_allow: bool,
    pub status: u16,
    pub executed: bool,
    pub tool_error: bool,
    pub pass: bool,
    pub detail: String,
}

fn judge(resp: &HttpResponse) -> (bool, String) {
    let body = resp.body.clone().unwrap_or(Value::Null);
    let is_err = body
        .pointer("/result/isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || body.get("error").is_some();
    let detail = body
        .get("error_description")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| body.to_string().chars().take(160).collect());
    (is_err, detail)
}

/// Run the whole suite. Each case gets a fresh server (fresh jti cache and
/// call log).
pub fn run(w: &World) -> Vec<Outcome> {
    cases()
        .into_iter()
        .map(|c| {
            let (app, log) = w.app();
            let reqs = (c.build)(w);
            let (last, setup) = reqs.split_last().expect("case without request");
            for r in setup {
                let _ = app.handle_at(&r.method, "/mcp", &r.headers, &r.body, r.now);
            }
            let before = log.lock().unwrap().len();
            let resp = app.handle_at(&last.method, "/mcp", &last.headers, &last.body, last.now);
            let after = log.lock().unwrap().len();
            let (tool_error, detail) = judge(&resp);
            let mutating = matches!(c.id, "C2" | "C4" | "C5" | "C6");
            let executed = resp.status == 200 && !tool_error && (!mutating || after == before + 1);
            let pass = if c.expect_allow {
                executed
            } else {
                resp.status != 200 && after == before
            };
            Outcome {
                id: c.id,
                class: c.class,
                expect_allow: c.expect_allow,
                status: resp.status,
                executed,
                tool_error,
                pass,
                detail,
            }
        })
        .collect()
}

/// Summary used by the CLI and CI.
pub fn summary(out: &[Outcome]) -> Value {
    let attacks: Vec<&Outcome> = out.iter().filter(|o| !o.expect_allow).collect();
    let controls: Vec<&Outcome> = out.iter().filter(|o| o.expect_allow).collect();
    let rejected = attacks.iter().filter(|o| o.pass).count();
    let allowed = controls.iter().filter(|o| o.pass).count();
    json!({
        "attacks_total": attacks.len(),
        "attacks_rejected": rejected,
        "attack_rejection_rate": rejected as f64 / attacks.len().max(1) as f64,
        "controls_total": controls.len(),
        "controls_allowed": allowed,
        "criterion_met": rejected == attacks.len() && allowed == controls.len(),
        "cases": out.iter().map(|o| json!({"id":o.id,"class":o.class,"expect_allow":o.expect_allow,
            "status":o.status,"pass":o.pass,"detail":o.detail})).collect::<Vec<_>>(),
    })
}
