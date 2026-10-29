//! Per-request verification: DPoP proof + Biscuit + Datalog over the MCP
//! request (method, tool, canonical arguments).

use crate::canon::{self, Leaf};
use crate::dpop::{self, JtiCache};
use crate::token;
use biscuit_auth::builder::{Fact, Term, fact};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit, PublicKey};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Methods every valid token may call (lifecycle and listing). Everything
/// else except `tools/call` is denied.
pub const PUBLIC_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "ping",
    "tools/list",
    "server/discover",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PublicKey,
    pub audience: String,
    /// Canonical URL of the MCP endpoint, compared with `htu`.
    pub endpoint_url: String,
    pub max_age: u64,
    pub max_skew: u64,
    pub require_rbh: bool,
    pub jti_capacity: usize,
    pub limits: AuthorizerLimits,
    pub max_token_bytes: usize,
    /// Number of verified tokens kept (keyed by SHA-256 of the exact token
    /// string). 0 disables the cache: every request re-verifies the whole
    /// signature chain.
    pub token_cache: usize,
}

impl Config {
    pub fn new(root: PublicKey, audience: &str, endpoint_url: &str) -> Self {
        Self {
            root,
            audience: audience.to_string(),
            endpoint_url: endpoint_url.to_string(),
            max_age: 60,
            max_skew: 5,
            require_rbh: true,
            jti_capacity: 100_000,
            limits: AuthorizerLimits {
                max_facts: 2000,
                max_iterations: 100,
                max_time: Duration::from_millis(50),
            },
            max_token_bytes: 16 * 1024,
            token_cache: 1024,
        }
    }
}

/// Why a request was refused. `status` is the HTTP status to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub status: u16,
    pub error: &'static str,
    pub reason: String,
}

fn deny<T>(status: u16, error: &'static str, reason: impl Into<String>) -> Result<T, Denied> {
    Err(Denied {
        status,
        error,
        reason: reason.into(),
    })
}

/// A request that passed.
#[derive(Debug, Clone)]
pub struct Allowed {
    pub method: String,
    pub tool: Option<String>,
    pub holder: String,
    pub holder_changes: i64,
    pub blocks: usize,
}

/// The MCP operation extracted from a JSON-RPC body.
#[derive(Debug, Clone)]
pub struct Operation {
    pub method: String,
    pub tool: Option<String>,
    pub args: Vec<(String, Leaf)>,
}

/// Parse the body strictly and extract the operation. Batches are refused:
/// one request, one authorization decision.
pub fn operation(body: &[u8]) -> Result<Operation, String> {
    let v = canon::parse_strict(body)?;
    let obj = match &v {
        Value::Object(o) => o,
        Value::Array(_) => return Err("JSON-RPC batches are not accepted".into()),
        _ => return Err("body is not a JSON-RPC object".into()),
    };
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .ok_or("missing method")?
        .to_string();
    if method != "tools/call" {
        return Ok(Operation {
            method,
            tool: None,
            args: Vec::new(),
        });
    }
    let params = obj
        .get("params")
        .and_then(Value::as_object)
        .ok_or("tools/call without params")?;
    let tool = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("tools/call without name")?;
    let args = match params.get("arguments") {
        None => Vec::new(),
        Some(a @ Value::Object(_)) => canon::flatten(a)?,
        Some(_) => return Err("arguments must be an object".into()),
    };
    Ok(Operation {
        method,
        tool: Some(tool.to_string()),
        args,
    })
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

/// A token whose signature chain and holder chain were verified.
struct VerifiedToken {
    biscuit: Biscuit,
    chain: token::HolderChain,
}

pub struct Verifier {
    cfg: Config,
    jti: JtiCache,
    tokens: Mutex<HashMap<[u8; 32], Arc<VerifiedToken>>>,
}

impl Verifier {
    pub fn new(cfg: Config) -> Self {
        let jti = JtiCache::new(cfg.jti_capacity);
        Self {
            cfg,
            jti,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Parse and verify the token (signatures against the root key, holder
    /// chain), or reuse a previous verification of the identical string.
    /// Biscuit tokens are immutable, so a cache hit for the same bytes is
    /// the same verification result; time-dependent checks are Datalog and
    /// run on every request.
    fn verified_token(&self, tok: &str) -> Result<Arc<VerifiedToken>, Denied> {
        let key = crate::b64::sha256(tok.as_bytes());
        if self.cfg.token_cache > 0
            && let Some(v) = self
                .tokens
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&key)
        {
            return Ok(v.clone());
        }
        let biscuit = Biscuit::from_base64(tok, self.cfg.root).map_err(|e| Denied {
            status: 401,
            error: "invalid_token",
            reason: format!("token does not verify: {e}"),
        })?;
        let chain = token::holder_chain(&biscuit).map_err(|e| Denied {
            status: 401,
            error: "invalid_token",
            reason: e.0,
        })?;
        let v = Arc::new(VerifiedToken { biscuit, chain });
        if self.cfg.token_cache > 0 {
            let mut m = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
            if m.len() >= self.cfg.token_cache {
                m.clear();
            }
            m.insert(key, v.clone());
        }
        Ok(v)
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Verify one HTTP request. `now` is unix seconds.
    pub fn verify(
        &self,
        http_method: &str,
        headers: &[(String, String)],
        body: &[u8],
        now: u64,
    ) -> Result<Allowed, Denied> {
        // Authorization: exactly one, scheme DPoP (Bearer downgrade refused,
        // RFC 9449 section 7.2).
        let authz = header(headers, "authorization");
        if authz.len() != 1 {
            return deny(
                401,
                "invalid_request",
                "expected exactly one Authorization header",
            );
        }
        let (scheme, tok) = authz[0].split_once(' ').unwrap_or((authz[0], ""));
        if !scheme.eq_ignore_ascii_case("DPoP") {
            return deny(401, "invalid_token", "Authorization scheme must be DPoP");
        }
        let tok = tok.trim();
        if tok.is_empty() || tok.len() > self.cfg.max_token_bytes {
            return deny(401, "invalid_token", "missing or oversized token");
        }
        // DPoP header: exactly one (RFC 9449 section 4.3 check 1).
        let proofs = header(headers, "dpop");
        if proofs.len() != 1 {
            return deny(
                401,
                "invalid_dpop_proof",
                "expected exactly one DPoP header",
            );
        }
        let proof = dpop::verify(
            proofs[0].trim(),
            &dpop::Expect {
                htm: http_method,
                htu: &self.cfg.endpoint_url,
                access_token: tok,
                body,
                now,
                max_age: self.cfg.max_age,
                max_skew: self.cfg.max_skew,
                require_rbh: self.cfg.require_rbh,
            },
        )
        .map_err(|e| Denied {
            status: 401,
            error: "invalid_dpop_proof",
            reason: e.0,
        })?;

        let vt = self.verified_token(tok)?;
        let (biscuit, chain) = (&vt.biscuit, &vt.chain);
        if chain.current() != proof.jkt {
            return deny(401, "invalid_token", "DPoP key is not the token holder");
        }
        // Single use of the proof. Recorded only for proofs that are
        // otherwise valid for this token, so garbage cannot fill the cache.
        if !self
            .jti
            .insert(&proof.jkt, &proof.jti, now, proof.iat + self.cfg.max_age)
        {
            return deny(401, "invalid_dpop_proof", "jti already used (replay)");
        }

        let op = operation(body).map_err(|m| Denied {
            status: 400,
            error: "invalid_request",
            reason: m,
        })?;

        let facts = request_facts(&op, &proof.jkt, chain.changes(), &self.cfg.audience, now);
        let mut ab = AuthorizerBuilder::new().set_limits(self.cfg.limits.clone());
        for f in facts {
            ab = ab.fact(f).map_err(|e| Denied {
                status: 500,
                error: "server_error",
                reason: e.to_string(),
            })?;
        }
        let public: BTreeSet<Term> = PUBLIC_METHODS
            .iter()
            .map(|m| Term::Str(m.to_string()))
            .collect();
        ab = ab
            .code_with_params(
                "allow if method($m), {public}.contains($m);
                 allow if method(\"tools/call\"), tool($t), right($t);
                 deny if true;",
                HashMap::from([("public".to_string(), Term::Set(public))]),
                HashMap::new(),
            )
            .map_err(|e| Denied {
                status: 500,
                error: "server_error",
                reason: e.to_string(),
            })?;
        let mut authorizer = ab.build(biscuit).map_err(|e| Denied {
            status: 403,
            error: "insufficient_scope",
            reason: e.to_string(),
        })?;
        authorizer.authorize().map_err(|e| Denied {
            status: 403,
            error: "insufficient_scope",
            reason: format!("{e}"),
        })?;
        Ok(Allowed {
            method: op.method,
            tool: op.tool,
            holder: proof.jkt,
            holder_changes: chain.changes(),
            blocks: biscuit.block_count(),
        })
    }
}

/// Authorizer facts describing the request.
pub fn request_facts(
    op: &Operation,
    jkt: &str,
    changes: i64,
    audience: &str,
    now: u64,
) -> Vec<Fact> {
    let s = |v: &str| Term::Str(v.to_string());
    let mut out = vec![
        fact("method", &[s(&op.method)]),
        fact("dpop_jkt", &[s(jkt)]),
        fact("holder_changes", &[Term::Integer(changes)]),
        fact("audience", &[s(audience)]),
        fact("time", &[Term::Date(now)]),
    ];
    if let Some(t) = &op.tool {
        out.push(fact("tool", &[s(t)]));
    }
    for (ptr, leaf) in &op.args {
        out.push(fact("arg_path", &[s(ptr)]));
        let v = match leaf {
            Leaf::Str(v) => Some(Term::Str(v.clone())),
            Leaf::Int(i) => Some(Term::Integer(*i)),
            Leaf::Bool(b) => Some(Term::Bool(*b)),
            Leaf::Null => Some(Term::Null),
            Leaf::Num(n) => {
                out.push(fact("arg_num", &[s(ptr), s(n)]));
                None
            }
            Leaf::Empty => None,
        };
        if let Some(v) = v {
            out.push(fact("arg", &[s(ptr), v]));
        }
    }
    out
}
