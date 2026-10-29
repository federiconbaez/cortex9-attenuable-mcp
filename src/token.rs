//! Biscuit capability tokens for MCP: minting, offline attenuation, and
//! key-changing delegation signed by the current holder.
//!
//! Holder binding. The authority block's `context` is `attn:holder=<jkt>`,
//! the RFC 7638 thumbprint of the DPoP key the token is issued to. Anybody
//! who has a Biscuit can append blocks (that is what offline attenuation
//! means), so a holder *change* cannot be an ordinary block: a block whose
//! context is `attn:holder=<new>` is honoured only when it is a Biscuit
//! third-party block whose external signature verifies with the key of the
//! *current* holder. A thief who copies the token can still restrict it,
//! but cannot move it to their own key, and the DPoP proof must come from
//! the holder at the end of the chain.
//!
//! Rights. The authority block carries `right(<tool>)` and an audience
//! check. Later blocks only add checks: by Biscuit scoping rules, facts in
//! later blocks are invisible to the authorizer's policies, so a block that
//! says `right("other")` grants nothing.

use crate::jwk;
use biscuit_auth::builder::{Algorithm, BlockBuilder, Term};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeSet, HashMap};

pub const CONTEXT_PREFIX: &str = "attn:holder=";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError(pub String);

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<biscuit_auth::error::Token> for TokenError {
    fn from(e: biscuit_auth::error::Token) -> Self {
        TokenError(format!("biscuit: {e}"))
    }
}

/// Convert an Ed25519 signing key into a Biscuit key pair.
pub fn biscuit_keypair(sk: &SigningKey) -> Result<KeyPair, TokenError> {
    let pk = PrivateKey::from_bytes(&sk.to_bytes(), Algorithm::Ed25519)
        .map_err(|e| TokenError(e.to_string()))?;
    Ok(KeyPair::from(&pk))
}

pub fn biscuit_public(sk: &SigningKey) -> Result<PublicKey, TokenError> {
    PublicKey::from_bytes(sk.verifying_key().as_bytes(), Algorithm::Ed25519)
        .map_err(|e| TokenError(e.to_string()))
}

/// Thumbprint of a Biscuit public key, if it is Ed25519.
pub fn biscuit_key_jkt(pk: &PublicKey) -> Option<String> {
    let bytes: [u8; 32] = pk.to_bytes().try_into().ok()?;
    match pk.algorithm() {
        biscuit_auth::format::schema::public_key::Algorithm::Ed25519 => {
            Some(jwk::thumbprint_raw(&bytes))
        }
        _ => None,
    }
}

/// What the root token grants.
#[derive(Debug, Clone)]
pub struct Grant {
    pub holder_jkt: String,
    pub audience: String,
    pub tools: Vec<String>,
    /// Unix seconds; `None` = no expiry in the authority block.
    pub expires_at: Option<u64>,
}

/// Mint a root token signed by `root`.
pub fn mint(root: &SigningKey, g: &Grant) -> Result<Biscuit, TokenError> {
    let mut b = Biscuit::builder().context(format!("{CONTEXT_PREFIX}{}", g.holder_jkt));
    for t in &g.tools {
        b = b.code_with_params(
            "right({t});",
            HashMap::from([("t".to_string(), Term::Str(t.clone()))]),
            HashMap::new(),
        )?;
    }
    b = b.code_with_params(
        "check if audience({aud});",
        HashMap::from([("aud".to_string(), Term::Str(g.audience.clone()))]),
        HashMap::new(),
    )?;
    if let Some(exp) = g.expires_at {
        b = b.code_with_params(
            "check if time($t), $t <= {exp};",
            HashMap::from([("exp".to_string(), Term::Date(exp))]),
            HashMap::new(),
        )?;
    }
    Ok(b.build(&biscuit_keypair(root)?)?)
}

/// Value constraint on one argument leaf.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl ArgValue {
    fn term(&self) -> Term {
        match self {
            ArgValue::Str(s) => Term::Str(s.clone()),
            ArgValue::Int(i) => Term::Integer(*i),
            ArgValue::Bool(b) => Term::Bool(*b),
        }
    }
}

/// Restrictions added by one attenuation block. Every field is optional;
/// all present fields must hold.
#[derive(Debug, Clone, Default)]
pub struct Attenuation {
    /// `tools/call` limited to these tool names.
    pub tools: Vec<String>,
    /// `tools/call` requires argument `pointer` == value.
    pub arg_eq: Vec<(String, ArgValue)>,
    /// `tools/call` requires string argument `pointer` to start with prefix.
    pub arg_prefix: Vec<(String, String)>,
    /// Closed world: every argument leaf must be one of these pointers.
    pub only_args: Option<Vec<String>>,
    /// Methods other than `tools/call` are refused.
    pub tools_call_only: bool,
    pub expires_at: Option<u64>,
    /// The token can only be used with a DPoP key of this thumbprint, which
    /// also forbids any later holder change (no re-delegation).
    pub lock_holder: Option<String>,
    /// Maximum number of holder changes allowed in the whole chain.
    pub max_holder_changes: Option<i64>,
}

fn p(k: &str, v: Term) -> (String, Term) {
    (k.to_string(), v)
}

fn str_set(items: &[String]) -> Term {
    Term::Set(
        items
            .iter()
            .cloned()
            .map(Term::Str)
            .collect::<BTreeSet<_>>(),
    )
}

impl Attenuation {
    /// Datalog block for these restrictions.
    pub fn block(&self) -> Result<BlockBuilder, TokenError> {
        let mut b = BlockBuilder::new();
        let add = |b: BlockBuilder, code: &str, params: Vec<(String, Term)>| {
            b.code_with_params(code, params.into_iter().collect(), HashMap::new())
        };
        // Non-tools/call methods pass every tools/call-specific check.
        const OTHER: &str = "method($m), $m !== \"tools/call\"";
        if !self.tools.is_empty() {
            b = add(
                b,
                &format!("check if {OTHER} or tool($t), {{tools}}.contains($t);"),
                vec![p("tools", str_set(&self.tools))],
            )?;
        }
        for (ptr, v) in &self.arg_eq {
            b = add(
                b,
                &format!("check if {OTHER} or arg({{ptr}}, {{v}});"),
                vec![p("ptr", Term::Str(ptr.clone())), p("v", v.term())],
            )?;
        }
        for (ptr, prefix) in &self.arg_prefix {
            b = add(
                b,
                &format!(
                    "check if {OTHER} or arg({{ptr}}, $v), $v.type() === \"string\", $v.starts_with({{pre}});"
                ),
                vec![
                    p("ptr", Term::Str(ptr.clone())),
                    p("pre", Term::Str(prefix.clone())),
                ],
            )?;
        }
        if let Some(only) = &self.only_args {
            b = add(
                b,
                "reject if arg_path($p), !{allowed}.contains($p);",
                vec![p("allowed", str_set(only))],
            )?;
        }
        if self.tools_call_only {
            b = add(b, "check if method(\"tools/call\");", vec![])?;
        }
        if let Some(exp) = self.expires_at {
            b = add(
                b,
                "check if time($t), $t <= {exp};",
                vec![p("exp", Term::Date(exp))],
            )?;
        }
        if let Some(jkt) = &self.lock_holder {
            b = add(
                b,
                "check if dpop_jkt({jkt});",
                vec![p("jkt", Term::Str(jkt.clone()))],
            )?;
        }
        if let Some(n) = self.max_holder_changes {
            b = add(
                b,
                "check if holder_changes($n), $n <= {max};",
                vec![p("max", Term::Integer(n))],
            )?;
        }
        Ok(b)
    }
}

/// Offline attenuation without changing the holder. Anyone holding the
/// token can do this; it can only restrict.
pub fn attenuate(token: &Biscuit, a: &Attenuation) -> Result<Biscuit, TokenError> {
    Ok(token.append(a.block()?)?)
}

/// Delegate to a new holder (`to_jkt`), adding restrictions. The block is a
/// third-party block signed by `current_holder`, the DPoP key the token is
/// currently bound to. In a real deployment the subagent sends only its
/// thumbprint; the delegating agent never sees the subagent's private key.
pub fn delegate(
    token: &Biscuit,
    current_holder: &SigningKey,
    to_jkt: &str,
    a: &Attenuation,
) -> Result<Biscuit, TokenError> {
    let req = token.third_party_request()?;
    let block = a.block()?.context(format!("{CONTEXT_PREFIX}{to_jkt}"));
    let signed = req.create_block(&biscuit_keypair(current_holder)?.private(), block)?;
    Ok(token.append_third_party(biscuit_public(current_holder)?, signed)?)
}

/// Resolved holder chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderChain {
    /// Holder thumbprints, root first.
    pub holders: Vec<String>,
}

impl HolderChain {
    pub fn current(&self) -> &str {
        self.holders.last().map(String::as_str).unwrap_or("")
    }
    pub fn changes(&self) -> i64 {
        self.holders.len() as i64 - 1
    }
}

/// Walk the blocks and resolve who may present this token.
pub fn holder_chain(token: &Biscuit) -> Result<HolderChain, TokenError> {
    let contexts = token.context();
    let externals = token.external_public_keys();
    let parse = |c: &Option<String>| -> Result<Option<String>, TokenError> {
        match c {
            Some(c) if c.starts_with("attn:") => match c.strip_prefix(CONTEXT_PREFIX) {
                Some(j) if !j.is_empty() && j.len() <= 64 && !j.contains(['\n', ' ']) => {
                    Ok(Some(j.to_string()))
                }
                _ => Err(TokenError(format!("malformed context {c:?}"))),
            },
            _ => Ok(None),
        }
    };
    let root = parse(contexts.first().unwrap_or(&None))?
        .ok_or_else(|| TokenError("authority block does not name a holder".into()))?;
    let mut holders = vec![root];
    for (i, ctx) in contexts.iter().enumerate().skip(1) {
        let Some(next) = parse(ctx)? else {
            continue;
        };
        let current = holders.last().cloned().unwrap_or_default();
        match externals.get(i).cloned().flatten() {
            None => {
                return Err(TokenError(format!(
                    "block {i} changes the holder without the holder's signature"
                )));
            }
            Some(pk) => {
                if biscuit_key_jkt(&pk).as_deref() != Some(current.as_str()) {
                    return Err(TokenError(format!(
                        "block {i} changes the holder but is not signed by the current holder"
                    )));
                }
            }
        }
        holders.push(next);
    }
    Ok(HolderChain { holders })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(holder: &SigningKey) -> Grant {
        Grant {
            holder_jkt: jwk::thumbprint(&holder.verifying_key()),
            audience: "aud".into(),
            tools: vec!["echo".into()],
            expires_at: None,
        }
    }

    #[test]
    fn chain_follows_signed_delegations() {
        let (root, a, b, c) = (
            jwk::generate(),
            jwk::generate(),
            jwk::generate(),
            jwk::generate(),
        );
        let t = mint(&root, &grant(&a)).unwrap();
        let ja = jwk::thumbprint(&a.verifying_key());
        let jb = jwk::thumbprint(&b.verifying_key());
        let jc = jwk::thumbprint(&c.verifying_key());
        assert_eq!(holder_chain(&t).unwrap().holders, vec![ja.clone()]);
        // Plain attenuation keeps the holder.
        let t1 = attenuate(
            &t,
            &Attenuation {
                tools: vec!["echo".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(holder_chain(&t1).unwrap().current(), ja);
        let t2 = delegate(&t1, &a, &jb, &Attenuation::default()).unwrap();
        let t3 = delegate(&t2, &b, &jc, &Attenuation::default()).unwrap();
        let ch = holder_chain(&t3).unwrap();
        assert_eq!(ch.holders, vec![ja, jb, jc]);
        assert_eq!(ch.changes(), 2);
    }

    #[test]
    fn unsigned_or_wrongly_signed_holder_change_is_rejected() {
        let (root, a, c) = (jwk::generate(), jwk::generate(), jwk::generate());
        let t = mint(&root, &grant(&a)).unwrap();
        let jc = jwk::thumbprint(&c.verifying_key());
        let plain = t
            .append(BlockBuilder::new().context(format!("{CONTEXT_PREFIX}{jc}")))
            .unwrap();
        assert!(holder_chain(&plain).is_err());
        let wrong = delegate(&t, &c, &jc, &Attenuation::default()).unwrap();
        assert!(holder_chain(&wrong).is_err());
        let malformed = t
            .append(BlockBuilder::new().context("attn:holder=".into()))
            .unwrap();
        assert!(holder_chain(&malformed).is_err());
        // Unrelated contexts are ignored.
        let other = t
            .append(BlockBuilder::new().context("note: hello".into()))
            .unwrap();
        assert!(holder_chain(&other).is_ok());
    }

    #[test]
    fn datalog_parameters_are_not_injectable() {
        // A tool name containing quotes and Datalog syntax must stay one
        // string term: the check still refuses "calc".
        let (root, a) = (jwk::generate(), jwk::generate());
        let mut g = grant(&a);
        g.tools = vec!["calc".into()];
        let t = mint(&root, &g).unwrap();
        let evil = "x\"}.contains($t) or true; right(\"calc";
        let t = attenuate(
            &t,
            &Attenuation {
                tools: vec![evil.into()],
                ..Default::default()
            },
        )
        .unwrap();
        let run = |tool: &str| {
            let mut az = biscuit_auth::AuthorizerBuilder::new()
                .code_with_params(
                    "method(\"tools/call\"); tool({t}); audience(\"aud\");
                     allow if tool($t), right($t);",
                    HashMap::from([("t".to_string(), Term::Str(tool.to_string()))]),
                    HashMap::new(),
                )
                .unwrap()
                .build(&t)
                .unwrap();
            az.authorize().is_ok()
        };
        assert!(!run("calc"));
    }
}
