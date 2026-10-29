//! DPoP proofs (RFC 9449) with EdDSA/Ed25519 keys: creation for clients and
//! the section 4.3 checks for the resource server, plus a `jti` replay cache.
//!
//! Extension (not part of RFC 9449): the proof carries `rbh`, the
//! base64url SHA-256 of the HTTP request body. RFC 9449 section 11.7 notes
//! that DPoP does not cover the body and allows extra claims; for MCP the
//! body *is* the operation (`tools/call` name and arguments), so a captured
//! proof must not be reusable with a different body. The verifier can be
//! configured to require it (default) or not.

use crate::{b64, canon, jwk};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

pub const TYP: &str = "dpop+jwt";
pub const ALG: &str = "EdDSA";
/// Maximum accepted `jti` length (RFC 9449 section 11.1 asks servers to
/// reject unnecessarily large values).
pub const MAX_JTI: usize = 64;
/// Maximum accepted proof length in bytes.
pub const MAX_PROOF: usize = 2048;

/// Fields of a proof to create.
#[derive(Debug, Clone)]
pub struct ProofClaims<'a> {
    pub htm: &'a str,
    pub htu: &'a str,
    pub iat: u64,
    pub access_token: &'a str,
    pub body: Option<&'a [u8]>,
    /// Explicit jti (tests); random 128-bit if `None`.
    pub jti: Option<String>,
}

pub fn random_jti() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b64::encode(&b)
}

/// Create a DPoP proof JWT signed with `key`.
pub fn create(key: &SigningKey, c: &ProofClaims) -> String {
    let header = json!({"typ": TYP, "alg": ALG, "jwk": jwk::public_jwk(&key.verifying_key())});
    let mut payload = json!({
        "jti": c.jti.clone().unwrap_or_else(random_jti),
        "htm": c.htm,
        "htu": c.htu,
        "iat": c.iat,
        "ath": b64::sha256_b64(c.access_token.as_bytes()),
    });
    if let Some(body) = c.body {
        payload["rbh"] = Value::String(b64::sha256_b64(body));
    }
    sign_raw(key, &header, &payload)
}

/// Sign arbitrary header/payload objects (used by tests to build malformed
/// proofs).
pub fn sign_raw(key: &SigningKey, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64::encode(header.to_string().as_bytes()),
        b64::encode(payload.to_string().as_bytes())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", b64::encode(&sig.to_bytes()))
}

/// Why a proof was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError(pub String);

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid_dpop_proof: {}", self.0)
    }
}

fn err<T>(m: impl Into<String>) -> Result<T, ProofError> {
    Err(ProofError(m.into()))
}

/// What the server expects of the request.
#[derive(Debug, Clone)]
pub struct Expect<'a> {
    pub htm: &'a str,
    /// Canonical target URI configured on the server (not taken from the
    /// `Host` header).
    pub htu: &'a str,
    pub access_token: &'a str,
    pub body: &'a [u8],
    pub now: u64,
    /// Oldest accepted `iat` is `now - max_age`.
    pub max_age: u64,
    /// Newest accepted `iat` is `now + max_skew`.
    pub max_skew: u64,
    pub require_rbh: bool,
}

/// A proof that passed every check except replay.
#[derive(Debug, Clone)]
pub struct Verified {
    pub jkt: String,
    pub jti: String,
    pub iat: u64,
}

/// Syntax- and scheme-based normalization of an http(s) URI for `htu`
/// comparison (RFC 9449 section 4.3, RFC 3986 sections 6.2.2/6.2.3):
/// lowercase scheme and host, drop default port, empty path becomes `/`,
/// drop query and fragment. Percent-encoding is compared as-is.
pub fn normalize_htu(u: &str) -> Option<String> {
    let u = u.split(['#', '?']).next()?;
    let (scheme, rest) = u.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => "80",
        "https" => "443",
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (h, rest) = authority.split_at(end + 1);
        match rest.strip_prefix(':') {
            Some(p) => (h.to_string(), Some(p.to_string())),
            None if rest.is_empty() => (h.to_string(), None),
            None => return None,
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.to_string())),
            None => (authority.clone(), None),
        }
    };
    let authority = match port {
        Some(p) if p == default_port || p.is_empty() => host,
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    Some(format!("{scheme}://{authority}{path}"))
}

/// RFC 9449 section 4.3 checks 2-9, 11 and 12 (ath). Check 1 (single
/// header) is done by the caller; check 10 (nonce) is not implemented; the
/// key-binding half of check 12 is done against the Biscuit holder.
pub fn verify(proof: &str, e: &Expect) -> Result<Verified, ProofError> {
    if proof.len() > MAX_PROOF {
        return err("proof too large");
    }
    let mut parts = proof.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return err("not a compact JWS with three parts");
    };
    let header = b64::decode(h).ok_or(ProofError("header not base64url".into()))?;
    let payload = b64::decode(p).ok_or(ProofError("payload not base64url".into()))?;
    let sig = b64::decode(s).ok_or(ProofError("signature not base64url".into()))?;
    let header = canon::parse_strict(&header).map_err(|m| ProofError(format!("header: {m}")))?;
    let payload = canon::parse_strict(&payload).map_err(|m| ProofError(format!("payload: {m}")))?;

    if header.get("typ").and_then(Value::as_str) != Some(TYP) {
        return err("typ must be dpop+jwt");
    }
    if header.get("alg").and_then(Value::as_str) != Some(ALG) {
        return err("alg must be EdDSA");
    }
    if header.get("crit").is_some() {
        return err("crit is not supported");
    }
    let jwk_v = header.get("jwk").ok_or(ProofError("missing jwk".into()))?;
    let key = jwk::parse_public_jwk(jwk_v).map_err(ProofError)?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| ProofError("signature must be 64 bytes".into()))?;
    let signing_input = &proof.as_bytes()[..h.len() + 1 + p.len()];
    key.verify_strict(signing_input, &Signature::from_bytes(&sig))
        .map_err(|_| ProofError("signature does not verify".into()))?;

    let s = |k: &str| payload.get(k).and_then(Value::as_str);
    let jti = s("jti").ok_or(ProofError("missing jti".into()))?;
    if jti.is_empty() || jti.len() > MAX_JTI {
        return err("jti length out of range");
    }
    if s("htm") != Some(e.htm) {
        return err("htm does not match the request method");
    }
    let htu = s("htu").ok_or(ProofError("missing htu".into()))?;
    match (normalize_htu(htu), normalize_htu(e.htu)) {
        (Some(a), Some(b)) if a == b => {}
        _ => return err("htu does not match the target URI"),
    }
    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(ProofError("missing or non-integer iat".into()))?;
    if iat + e.max_age < e.now {
        return err("iat too old");
    }
    if iat > e.now + e.max_skew {
        return err("iat in the future");
    }
    if s("ath") != Some(b64::sha256_b64(e.access_token.as_bytes()).as_str()) {
        return err("ath does not match the access token");
    }
    match s("rbh") {
        Some(v) if v == b64::sha256_b64(e.body) => {}
        Some(_) => return err("rbh does not match the request body"),
        None if e.require_rbh => return err("missing rbh"),
        None => {}
    }
    Ok(Verified {
        jkt: jwk::thumbprint(&key),
        jti: jti.to_string(),
        iat,
    })
}

/// In-memory single-use cache of `(jkt, jti)` for the acceptance window
/// (RFC 9449 section 11.1). Stores SHA-256 of the pair, not the values.
/// When full it fails closed (rejects) instead of evicting live entries.
pub struct JtiCache {
    inner: Mutex<HashMap<[u8; 32], u64>>,
    capacity: usize,
}

impl JtiCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Record a use. `expires` is the last second at which the proof would
    /// still be accepted. Returns false on replay or when full.
    pub fn insert(&self, jkt: &str, jti: &str, now: u64, expires: u64) -> bool {
        let key = b64::sha256(format!("{jkt}\n{jti}").as_bytes());
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if m.get(&key).is_some_and(|&exp| exp >= now) {
            return false;
        }
        if m.len() >= self.capacity {
            m.retain(|_, exp| *exp >= now);
            if m.len() >= self.capacity {
                return false;
            }
        }
        m.insert(key, expires);
        true
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://mcp.example.com/mcp";

    fn expect<'a>(tok: &'a str, body: &'a [u8], now: u64) -> Expect<'a> {
        Expect {
            htm: "POST",
            htu: URL,
            access_token: tok,
            body,
            now,
            max_age: 60,
            max_skew: 5,
            require_rbh: true,
        }
    }

    fn proof(k: &SigningKey, tok: &str, body: &[u8], iat: u64) -> String {
        create(
            k,
            &ProofClaims {
                htm: "POST",
                htu: URL,
                iat,
                access_token: tok,
                body: Some(body),
                jti: None,
            },
        )
    }

    #[test]
    fn valid_proof_and_thumbprint() {
        let k = jwk::generate();
        let p = proof(&k, "tok", b"{}", 1000);
        let v = verify(&p, &expect("tok", b"{}", 1000)).unwrap();
        assert_eq!(v.jkt, jwk::thumbprint(&k.verifying_key()));
    }

    #[test]
    fn each_binding_is_checked() {
        let k = jwk::generate();
        let p = proof(&k, "tok", b"{}", 1000);
        assert!(verify(&p, &expect("other", b"{}", 1000)).is_err(), "ath");
        assert!(verify(&p, &expect("tok", b"{ }", 1000)).is_err(), "rbh");
        assert!(verify(&p, &expect("tok", b"{}", 1061)).is_err(), "old");
        assert!(verify(&p, &expect("tok", b"{}", 994)).is_err(), "future");
        let mut e = expect("tok", b"{}", 1000);
        e.htm = "GET";
        assert!(verify(&p, &e).is_err(), "htm");
        e = expect("tok", b"{}", 1000);
        e.htu = "https://mcp.example.com/other";
        assert!(verify(&p, &e).is_err(), "htu");
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let k = jwk::generate();
        let p = proof(&k, "tok", b"{}", 1000);
        let mut parts: Vec<String> = p.split('.').map(String::from).collect();
        let mut payload: Value = serde_json::from_slice(&b64::decode(&parts[1]).unwrap()).unwrap();
        payload["iat"] = json!(1001);
        parts[1] = b64::encode(payload.to_string().as_bytes());
        assert!(verify(&parts.join("."), &expect("tok", b"{}", 1000)).is_err());
    }

    #[test]
    fn alg_typ_and_private_jwk_rejected() {
        let k = jwk::generate();
        let payload = json!({"jti":"a","htm":"POST","htu":URL,"iat":1000,
            "ath": b64::sha256_b64(b"tok"), "rbh": b64::sha256_b64(b"{}")});
        let good_jwk = jwk::public_jwk(&k.verifying_key());
        for header in [
            json!({"typ":"dpop+jwt","alg":"none","jwk":good_jwk}),
            json!({"typ":"dpop+jwt","alg":"HS256","jwk":good_jwk}),
            json!({"typ":"JWT","alg":"EdDSA","jwk":good_jwk}),
            json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":jwk::private_jwk(&k)}),
            json!({"typ":"dpop+jwt","alg":"EdDSA"}),
        ] {
            let p = sign_raw(&k, &header, &payload);
            assert!(verify(&p, &expect("tok", b"{}", 1000)).is_err(), "{header}");
        }
        // Same payload with a correct header passes, so the cases above fail
        // for the header and not for something else.
        let ok = sign_raw(
            &k,
            &json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":good_jwk}),
            &payload,
        );
        assert!(verify(&ok, &expect("tok", b"{}", 1000)).is_ok());
    }

    #[test]
    fn jti_cache_single_use() {
        let c = JtiCache::new(2);
        assert!(c.insert("k", "1", 100, 160));
        assert!(!c.insert("k", "1", 101, 161));
        assert!(c.insert("k2", "1", 101, 161));
        // Full with live entries: fail closed.
        assert!(!c.insert("k", "2", 102, 162));
        // After expiry the old entries are pruned.
        assert!(c.insert("k", "3", 200, 260));
    }

    #[test]
    fn htu_normalization() {
        assert_eq!(
            normalize_htu("HTTPS://MCP.Example.com:443/mcp?x=1#f").as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(
            normalize_htu("http://127.0.0.1:8808/mcp").as_deref(),
            Some("http://127.0.0.1:8808/mcp")
        );
        assert_eq!(normalize_htu("http://h").as_deref(), Some("http://h/"));
        assert!(normalize_htu("ftp://h/x").is_none());
        assert!(normalize_htu("http://u@h/x").is_none());
    }
}
