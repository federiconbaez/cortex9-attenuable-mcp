//! Ed25519 keys as OKP JWKs (RFC 8037) and their RFC 7638 thumbprints.

use crate::b64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::{Value, json};

/// RFC 7638 thumbprint of an Ed25519 public key: base64url(SHA-256) over
/// `{"crv":"Ed25519","kty":"OKP","x":"..."}` (required members, sorted,
/// no whitespace).
pub fn thumbprint_raw(public: &[u8; 32]) -> String {
    let canon = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        b64::encode(public)
    );
    b64::sha256_b64(canon.as_bytes())
}

pub fn thumbprint(key: &VerifyingKey) -> String {
    thumbprint_raw(key.as_bytes())
}

/// Public JWK object for an Ed25519 key.
pub fn public_jwk(key: &VerifyingKey) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": b64::encode(key.as_bytes())})
}

/// Parse a *public* OKP/Ed25519 JWK. Rejects any JWK that carries the
/// private member `d` (RFC 9449 section 4.3 check 7).
pub fn parse_public_jwk(v: &Value) -> Result<VerifyingKey, String> {
    let obj = v.as_object().ok_or("jwk is not an object")?;
    if obj.contains_key("d") {
        return Err("jwk contains a private key".into());
    }
    if obj.get("kty").and_then(Value::as_str) != Some("OKP") {
        return Err("jwk kty must be OKP".into());
    }
    if obj.get("crv").and_then(Value::as_str) != Some("Ed25519") {
        return Err("jwk crv must be Ed25519".into());
    }
    let x = obj
        .get("x")
        .and_then(Value::as_str)
        .and_then(b64::decode)
        .ok_or("jwk x is not base64url")?;
    let x: [u8; 32] = x.try_into().map_err(|_| "jwk x must be 32 bytes")?;
    VerifyingKey::from_bytes(&x).map_err(|_| "jwk x is not a valid point".to_string())
}

/// A private key file: an OKP JWK with `d`.
pub fn private_jwk(key: &SigningKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64::encode(key.verifying_key().as_bytes()),
        "d": b64::encode(&key.to_bytes()),
    })
}

pub fn parse_private_jwk(v: &Value) -> Result<SigningKey, String> {
    let d = v
        .get("d")
        .and_then(Value::as_str)
        .and_then(b64::decode)
        .ok_or("private jwk without d")?;
    let d: [u8; 32] = d.try_into().map_err(|_| "d must be 32 bytes")?;
    let sk = SigningKey::from_bytes(&d);
    if v.get("x")
        .and_then(Value::as_str)
        .is_some_and(|x| x != b64::encode(sk.verifying_key().as_bytes()))
    {
        return Err("x does not match d".into());
    }
    Ok(sk)
}

pub fn generate() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.3: thumbprint of the appendix A.2 public key.
    #[test]
    fn rfc8037_thumbprint_vector() {
        let x = b64::decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        let x: [u8; 32] = x.try_into().unwrap();
        assert_eq!(
            thumbprint_raw(&x),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn private_member_rejected() {
        let sk = generate();
        assert!(parse_public_jwk(&private_jwk(&sk)).is_err());
        assert!(parse_public_jwk(&public_jwk(&sk.verifying_key())).is_ok());
    }

    #[test]
    fn private_roundtrip() {
        let sk = generate();
        let back = parse_private_jwk(&private_jwk(&sk)).unwrap();
        assert_eq!(back.to_bytes(), sk.to_bytes());
    }
}

#[cfg(test)]
mod rfc8037_signing {
    use super::*;
    use ed25519_dalek::Signer;

    /// RFC 8037 appendix A.1 key and A.4 JWS: our JWK parser and the
    /// signer reproduce the published compact serialization.
    #[test]
    fn rfc8037_a4_signature_vector() {
        let jwk = json!({"kty":"OKP","crv":"Ed25519",
            "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        let sk = parse_private_jwk(&jwk).unwrap();
        let input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let sig = sk.sign(input.as_bytes());
        assert_eq!(
            b64::encode(&sig.to_bytes()),
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        );
    }
}
