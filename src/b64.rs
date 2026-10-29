//! base64url without padding (RFC 7515 section 2).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict decode: rejects padding and the standard alphabet.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// base64url(SHA-256(bytes)), as used by `ath` (RFC 9449 section 4.2).
pub fn sha256_b64(bytes: &[u8]) -> String {
    encode(&sha256(bytes))
}
