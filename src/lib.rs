//! # attenuable-mcp
//!
//! Attenuable capability tokens for MCP `tools/call`: Biscuit tokens whose
//! Datalog checks see the tool name and the canonicalized arguments, bound
//! to a DPoP (RFC 9449) key, with holder changes signed by the current
//! holder. See the README for what is and is not covered.

pub mod b64;
pub mod canon;
pub mod dpop;
pub mod jwk;
pub mod token;
