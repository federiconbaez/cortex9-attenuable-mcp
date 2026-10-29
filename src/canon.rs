//! Strict JSON parsing and canonicalization of `tools/call` arguments into
//! Datalog facts.
//!
//! The authorizer and the MCP dispatcher must see *the same* arguments.
//! `serde_json` keeps the last value of a duplicated object key, while other
//! parsers keep the first one; a request such as
//! `{"repo":"allowed","repo":"other"}` could then be authorized on one value
//! and executed on the other. [`parse_strict`] rejects duplicated keys
//! anywhere in the document, so there is a single interpretation.
//!
//! Arguments are flattened into leaves addressed by RFC 6901 JSON Pointers
//! (`/opts/force`, `/paths/0`). Each leaf produces `arg_path(pointer)` and
//! `arg(pointer, value)`. Integers become Datalog integers, strings stay
//! strings, booleans stay booleans, `null` is `null`, and non-integer numbers
//! are passed as their JSON text in an `arg_num(pointer, text)` fact (Datalog
//! has no floats). Empty objects/arrays produce `arg_path` only.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Maximum number of leaves accepted in `arguments`.
pub const MAX_LEAVES: usize = 256;
/// Maximum nesting depth accepted in `arguments`.
pub const MAX_DEPTH: usize = 16;
/// Maximum length (bytes) of a string leaf or pointer.
pub const MAX_STR: usize = 4096;

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate object key {k:?}")));
            }
            let Strict(v) = map.next_value()?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parse JSON rejecting duplicated object keys at any depth.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(v) = Strict::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

/// One canonical argument leaf.
#[derive(Debug, Clone, PartialEq)]
pub enum Leaf {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
    /// Non-integer number, kept as its JSON text.
    Num(String),
    /// Empty object or array (only `arg_path` is emitted).
    Empty,
}

/// Escape one JSON Pointer reference token (RFC 6901 section 3).
pub fn escape_token(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// Flatten `arguments` into `(pointer, leaf)` pairs, sorted by pointer.
pub fn flatten(args: &Value) -> Result<Vec<(String, Leaf)>, String> {
    let mut out = Vec::new();
    walk(args, String::new(), 0, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(v: &Value, ptr: String, depth: usize, out: &mut Vec<(String, Leaf)>) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("arguments nested too deeply".into());
    }
    if ptr.len() > MAX_STR {
        return Err("argument pointer too long".into());
    }
    let push = |out: &mut Vec<(String, Leaf)>, leaf: Leaf| -> Result<(), String> {
        if out.len() >= MAX_LEAVES {
            return Err("too many argument leaves".into());
        }
        out.push((ptr.clone(), leaf));
        Ok(())
    };
    match v {
        Value::Object(m) if m.is_empty() => push(out, Leaf::Empty),
        Value::Array(a) if a.is_empty() => push(out, Leaf::Empty),
        Value::Object(m) => {
            for (k, child) in m {
                walk(child, format!("{ptr}/{}", escape_token(k)), depth + 1, out)?;
            }
            Ok(())
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                walk(child, format!("{ptr}/{i}"), depth + 1, out)?;
            }
            Ok(())
        }
        Value::String(s) => {
            if s.len() > MAX_STR {
                return Err("argument string too long".into());
            }
            push(out, Leaf::Str(s.clone()))
        }
        Value::Bool(b) => push(out, Leaf::Bool(*b)),
        Value::Null => push(out, Leaf::Null),
        Value::Number(n) => match n.as_i64() {
            Some(i) => push(out, Leaf::Int(i)),
            None => push(out, Leaf::Num(n.to_string())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duplicate_keys_rejected_at_any_depth() {
        assert!(parse_strict(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict(br#"{"p":{"arguments":{"repo":"x","repo":"y"}}}"#).is_err());
        // Escaped spelling of the same key is still a duplicate after decoding.
        assert!(parse_strict(br#"{"repo":"x","\u0072epo":"y"}"#).is_err());
        assert!(parse_strict(br#"{"a":1,"b":[{"c":1},{"c":2}]}"#).is_ok());
    }

    #[test]
    fn trailing_garbage_rejected() {
        assert!(parse_strict(br#"{"a":1} {"a":2}"#).is_err());
    }

    #[test]
    fn flatten_pointers_and_types() {
        let v = json!({"repo":"o/r","opts":{"force":false,"n":3,"x":1.5},"a/b":null,"t~":[],"l":["p","q"]});
        let f = flatten(&v).unwrap();
        let get = |p: &str| f.iter().find(|(k, _)| k == p).map(|(_, l)| l.clone());
        assert_eq!(get("/repo"), Some(Leaf::Str("o/r".into())));
        assert_eq!(get("/opts/force"), Some(Leaf::Bool(false)));
        assert_eq!(get("/opts/n"), Some(Leaf::Int(3)));
        assert_eq!(get("/opts/x"), Some(Leaf::Num("1.5".into())));
        assert_eq!(get("/a~1b"), Some(Leaf::Null));
        assert_eq!(get("/t~0"), Some(Leaf::Empty));
        assert_eq!(get("/l/1"), Some(Leaf::Str("q".into())));
    }

    #[test]
    fn limits_enforced() {
        let many: Vec<u32> = (0..(MAX_LEAVES as u32 + 1)).collect();
        assert!(flatten(&json!({ "a": many })).is_err());
        let mut deep = json!(1);
        for _ in 0..(MAX_DEPTH + 2) {
            deep = json!({ "d": deep });
        }
        assert!(flatten(&deep).is_err());
    }
}
