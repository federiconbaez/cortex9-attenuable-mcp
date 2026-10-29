//! `attn`: keys, tokens, proofs, the authenticated MCP server, the attack
//! suite and the benchmark.

use attenuable_mcp::middleware::{AuthenticatedMcp, demo_server};
use attenuable_mcp::token::{self, ArgValue, Attenuation, Grant};
use attenuable_mcp::verifier::{Config, Verifier};
use attenuable_mcp::{bench, dpop, jwk, suite};
use biscuit_auth::Biscuit;
use mcp_server::transport::http::HttpConfig;
use serde_json::Value;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

const USAGE: &str = "\
attn: attenuable capability tokens for MCP tools/call (Biscuit + DPoP)

USAGE:
  attn keygen --out FILE                         write an Ed25519 private JWK, print its jkt
  attn jkt --key FILE                            print the RFC 7638 thumbprint of a key
  attn mint --root FILE --holder JKT --audience AUD --tool NAME... [--ttl SECS]
  attn pub --key FILE                            print the hex public key (server --root-pub file)
  attn attenuate --root-pub FILE --token TOKEN [RESTRICTIONS]
                                                 offline attenuation (same holder)
  attn delegate --root-pub FILE --token TOKEN --holder-key FILE --to JKT [RESTRICTIONS]
  attn proof --key FILE --token TOKEN --url URL --body FILE [--method POST]
  attn inspect --root-pub FILE --token TOKEN                    print blocks and the holder chain
  attn serve --root-pub FILE --audience AUD --url URL [--bind ADDR]
  attn suite [--json]                            confused-deputy suite; exit 1 unless 100%
  attn bench [--iters N] [--warmup N]            verification latency and token sizes

RESTRICTIONS:
  --tool NAME            allow only these tools (repeatable)
  --arg PTR=STRING       require string argument (JSON Pointer) to equal value
  --arg-int PTR=N        require integer argument
  --arg-bool PTR=true    require boolean argument
  --arg-prefix PTR=PRE   require string argument prefix
  --only-args PTR,PTR    no other argument leaves allowed
  --tools-call-only      refuse every other MCP method
  --ttl SECS             expire SECS from now
  --lock JKT             usable only with this DPoP key (forbids re-delegation)
  --max-hops N           maximum holder changes in the chain

TOKEN arguments accept a literal base64 token or @FILE.
";

fn args_get<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn args_all<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].as_str())
        .collect()
}

fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn need<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    args_get(args, flag).ok_or_else(|| format!("missing {flag}"))
}

fn read_value(v: &str) -> Result<String, String> {
    match v.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("{path}: {e}")),
        None => Ok(v.to_string()),
    }
}

fn load_key(path: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    jwk::parse_private_jwk(&v)
}

fn now() -> u64 {
    attenuable_mcp::middleware::unix_now()
}

fn split_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected PTR=VALUE, got {s:?}"))
}

fn restrictions(args: &[String]) -> Result<Attenuation, String> {
    let mut a = Attenuation {
        tools: args_all(args, "--tool")
            .into_iter()
            .map(String::from)
            .collect(),
        tools_call_only: has(args, "--tools-call-only"),
        ..Default::default()
    };
    for s in args_all(args, "--arg") {
        let (k, v) = split_kv(s)?;
        a.arg_eq.push((k, ArgValue::Str(v)));
    }
    for s in args_all(args, "--arg-int") {
        let (k, v) = split_kv(s)?;
        a.arg_eq.push((
            k,
            ArgValue::Int(v.parse().map_err(|_| format!("bad integer {v}"))?),
        ));
    }
    for s in args_all(args, "--arg-bool") {
        let (k, v) = split_kv(s)?;
        a.arg_eq.push((
            k,
            ArgValue::Bool(v.parse().map_err(|_| format!("bad bool {v}"))?),
        ));
    }
    for s in args_all(args, "--arg-prefix") {
        a.arg_prefix.push(split_kv(s)?);
    }
    if let Some(list) = args_get(args, "--only-args") {
        a.only_args = Some(
            list.split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        );
    }
    if let Some(ttl) = args_get(args, "--ttl") {
        a.expires_at = Some(now() + ttl.parse::<u64>().map_err(|_| "bad --ttl")?);
    }
    a.lock_holder = args_get(args, "--lock").map(String::from);
    if let Some(n) = args_get(args, "--max-hops") {
        a.max_holder_changes = Some(n.parse().map_err(|_| "bad --max-hops")?);
    }
    Ok(a)
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let rest = &args[1.min(args.len())..];
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let out = need(rest, "--out")?;
            let sk = jwk::generate();
            let text = serde_json::to_string_pretty(&jwk::private_jwk(&sk)).unwrap();
            write_private(out, &text)?;
            println!("{}", jwk::thumbprint(&sk.verifying_key()));
        }
        Some("jkt") => {
            let sk = load_key(need(rest, "--key")?)?;
            println!("{}", jwk::thumbprint(&sk.verifying_key()));
        }
        Some("pub") => {
            let sk = load_key(need(rest, "--key")?)?;
            println!("{}", hex::encode(sk.verifying_key().as_bytes()));
        }
        Some("mint") => {
            let root = load_key(need(rest, "--root")?)?;
            let ttl = args_get(rest, "--ttl")
                .map(|t| t.parse::<u64>())
                .transpose()
                .map_err(|_| "bad --ttl")?;
            let g = Grant {
                holder_jkt: need(rest, "--holder")?.to_string(),
                audience: need(rest, "--audience")?.to_string(),
                tools: args_all(rest, "--tool")
                    .into_iter()
                    .map(String::from)
                    .collect(),
                expires_at: ttl.map(|t| now() + t),
            };
            let t = token::mint(&root, &g).map_err(|e| e.0)?;
            println!("{}", t.to_base64().map_err(|e| e.to_string())?);
        }
        Some("attenuate") => {
            let t = parse_token(rest)?;
            let out = token::attenuate(&t, &restrictions(rest)?).map_err(|e| e.0)?;
            println!("{}", out.to_base64().map_err(|e| e.to_string())?);
        }
        Some("delegate") => {
            let t = parse_token(rest)?;
            let holder = load_key(need(rest, "--holder-key")?)?;
            let out = token::delegate(&t, &holder, need(rest, "--to")?, &restrictions(rest)?)
                .map_err(|e| e.0)?;
            println!("{}", out.to_base64().map_err(|e| e.to_string())?);
        }
        Some("proof") => {
            let key = load_key(need(rest, "--key")?)?;
            let tok = read_value(need(rest, "--token")?)?;
            let body_path = need(rest, "--body")?;
            let body = std::fs::read(body_path).map_err(|e| format!("{body_path}: {e}"))?;
            let p = dpop::create(
                &key,
                &dpop::ProofClaims {
                    htm: args_get(rest, "--method").unwrap_or("POST"),
                    htu: need(rest, "--url")?,
                    iat: now(),
                    access_token: &tok,
                    body: Some(&body),
                    jti: None,
                },
            );
            println!("{p}");
        }
        Some("inspect") => {
            let t = parse_token(rest)?;
            println!("{}", t.print());
            match token::holder_chain(&t) {
                Ok(c) => println!("holder chain: {}", c.holders.join(" -> ")),
                Err(e) => println!("holder chain INVALID: {}", e.0),
            }
            println!("bytes: {}", t.to_vec().map_err(|e| e.to_string())?.len());
        }
        Some("serve") => {
            let root = load_root(need(rest, "--root-pub")?)?;
            let cfg = Config::new(root, need(rest, "--audience")?, need(rest, "--url")?);
            let bind = args_get(rest, "--bind").unwrap_or("127.0.0.1:8808");
            let http = tiny_http::Server::http(bind).map_err(|e| e.to_string())?;
            let app = AuthenticatedMcp::new(
                Verifier::new(cfg),
                demo_server(Arc::new(Mutex::new(Vec::new()))),
                HttpConfig::default(),
            );
            eprintln!("attn: authenticated MCP endpoint on http://{bind}/mcp");
            Arc::new(app).serve(Arc::new(http), 4);
        }
        Some("suite") => {
            let w = suite::World::new();
            let out = suite::run(&w);
            let s = suite::summary(&out);
            if has(rest, "--json") {
                println!("{}", serde_json::to_string_pretty(&s).unwrap());
            } else {
                for o in &out {
                    println!(
                        "{:4} {:13} {:6} status={} {}",
                        o.id,
                        o.class,
                        if o.pass { "PASS" } else { "FAIL" },
                        o.status,
                        o.detail.chars().take(110).collect::<String>()
                    );
                }
                println!(
                    "attacks rejected: {}/{}  controls executed: {}/{}",
                    s["attacks_rejected"],
                    s["attacks_total"],
                    s["controls_allowed"],
                    s["controls_total"]
                );
            }
            if s["criterion_met"] != true {
                return Ok(ExitCode::FAILURE);
            }
        }
        Some("bench") => {
            let iters = args_get(rest, "--iters")
                .unwrap_or("20000")
                .parse()
                .map_err(|_| "bad --iters")?;
            let warmup = args_get(rest, "--warmup")
                .unwrap_or("2000")
                .parse()
                .map_err(|_| "bad --warmup")?;
            let r = bench::run(iters, warmup);
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        Some("-h" | "--help" | "help") | None => {
            print!("{USAGE}");
        }
        Some(other) => return Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
    Ok(ExitCode::SUCCESS)
}

fn load_root(path: &str) -> Result<biscuit_auth::PublicKey, String> {
    let hex = read_value(&format!("@{path}"))?;
    biscuit_auth::PublicKey::from_bytes_hex(&hex, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| e.to_string())
}

/// Parse and verify a token against the root public key (`--root-pub`).
fn parse_token(rest: &[String]) -> Result<Biscuit, String> {
    let root = load_root(need(rest, "--root-pub")?)?;
    let s = read_value(need(rest, "--token")?)?;
    Biscuit::from_base64(&s, root).map_err(|e| format!("token: {e}"))
}

#[cfg(unix)]
fn write_private(path: &str, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn write_private(path: &str, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args.first().map(String::as_str) == Some(mcp_server::sandbox::WORKER_ARG) {
        let job = args.get(1).map(String::as_str).unwrap_or("");
        return ExitCode::from(mcp_server::sandbox::worker_main(job) as u8);
    }
    match run(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("attn: error: {e}");
            ExitCode::from(2)
        }
    }
}
