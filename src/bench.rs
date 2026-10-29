//! Measurement (b): per-request verification cost and token sizes.

use crate::dpop::{self, ProofClaims};
use crate::suite::{self, NOW, URL, World};
use biscuit_auth::Biscuit;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::time::Instant;

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[idx]
}

/// Latency statistics in microseconds.
pub fn stats(mut us: Vec<f64>) -> Value {
    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = us.iter().sum::<f64>() / us.len().max(1) as f64;
    json!({
        "n": us.len(),
        "mean_us": round2(mean),
        "p50_us": round2(percentile(&us, 0.50)),
        "p90_us": round2(percentile(&us, 0.90)),
        "p99_us": round2(percentile(&us, 0.99)),
        "p999_us": round2(percentile(&us, 0.999)),
        "max_us": round2(*us.last().unwrap_or(&f64::NAN)),
    })
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

struct Prepared {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn prepare(token: &Biscuit, key: &SigningKey, args: Value, n: usize) -> Vec<Prepared> {
    let tok = token.to_base64().unwrap();
    let body = suite::call_body("repo.push", args);
    (0..n)
        .map(|_| {
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
            let mut headers = suite::mcp_headers("tools/call", Some("repo.push"));
            headers.push(("Authorization".into(), format!("DPoP {tok}")));
            headers.push(("DPoP".into(), proof));
            Prepared {
                headers,
                body: body.clone(),
            }
        })
        .collect()
}

/// Time `Verifier::verify` (DPoP + Biscuit signatures + holder chain +
/// Datalog) for `iters` requests, after `warmup` untimed ones. Proofs are
/// pre-generated (client cost excluded), each with a unique jti.
pub fn verify_latency(
    root: biscuit_auth::PublicKey,
    token: &Biscuit,
    key: &SigningKey,
    args: Value,
    iters: usize,
    warmup: usize,
    cache: bool,
) -> Value {
    let reqs = prepare(token, key, args, iters + warmup);
    let verifier = crate::verifier::Verifier::new({
        let mut c = crate::verifier::Config::new(root, suite::AUD, URL);
        c.jti_capacity = iters + warmup + 1;
        c.token_cache = if cache { 1024 } else { 0 };
        c
    });
    let mut us = Vec::with_capacity(iters);
    for (i, r) in reqs.iter().enumerate() {
        let t = Instant::now();
        let res = verifier.verify("POST", &r.headers, &r.body, NOW);
        let dt = t.elapsed();
        assert!(res.is_ok(), "benchmark request refused: {res:?}");
        if i >= warmup {
            us.push(dt.as_secs_f64() * 1e6);
        }
    }
    stats(us)
}

/// Full benchmark report.
pub fn run(iters: usize, warmup: usize) -> Value {
    let w = World::new();
    let root = crate::token::biscuit_public(&w.root).unwrap();
    let push = json!({"repo":"acme/site","branch":"feature/x"});
    let level1 = w.delegated.clone();
    let size = |t: &Biscuit| {
        json!({"blocks": t.block_count(), "bytes": t.to_vec().unwrap().len(),
               "base64_bytes": t.to_base64().unwrap().len()})
    };
    // A two-level token: root -> A narrows -> delegate to B.
    let narrowed = crate::token::attenuate(
        &w.root_token,
        &crate::token::Attenuation {
            tools: vec!["echo".into(), "repo.push".into()],
            expires_at: Some(NOW + 1800),
            ..Default::default()
        },
    )
    .unwrap();
    let b_jkt = crate::jwk::thumbprint(&w.b.verifying_key());
    let level2 =
        crate::token::delegate(&narrowed, &w.a, &b_jkt, &suite::b_restrictions(&b_jkt)).unwrap();
    let proof_len = prepare(&w.three_levels, &w.b, push.clone(), 1)[0]
        .headers
        .iter()
        .find(|(k, _)| k == "DPoP")
        .map(|(_, v)| v.len())
        .unwrap_or(0);
    json!({
        "iters": iters,
        "warmup": warmup,
        "token_sizes": {
            "level0_root": size(&w.root_token),
            "level1_delegated": size(&level1),
            "level2": size(&level2),
            "level3": size(&w.three_levels),
        },
        "dpop_proof_bytes": proof_len,
        // Every request re-verifies the full Biscuit signature chain.
        "verify_latency_cold": {
            "level0_root": verify_latency(root, &w.root_token, &w.a, push.clone(), iters, warmup, false),
            "level1_delegated": verify_latency(root, &level1, &w.b, push.clone(), iters, warmup, false),
            "level3": verify_latency(root, &w.three_levels, &w.b, push.clone(), iters, warmup, false),
        },
        // Same token string seen before: signature chain reused; DPoP
        // signature, jti, and all Datalog checks still run per request.
        "verify_latency_cached_token": {
            "level0_root": verify_latency(root, &w.root_token, &w.a, push.clone(), iters, warmup, true),
            "level1_delegated": verify_latency(root, &level1, &w.b, push.clone(), iters, warmup, true),
            "level3": verify_latency(root, &w.three_levels, &w.b, push.clone(), iters, warmup, true),
        },
        "target_p99_us": 200,
    })
}
