//! Where verification time goes for the 3-level token (median and p99, µs):
//! `cargo run --release --example breakdown`.

use attenuable_mcp::{b64, dpop, suite, token};
use std::time::Instant;

fn stats(mut v: Vec<f64>) -> String {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    format!(
        "p50={:.1}us p99={:.1}us",
        v[v.len() / 2],
        v[v.len() * 99 / 100]
    )
}

fn time(n: usize, mut f: impl FnMut(usize)) -> String {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let t = Instant::now();
        f(i);
        v.push(t.elapsed().as_secs_f64() * 1e6);
    }
    stats(v)
}

fn main() {
    let n = 5000;
    let w = suite::World::new();
    let root = token::biscuit_public(&w.root).unwrap();
    let tok = w.three_levels.to_base64().unwrap();
    println!(
        "biscuit parse + signature chain: {}",
        time(n, |_| {
            std::hint::black_box(biscuit_auth::Biscuit::from_base64(&tok, root).unwrap());
        })
    );
    let b = biscuit_auth::Biscuit::from_base64(&tok, root).unwrap();
    println!(
        "holder chain:                    {}",
        time(n, |_| {
            std::hint::black_box(token::holder_chain(&b).unwrap());
        })
    );
    let body = suite::call_body(
        "repo.push",
        serde_json::json!({"repo":"acme/site","branch":"feature/x"}),
    );
    let proofs: Vec<String> = (0..n)
        .map(|_| {
            dpop::create(
                &w.b,
                &dpop::ProofClaims {
                    htm: "POST",
                    htu: suite::URL,
                    iat: suite::NOW,
                    access_token: &tok,
                    body: Some(&body),
                    jti: None,
                },
            )
        })
        .collect();
    let expect = dpop::Expect {
        htm: "POST",
        htu: suite::URL,
        access_token: &tok,
        body: &body,
        now: suite::NOW,
        max_age: 60,
        max_skew: 5,
        require_rbh: true,
    };
    println!(
        "DPoP proof verify:               {}",
        time(n, |i| {
            std::hint::black_box(dpop::verify(&proofs[i], &expect).unwrap());
        })
    );
    println!(
        "sha256(token) (cache key):       {}",
        time(n, |_| {
            std::hint::black_box(b64::sha256(tok.as_bytes()));
        })
    );
}
