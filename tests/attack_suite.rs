//! Measurement (a): every attack refused and never executed, every control
//! executed.

use attenuable_mcp::suite;

#[test]
fn attack_suite_rejects_all_attacks_and_allows_all_controls() {
    let w = suite::World::new();
    let out = suite::run(&w);
    for o in &out {
        println!(
            "{:4} {:13} expect_allow={:5} status={} pass={} {}",
            o.id, o.class, o.expect_allow, o.status, o.pass, o.detail
        );
    }
    let failed: Vec<_> = out.iter().filter(|o| !o.pass).map(|o| o.id).collect();
    assert!(failed.is_empty(), "failed cases: {failed:?}");
    let s = suite::summary(&out);
    assert_eq!(s["criterion_met"], true);
    assert!(s["attacks_total"].as_u64().unwrap() >= 30);
}

#[test]
fn token_cache_does_not_skip_time_or_holder_checks() {
    use attenuable_mcp::suite::{NOW, World, call};
    use serde_json::json;
    let w = World::new();
    let (app, log) = w.app();
    let args = json!({"repo":"acme/site","branch":"feature/a"});
    let r = call(&w.delegated, &w.b, "repo.push", args.clone());
    assert_eq!(
        app.handle_at("POST", "/mcp", &r.headers, &r.body, r.now)
            .status,
        200
    );
    // Same token string, now cached: after expiry it is refused.
    let mut late = call(&w.delegated, &w.b, "repo.push", args.clone());
    late.now = NOW + 601;
    // Fresh proof at the late time.
    let tok = w.delegated.to_base64().unwrap();
    let proof = attenuable_mcp::dpop::create(
        &w.b,
        &attenuable_mcp::dpop::ProofClaims {
            htm: "POST",
            htu: attenuable_mcp::suite::URL,
            iat: NOW + 601,
            access_token: &tok,
            body: Some(&late.body),
            jti: None,
        },
    );
    late.headers.retain(|(k, _)| k != "DPoP");
    late.headers.push(("DPoP".into(), proof));
    assert_eq!(
        app.handle_at("POST", "/mcp", &late.headers, &late.body, late.now)
            .status,
        403
    );
    // Same cached token with the attacker's key: still refused.
    let r = call(&w.delegated, &w.c, "repo.push", args);
    assert_eq!(
        app.handle_at("POST", "/mcp", &r.headers, &r.body, r.now)
            .status,
        401
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}
