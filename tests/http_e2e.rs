//! End to end over a real TCP socket: tiny_http listener, the
//! authorization layer, and mcp-server-rs dispatching the tool.

use attenuable_mcp::dpop::{self, ProofClaims};
use attenuable_mcp::middleware::{AuthenticatedMcp, demo_server, unix_now};
use attenuable_mcp::token::{self, ArgValue, Attenuation, Grant};
use attenuable_mcp::verifier::{Config, Verifier};
use attenuable_mcp::{jwk, suite};
use mcp_server::transport::http::HttpConfig;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

fn post(addr: &str, headers: &[(String, String)], body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split(' ').nth(1).unwrap().parse().unwrap();
    (status, out)
}

#[test]
fn real_socket_allows_attenuated_call_and_refuses_escalation() {
    let http = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let port = http.server_addr().to_ip().unwrap().port();
    let addr = format!("127.0.0.1:{port}");
    let url = format!("http://{addr}/mcp");

    let root = jwk::generate();
    let a = jwk::generate();
    let b = jwk::generate();
    let b_jkt = jwk::thumbprint(&b.verifying_key());
    let now = unix_now();
    let root_token = token::mint(
        &root,
        &Grant {
            holder_jkt: jwk::thumbprint(&a.verifying_key()),
            audience: "mcp://e2e".into(),
            tools: vec!["echo".into(), "repo.push".into()],
            expires_at: Some(now + 300),
        },
    )
    .unwrap();
    let delegated = token::delegate(
        &root_token,
        &a,
        &b_jkt,
        &Attenuation {
            tools: vec!["repo.push".into()],
            arg_eq: vec![("/repo".into(), ArgValue::Str("acme/site".into()))],
            only_args: Some(vec!["/repo".into(), "/branch".into()]),
            lock_holder: Some(b_jkt.clone()),
            expires_at: Some(now + 120),
            ..Default::default()
        },
    )
    .unwrap();

    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let app = Arc::new(AuthenticatedMcp::new(
        Verifier::new(Config::new(
            token::biscuit_public(&root).unwrap(),
            "mcp://e2e",
            &url,
        )),
        demo_server(log.clone()),
        HttpConfig::default(),
    ));
    {
        let app = app.clone();
        let http = http.clone();
        std::thread::spawn(move || app.serve(http, 2));
    }

    let tok = delegated.to_base64().unwrap();
    let send = |tool: &str, args: Value| {
        let body = suite::call_body(tool, args);
        let proof = dpop::create(
            &b,
            &ProofClaims {
                htm: "POST",
                htu: &url,
                iat: unix_now(),
                access_token: &tok,
                body: Some(&body),
                jti: None,
            },
        );
        let mut h = suite::mcp_headers("tools/call", Some(tool));
        h.push(("Authorization".into(), format!("DPoP {tok}")));
        h.push(("DPoP".into(), proof));
        post(&addr, &h, &body)
    };

    let (st, out) = send(
        "repo.push",
        json!({"repo":"acme/site","branch":"feature/a"}),
    );
    assert_eq!(st, 200, "{out}");
    assert!(out.contains("pushed"), "{out}");
    assert_eq!(log.lock().unwrap().len(), 1);

    let (st, out) = send(
        "repo.push",
        json!({"repo":"acme/other","branch":"feature/a"}),
    );
    assert_eq!(st, 403, "{out}");
    assert!(
        out.to_ascii_lowercase()
            .contains("www-authenticate: dpop error=\"insufficient_scope\""),
        "{out}"
    );
    let (st, _) = send("echo", json!({"text":"x"}));
    assert_eq!(st, 403);
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "refused calls must not reach the tool"
    );

    // No credentials at all.
    let body = suite::call_body("echo", json!({"text":"x"}));
    let (st, out) = post(
        &addr,
        &suite::mcp_headers("tools/call", Some("echo")),
        &body,
    );
    assert_eq!(st, 401, "{out}");
}
