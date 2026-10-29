//! The `attn` binary: keygen, mint, delegate, inspect, proof.

use std::path::PathBuf;
use std::process::Command;

fn attn(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_attn"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

fn tmpdir() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom(&mut b);
    let d = std::env::temp_dir().join(format!("attn-cli-{}", hex(&b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn getrandom(b: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        ^ (std::process::id() as u128);
    for (i, x) in b.iter_mut().enumerate() {
        *x = (n >> (i * 8)) as u8;
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn keygen_mint_delegate_inspect() {
    let d = tmpdir();
    let p = |n: &str| d.join(n).to_string_lossy().to_string();
    let (ok, _root_jkt, e) = attn(&["keygen", "--out", &p("root.key.json")]);
    assert!(ok, "{e}");
    let (ok, a_jkt, _) = attn(&["keygen", "--out", &p("a.key.json")]);
    assert!(ok);
    let (ok, b_jkt, _) = attn(&["keygen", "--out", &p("b.key.json")]);
    assert!(ok);
    assert_eq!(a_jkt.len(), 43, "base64url SHA-256 thumbprint");
    // keygen refuses to overwrite an existing key.
    assert!(!attn(&["keygen", "--out", &p("a.key.json")]).0);

    let (ok, root_pub, _) = attn(&["pub", "--key", &p("root.key.json")]);
    assert!(ok);
    std::fs::write(p("root.pub"), &root_pub).unwrap();

    let (ok, tok, e) = attn(&[
        "mint",
        "--root",
        &p("root.key.json"),
        "--holder",
        &a_jkt,
        "--audience",
        "mcp://cli",
        "--tool",
        "repo.push",
        "--tool",
        "echo",
        "--ttl",
        "600",
    ]);
    assert!(ok, "{e}");
    std::fs::write(p("root.tok"), &tok).unwrap();

    let tok_arg = format!("@{}", p("root.tok"));
    let (ok, del, e) = attn(&[
        "delegate",
        "--root-pub",
        &p("root.pub"),
        "--token",
        &tok_arg,
        "--holder-key",
        &p("a.key.json"),
        "--to",
        &b_jkt,
        "--tool",
        "repo.push",
        "--arg",
        "/repo=acme/site",
        "--only-args",
        "/repo,/branch",
        "--lock",
        &b_jkt,
        "--ttl",
        "120",
    ]);
    assert!(ok, "{e}");
    std::fs::write(p("b.tok"), &del).unwrap();

    let (ok, out, e) = attn(&[
        "inspect",
        "--root-pub",
        &p("root.pub"),
        "--token",
        &format!("@{}", p("b.tok")),
    ]);
    assert!(ok, "{e}");
    assert!(
        out.contains(&format!("holder chain: {a_jkt} -> {b_jkt}")),
        "{out}"
    );
    assert!(out.contains("acme/site"), "{out}");

    // Delegating with a key that is not the current holder produces a token
    // whose chain is invalid.
    let (ok, bad, _) = attn(&[
        "delegate",
        "--root-pub",
        &p("root.pub"),
        "--token",
        &tok_arg,
        "--holder-key",
        &p("b.key.json"),
        "--to",
        &b_jkt,
    ]);
    assert!(ok);
    std::fs::write(p("bad.tok"), &bad).unwrap();
    let (_, out, _) = attn(&[
        "inspect",
        "--root-pub",
        &p("root.pub"),
        "--token",
        &format!("@{}", p("bad.tok")),
    ]);
    assert!(out.contains("holder chain INVALID"), "{out}");

    std::fs::write(
        p("body.json"),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .unwrap();
    let (ok, proof, e) = attn(&[
        "proof",
        "--key",
        &p("b.key.json"),
        "--token",
        &format!("@{}", p("b.tok")),
        "--url",
        "http://127.0.0.1:8808/mcp",
        "--body",
        &p("body.json"),
    ]);
    assert!(ok, "{e}");
    assert_eq!(proof.split('.').count(), 3);

    // A token signed by another root does not parse with this root key.
    let (_, other_pub, _) = attn(&["pub", "--key", &p("a.key.json")]);
    std::fs::write(p("other.pub"), other_pub).unwrap();
    assert!(
        !attn(&[
            "inspect",
            "--root-pub",
            &p("other.pub"),
            "--token",
            &tok_arg
        ])
        .0
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn suite_command_exits_zero() {
    let (ok, out, e) = attn(&["suite"]);
    assert!(ok, "{out}\n{e}");
    assert!(out.contains("attacks rejected: 34/34"), "{out}");
}
