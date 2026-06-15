//! `PROMTECT_BLOCK_RISKY` end-to-end: the binary must refuse a high-risk upstream
//! before binding (so this exits fast, no hang), and must NOT mask the refusal away.

use std::process::Command;

#[test]
fn refuses_high_risk_upstream_when_blocking() {
    let out = Command::new(env!("CARGO_BIN_EXE_promtect"))
        .env("PROMTECT_UPSTREAM", "https://api.deepseek.com")
        .env("PROMTECT_BLOCK_RISKY", "1")
        .env("PROMTECT_PORT", "18799")
        .output()
        .expect("run promtect");

    assert!(
        !out.status.success(),
        "expected non-zero exit when refusing a high-risk upstream"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("high-risk"),
        "expected a clear refusal on stderr, got: {stderr}"
    );
}
