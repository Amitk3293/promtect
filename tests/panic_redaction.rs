// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Subprocess regression for value-free detector panic handling.

use std::process::{Command, Stdio};
use std::sync::Arc;

const CHILD_ENV: &str = "PROMTECT_PANIC_REDACTION_CHILD";
const AUDIT_ENV: &str = "PROMTECT_PANIC_REDACTION_AUDIT";
const CANARY: &str = "synthetic-promtect-panic-canary-94d5a831";

async fn exercise_panicking_detector(audit_path: &std::path::Path) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind panic-regression proxy");
    let addr = listener.local_addr().expect("read proxy address");
    let audit = Arc::new(promtect::audit::Audit::to_file(audit_path));
    let ctx = promtect::proxy::Ctx {
        upstream: "http://127.0.0.1:9".to_owned(),
        audit: Arc::clone(&audit),
        client: reqwest::Client::new(),
        max_body_bytes: promtect::proxy::DEFAULT_MAX_BODY_BYTES,
        restore: true,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: Some(Arc::new(|candidate: &str| panic!("{candidate}"))),
        output_scan: None,
    };
    let server = tokio::spawn(async move {
        axum::serve(listener, promtect::proxy::app(ctx))
            .await
            .expect("serve panic-regression proxy");
    });

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/messages"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"prompt":"{CANARY}"}}"#))
        .send()
        .await
        .expect("send request through panic-regression proxy");
    let status = response.status();
    let body = response.text().await.expect("read fail-closed response");
    server.abort();
    let _ = server.await;
    drop(audit);

    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "promtect: request scanning failed");
    assert!(
        !body.contains(CANARY),
        "client response exposed panic canary"
    );

    let audit = std::fs::read_to_string(audit_path).expect("read panic-regression audit");
    assert!(audit.contains(r#""blocked":true"#));
    assert!(audit.contains(r#""action":"request_blocked""#));
    assert!(audit.contains(r#""detector":"scan_failure""#));
    assert!(!audit.contains(CANARY), "audit exposed panic canary");

    println!("panic-runtime-ok status={status} body={body}");
}

#[test]
fn detector_panic_is_absent_from_stderr_audit_and_client() {
    if std::env::var_os(CHILD_ENV).is_some() {
        promtect::install_value_free_panic_hook();
        let audit_path = std::env::var_os(AUDIT_ENV).expect("child audit path");
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build child runtime")
            .block_on(exercise_panicking_detector(std::path::Path::new(
                &audit_path,
            )));
        return;
    }

    let audit_path = std::env::temp_dir().join(format!(
        "promtect-panic-redaction-{}-{}.jsonl",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let output = Command::new(std::env::current_exe().expect("locate integration test binary"))
        .arg("--exact")
        .arg("detector_panic_is_absent_from_stderr_audit_and_client")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .env(AUDIT_ENV, &audit_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run panic-regression subprocess");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    std::fs::remove_file(&audit_path).ok();
    let mut lock_path = audit_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    std::fs::remove_file(std::path::PathBuf::from(lock_path)).ok();

    assert!(
        output.status.success(),
        "panic-regression subprocess failed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stdout.contains("panic-runtime-ok"));
    assert!(stderr.contains("promtect: internal task panicked; request failed closed"));
    assert!(stderr.contains("promtect: request scanning task failed"));
    assert!(!stdout.contains(CANARY), "stdout exposed panic canary");
    assert!(!stderr.contains(CANARY), "stderr exposed panic canary");
    assert!(!audit.contains(CANARY), "audit exposed panic canary");
}
