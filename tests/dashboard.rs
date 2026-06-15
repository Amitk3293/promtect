//! Integration tests for the dashboard HTTP server (`src/dashboard.rs`).
//!
//! Strategy: write a synthetic audit JSONL to a temp file, bind the dashboard
//! router on an ephemeral OS-assigned port (127.0.0.1:0), serve it in a
//! background tokio task, then exercise all three endpoints via reqwest.
//!
//! Each `#[tokio::test]` is independent: it creates its own temp file and
//! ephemeral listener so the tests can run in parallel without port conflicts.

use std::io::Write as _;
use std::sync::Arc;

use promtect::dashboard::{DashCtx, app};

// ── helpers ─────────────────────────────────────────────────────────────────

/// Write a minimal two-event audit JSONL (one `request` + one `mask`) to a
/// temp file and return the path. The fixture is intentionally value-free:
/// the mask event only records the detector name and a placeholder sentinel,
/// never the actual secret.
fn write_fixture_audit() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "promtect-dashboard-test-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let mut f = std::fs::File::create(&path).expect("create temp audit file");

    // A request that had one secret masked by the "aws_key" detector.
    writeln!(
        f,
        r#"{{"ts_ms":1000,"action":"request","request_id":"req-1","masked":1,"detectors":["aws_key"],"bytes_in":200,"bytes_out":210}}"#
    )
    .unwrap();

    // The corresponding mask event that drove the counter.
    writeln!(
        f,
        r#"{{"ts_ms":1000,"action":"mask","detector":"aws_key","placeholder":"«promtect:aws_key:0001»","request_id":"req-1"}}"#
    )
    .unwrap();

    // A clean request with no secrets.
    writeln!(
        f,
        r#"{{"ts_ms":2000,"action":"request","request_id":"req-2","masked":0,"detectors":[],"bytes_in":50,"bytes_out":50}}"#
    )
    .unwrap();

    path
}

/// Bind the dashboard app on an ephemeral port and return the base URL.
///
/// The server runs in a detached tokio task for the duration of the test.
/// Because tests use ephemeral ports there is no teardown step — the OS
/// reclaims the port once the test process exits.
async fn spawn_dashboard(audit_path: std::path::PathBuf) -> String {
    let ctx = DashCtx {
        audit_path: Arc::new(audit_path),
    };
    let router = app(ctx);

    // Port 0 asks the OS to choose a free ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("get local addr");

    // Serve in a background task; we never await the handle so the server
    // keeps running while the test exercises its endpoints.
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("dashboard server error");
    });

    format!("http://{addr}")
}

// ── tests ────────────────────────────────────────────────────────────────────

/// `GET /api/metrics` must return HTTP 200 with valid JSON containing the
/// headline counter fields and the per-detector breakdown from the fixture.
#[tokio::test]
async fn api_metrics_returns_200_with_correct_json() {
    let audit_path = write_fixture_audit();
    let base = spawn_dashboard(audit_path.clone()).await;

    let resp = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET /api/metrics");

    // Verify the HTTP status before attempting to parse the body.
    assert_eq!(resp.status(), 200, "/api/metrics must return 200 OK");

    // reqwest is built without the `json` feature (only `rustls` + `stream`);
    // deserialize via the text body to avoid adding a dependency we don't need.
    let body = resp.text().await.expect("read /api/metrics body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON body");

    // The fixture has 2 request events total.
    assert_eq!(
        json["requests_total"].as_u64(),
        Some(2),
        "requests_total must be 2 (one dirty + one clean)"
    );

    // Only one of the two requests contained a masked secret.
    assert_eq!(
        json["requests_with_secrets"].as_u64(),
        Some(1),
        "requests_with_secrets must be 1"
    );

    // The fixture contains exactly one mask event for aws_key.
    assert_eq!(
        json["by_detector"]["aws_key"].as_u64(),
        Some(1),
        "by_detector.aws_key must be 1"
    );

    // secrets_masked_total is driven by mask events, not the request-level field.
    assert_eq!(
        json["secrets_masked_total"].as_u64(),
        Some(1),
        "secrets_masked_total must equal the number of mask events"
    );

    std::fs::remove_file(&audit_path).ok();
}

/// `GET /metrics` must return HTTP 200 with the Prometheus `Content-Type` and a
/// body that contains the required metric names and a labelled detector line.
#[tokio::test]
async fn prometheus_endpoint_returns_200_with_correct_body() {
    let audit_path = write_fixture_audit();
    let base = spawn_dashboard(audit_path.clone()).await;

    let resp = reqwest::get(format!("{base}/metrics"))
        .await
        .expect("GET /metrics");

    // Prometheus scrapers check the status code before parsing.
    assert_eq!(resp.status(), 200, "/metrics must return 200 OK");

    // The content-type must match Prometheus text-format version 0.0.4 exactly.
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/plain") && ct.contains("0.0.4"),
        "Content-Type must be text/plain; version=0.0.4, got: {ct}"
    );

    let body = resp.text().await.expect("read /metrics body");

    // The global request counter must be present with the right value.
    assert!(
        body.contains("promtect_requests_total 2"),
        "expected 'promtect_requests_total 2' in Prometheus body:\n{body}"
    );

    // The labelled per-detector counter line must follow Prometheus label syntax.
    assert!(
        body.contains(r#"promtect_secrets_masked_total{detector="aws_key"} 1"#),
        "expected labelled aws_key counter in Prometheus body:\n{body}"
    );

    std::fs::remove_file(&audit_path).ok();
}

/// `GET /` must return HTTP 200 with an HTML body that contains the string
/// "Promtect" — the minimal sanity check that the embedded HTML file is served.
#[tokio::test]
async fn index_endpoint_returns_200_with_html_page() {
    let audit_path = write_fixture_audit();
    let base = spawn_dashboard(audit_path.clone()).await;

    let resp = reqwest::get(format!("{base}/")).await.expect("GET /");

    // Any non-200 here indicates the embedded HTML is missing at compile time.
    assert_eq!(resp.status(), 200, "/ must return 200 OK");

    let body = resp.text().await.expect("read / body");

    // The page title and heading both include "Promtect" — presence confirms the
    // correct file is being served rather than an error page.
    assert!(
        body.contains("Promtect"),
        "dashboard HTML must contain 'Promtect', got:\n{body}"
    );

    // The page must reference the /api/metrics endpoint so the JS can fetch data.
    assert!(
        body.contains("/api/metrics"),
        "dashboard HTML must reference /api/metrics for client-side data fetching"
    );

    std::fs::remove_file(&audit_path).ok();
}

/// `GET /api/metrics` on a missing audit file must still return 200 with all
/// counters at zero — the dashboard must be usable before any requests arrive.
#[tokio::test]
async fn api_metrics_returns_zeros_when_audit_file_is_missing() {
    // Point to a path that definitely does not exist.
    let audit_path =
        std::env::temp_dir().join(format!("promtect-no-such-{}.jsonl", uuid::Uuid::new_v4()));
    let base = spawn_dashboard(audit_path).await;

    let resp = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET /api/metrics with missing file");

    assert_eq!(
        resp.status(),
        200,
        "must return 200 even with no audit file"
    );

    // reqwest is built without the `json` feature — parse via text body.
    let body = resp.text().await.expect("read body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON body");
    assert_eq!(
        json["requests_total"].as_u64(),
        Some(0),
        "requests_total must be 0 with no audit file"
    );
    assert_eq!(
        json["secrets_masked_total"].as_u64(),
        Some(0),
        "secrets_masked_total must be 0 with no audit file"
    );
}
