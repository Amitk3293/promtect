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
    spawn_dashboard_with_restore(audit_path, true).await
}

async fn spawn_dashboard_with_restore(
    audit_path: std::path::PathBuf,
    restore_enabled: bool,
) -> String {
    let ctx = DashCtx {
        audit_path: Arc::new(audit_path),
        restore_enabled,
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

/// A real audit read failure must make both metrics endpoints unavailable. A
/// directory can be opened as a file descriptor on supported CI platforms, but
/// attempting to read it fails, exercising the production I/O path rather than
/// a synthetic panic.
#[tokio::test]
async fn audit_read_failure_returns_503_without_false_zero_metrics() {
    let audit_directory = std::env::temp_dir().join(format!(
        "promtect-dashboard-read-error-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&audit_directory).expect("create unreadable audit fixture");
    let base = spawn_dashboard(audit_directory.clone()).await;

    let api = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET failed /api/metrics");
    assert_eq!(api.status(), 503);
    let api_body = api.text().await.expect("read failed API response");
    assert!(api_body.contains("metrics temporarily unavailable"));
    assert!(!api_body.contains("requests_total"));

    let prometheus = reqwest::get(format!("{base}/metrics"))
        .await
        .expect("GET failed /metrics");
    assert_eq!(prometheus.status(), 503);
    let prometheus_body = prometheus
        .text()
        .await
        .expect("read failed Prometheus response");
    assert!(prometheus_body.contains("metrics temporarily unavailable"));
    assert!(!prometheus_body.contains("promtect_requests_total"));

    std::fs::remove_dir(&audit_directory).ok();
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
    assert!(body.contains("m.restore_enabled === true"));
    assert!(body.contains("Secrets masked"));
    assert!(!body.contains("Secrets blocked"));

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

#[tokio::test]
async fn api_metrics_reports_strict_restore_mode_truthfully() {
    let audit_path = write_fixture_audit();
    let base = spawn_dashboard_with_restore(audit_path.clone(), false).await;

    let body = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET strict-mode metrics")
        .text()
        .await
        .expect("read strict-mode metrics");
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse strict-mode metrics");
    std::fs::remove_file(&audit_path).ok();

    assert_eq!(json["restore_enabled"].as_bool(), Some(false));
}

#[tokio::test]
async fn api_metrics_skips_oversized_records_and_keeps_recent_lifecycle() {
    let audit_path = std::env::temp_dir().join(format!(
        "promtect-dashboard-bounded-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let mut f = std::io::BufWriter::new(
        std::fs::File::create(&audit_path).expect("create bounded dashboard audit"),
    );

    for i in 0u64..100 {
        writeln!(
            f,
            r#"{{"ts_ms":{i},"action":"request","request_id":"req-{i}","masked":1,"detectors":["aws_key"],"bytes_in":1,"bytes_out":1}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"action":"unmask","request_id":"req-{i}"}}"#).unwrap();
        writeln!(
            f,
            r#"{{"action":"stream_interrupted","request_id":"req-{i}"}}"#
        )
        .unwrap();
    }
    let oversized = serde_json::json!({
        "ts_ms": 1_000,
        "action": "request",
        "request_id": "must-be-skipped",
        "masked": 0,
        "detectors": [],
        "bytes_in": 1,
        "bytes_out": 1,
        "padding": "x".repeat(64 * 1024),
    });
    writeln!(f, "{oversized}").unwrap();
    f.flush().unwrap();
    drop(f);

    let base = spawn_dashboard(audit_path.clone()).await;
    let response = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET bounded metrics");
    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("read bounded metrics");
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse bounded metrics");
    std::fs::remove_file(&audit_path).ok();

    assert_eq!(json["requests_total"].as_u64(), Some(100));
    let recent = json["recent"].as_array().expect("recent array");
    assert_eq!(recent.len(), 20);
    assert_eq!(recent[0]["request_id"].as_str(), Some("req-99"));
    assert_eq!(recent[19]["request_id"].as_str(), Some("req-80"));
    assert_eq!(recent[0]["restored"].as_u64(), Some(1));
    assert_eq!(recent[0]["failures"].as_u64(), Some(1));
    assert_eq!(recent[0]["interrupted"].as_bool(), Some(true));
}

#[tokio::test]
#[cfg(unix)]
async fn scan_failure_returns_503_and_recovers_when_path_becomes_readable() {
    let audit_path = std::env::temp_dir().join(format!(
        "promtect-dashboard-scan-failure-{}",
        uuid::Uuid::new_v4()
    ));
    let listener =
        std::os::unix::net::UnixListener::bind(&audit_path).expect("create non-file audit path");
    let base = spawn_dashboard(audit_path.clone()).await;

    let api_failure = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET failed JSON aggregation");
    assert_eq!(api_failure.status(), 503);
    let api_body = api_failure.text().await.expect("read failed JSON body");
    assert!(api_body.contains("metrics temporarily unavailable"));
    assert!(!api_body.contains("requests_total"));
    assert!(!api_body.contains("requests_clean"));

    let prometheus_failure = reqwest::get(format!("{base}/metrics"))
        .await
        .expect("GET failed Prometheus aggregation");
    assert_eq!(prometheus_failure.status(), 503);
    let prometheus_body = prometheus_failure
        .text()
        .await
        .expect("read failed Prometheus body");
    assert!(prometheus_body.contains("metrics temporarily unavailable"));
    assert!(!prometheus_body.contains("promtect_requests_total"));

    drop(listener);
    std::fs::remove_file(&audit_path).expect("remove socket audit path");
    let mut f = std::fs::File::create(&audit_path).expect("create recovered audit file");
    writeln!(
        f,
        r#"{{"ts_ms":1,"action":"request","request_id":"recovered","masked":1,"detectors":["aws_key"],"bytes_in":1,"bytes_out":1}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"ts_ms":1,"action":"mask","detector":"aws_key","request_id":"recovered"}}"#
    )
    .unwrap();
    drop(f);

    let recovered = reqwest::get(format!("{base}/api/metrics"))
        .await
        .expect("GET recovered aggregation");
    assert_eq!(recovered.status(), 200);
    let recovered_body = recovered.text().await.expect("read recovered body");
    let json: serde_json::Value =
        serde_json::from_str(&recovered_body).expect("parse recovered metrics");
    assert_eq!(json["requests_total"].as_u64(), Some(1));
    assert_eq!(json["secrets_masked_total"].as_u64(), Some(1));

    std::fs::remove_file(&audit_path).ok();
}
