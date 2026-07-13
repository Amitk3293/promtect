//! Integration tests for the Promtect proxy: header forwarding, multi-secret masking,
//! 502 on upstream error, sentinel deduplication, and response restore invariants.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, header::CONTENT_ENCODING},
    routing::post,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

// ── Shared mock-upstream state ────────────────────────────────────────────────

/// Records every request the mock upstream receives so tests can assert on it.
#[derive(Clone, Default)]
struct Seen {
    body: Arc<Mutex<String>>,
    headers: Arc<Mutex<HeaderMap>>,
    requests: Arc<AtomicU64>,
}

/// Echo handler: stores the received headers + body, returns `{"echo": <body>}`.
async fn mock(State(seen): State<Seen>, headers: HeaderMap, body: String) -> Json<Value> {
    seen.requests.fetch_add(1, Ordering::Relaxed);
    *seen.headers.lock().unwrap() = headers;
    *seen.body.lock().unwrap() = body.clone();
    Json(json!({ "echo": body }))
}

/// Leaky handler: returns a reply containing a secret the "model" produced, which
/// was never in the request. Used to exercise the response output scan.
async fn mock_leaky() -> Json<Value> {
    Json(json!({ "reply": "sure, your key is AKIA1234567890ABCDEF done" }))
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Bind `app` on a random loopback port, serve it in a background task, and
/// return the base URL (e.g. `"http://127.0.0.1:51234"`).
async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Build a fresh Promtect proxy `Ctx` pointing at `upstream_url`.
/// No vault field: the proxy mints a per-request vault internally.
fn ctx(upstream_url: &str) -> promtect::proxy::Ctx {
    promtect::proxy::Ctx {
        upstream: upstream_url.to_string(),
        audit: Arc::new(promtect::audit::Audit::null()),
        client: reqwest::Client::new(),
        max_body_bytes: promtect::proxy::DEFAULT_MAX_BODY_BYTES,
        restore: true,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: None,
        output_scan: None,
    }
}

/// Build a default mock upstream and return its base URL plus a `Seen` handle.
async fn spawn_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/", post(mock))
        .with_state(seen.clone());
    let url = spawn(app).await;
    (url, seen)
}

/// Start a raw HTTP receiver that counts accepted TCP sockets before returning a
/// minimal response. This distinguishes "no upstream request" from the stronger
/// security invariant "no upstream connection was opened".
async fn spawn_socket_counter() -> (String, Arc<AtomicU64>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicU64::new(0));
    let accepted = Arc::clone(&connections);

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });

    (format!("http://{addr}"), connections)
}

/// POST JSON body through Promtect; return the response body text.
async fn post_through(promtect_url: &str, body: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (status, text)
}

/// POST a body with an explicit request `Content-Encoding` through Promtect.
async fn post_with_encoding(
    promtect_url: &str,
    body: &str,
    encoding: &str,
) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .header("content-encoding", encoding)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (status, text)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Auth headers pass to the upstream byte-for-byte; only the body is ever masked.
#[tokio::test]
async fn auth_header_forwarded_untouched() {
    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let client = reqwest::Client::new();
    client
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .header("x-api-key", "sk-ant-api03-thisisafakeapikeyvalue00")
        .body(r#"{"role":"user","content":"hello"}"#)
        .send()
        .await
        .unwrap();

    let received = seen.headers.lock().unwrap();
    // The key must arrive unchanged (not masked, not stripped).
    assert_eq!(
        received.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some("sk-ant-api03-thisisafakeapikeyvalue00"),
        "x-api-key header must be forwarded verbatim"
    );
}

/// End-to-end output scan: a secret the model places in the RESPONSE (never in the
/// request) is flagged by the Pro response scan through the real proxy app —
/// recorded value-free in the audit log, with the response bytes left unchanged.
#[tokio::test]
async fn output_scan_flags_model_secret_in_live_response() {
    let audit_path =
        std::env::temp_dir().join(format!("promtect_outputscan_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_path);

    // Upstream returns a reply carrying a key that was never in the request.
    let upstream = spawn(axum::Router::new().route("/", axum::routing::post(mock_leaky))).await;

    // Proxy with a real audit file and an output scanner (the core detectors).
    let mut c = ctx(&upstream);
    c.audit = std::sync::Arc::new(promtect::audit::Audit::to_file(
        audit_path.to_string_lossy().into_owned(),
    ));
    c.output_scan = Some(std::sync::Arc::new(|t: &str| promtect::detect::detect(t)));
    let promtect_url = spawn(promtect::proxy::app(c)).await;

    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(r#"{"q":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();

    // Observe-only: the model's key reaches the client unchanged.
    assert!(
        body.contains("AKIA1234567890ABCDEF"),
        "output scan must not alter the response body: {body}"
    );

    // The scan recorded the model-generated key, value-free.
    let log = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        log.contains("output_secret") && log.contains("aws_key"),
        "audit must record an output_secret aws_key event, got: {log}"
    );
    assert!(
        !log.contains("AKIA1234567890ABCDEF"),
        "audit must be value-free, got: {log}"
    );
    let _ = std::fs::remove_file(&audit_path);
}

/// A downstream paid/rulebook detector participates in both masking and the
/// final residual check. If its first span is unusable, the second pass catches
/// the surviving canary and blocks before the upstream receives a request.
#[tokio::test]
async fn active_extra_detector_blocks_a_residual_before_upstream() {
    let (mock_url, seen) = spawn_mock().await;
    let mut c = ctx(&mock_url);
    let calls = Arc::new(AtomicU64::new(0));
    let calls_for_detector = Arc::clone(&calls);
    c.extra_detect = Some(Arc::new(move |text: &str| {
        let Some(start) = text.find("CUSTOMSECRET") else {
            return Vec::new();
        };
        let end = if calls_for_detector.fetch_add(1, Ordering::SeqCst) == 0 {
            text.len() + 1
        } else {
            start + "CUSTOMSECRET".len()
        };
        vec![promtect::detect::Match::new(
            "custom_rulebook",
            "CUSTOMSECRET".to_owned(),
            start,
            end,
        )]
    }));
    let promtect_url = spawn(promtect::proxy::app(c)).await;

    let response = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(r#"{"prompt":"CUSTOMSECRET"}"#)
        .send()
        .await
        .expect("post through residual detector");
    let status = response.status();
    let body = response.text().await.expect("read value-free rejection");

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(seen.requests.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(body.contains("custom_rulebook"));
    assert!(!body.contains("CUSTOMSECRET"));
}

#[derive(Clone, Copy)]
enum MalformedResidualSpan {
    Empty,
    Reversed,
    OutOfRange,
    NonCharBoundary,
    ValueMismatch,
}

async fn assert_malformed_residual_blocks_before_upstream(case: MalformedResidualSpan) {
    let (upstream_url, connections) = spawn_socket_counter().await;
    let mut c = ctx(&upstream_url);
    c.extra_detect = Some(Arc::new(move |candidate: &str| {
        if let Some(start) = candidate.find("CUSTOMSECRET") {
            return vec![promtect::detect::Match::new(
                "custom_rulebook",
                "CUSTOMSECRET".to_owned(),
                start,
                start + "CUSTOMSECRET".len(),
            )];
        }

        let sentinel_start = candidate
            .find("«promtect:custom_rulebook:")
            .expect("the first detector pass must mint a custom sentinel");
        let inside = sentinel_start + "«".len();
        let (value, start, end) = match case {
            MalformedResidualSpan::Empty => ("", inside, inside),
            MalformedResidualSpan::Reversed => ("x", inside + 2, inside + 1),
            MalformedResidualSpan::OutOfRange => {
                ("CUSTOMSECRET", candidate.len(), candidate.len() + 1)
            }
            MalformedResidualSpan::NonCharBoundary => ("x", sentinel_start + 1, inside),
            MalformedResidualSpan::ValueMismatch => {
                let start = candidate
                    .find("promtect")
                    .expect("minted sentinel must contain its marker");
                ("CUSTOMSECRET", start, start + "promtect".len())
            }
        };

        vec![promtect::detect::Match::new(
            "custom_rulebook",
            value.to_owned(),
            start,
            end,
        )]
    }));
    let promtect_url = spawn(promtect::proxy::app(c)).await;

    let response = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(r#"{"prompt":"CUSTOMSECRET"}"#)
        .send()
        .await
        .expect("post through malformed residual detector");
    let status = response.status();
    let body = response.text().await.expect("read value-free rejection");

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    assert!(body.contains("custom_rulebook"));
    assert!(!body.contains("CUSTOMSECRET"));
}

#[tokio::test]
async fn empty_residual_span_inside_a_minted_sentinel_fails_closed() {
    assert_malformed_residual_blocks_before_upstream(MalformedResidualSpan::Empty).await;
}

#[tokio::test]
async fn reversed_residual_span_inside_a_minted_sentinel_fails_closed() {
    assert_malformed_residual_blocks_before_upstream(MalformedResidualSpan::Reversed).await;
}

#[tokio::test]
async fn out_of_range_residual_span_fails_closed() {
    assert_malformed_residual_blocks_before_upstream(MalformedResidualSpan::OutOfRange).await;
}

#[tokio::test]
async fn non_char_boundary_residual_span_inside_a_minted_sentinel_fails_closed() {
    assert_malformed_residual_blocks_before_upstream(MalformedResidualSpan::NonCharBoundary).await;
}

#[tokio::test]
async fn value_mismatched_residual_span_inside_a_minted_sentinel_fails_closed() {
    assert_malformed_residual_blocks_before_upstream(MalformedResidualSpan::ValueMismatch).await;
}

/// Three distinct secrets in one body are each masked before reaching the upstream
/// and all three are restored in the response returned to the client.
#[tokio::test]
async fn multiple_distinct_secrets_masked_and_restored() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let ant = "sk-ant-api03-abcdefghijklmnopqrstuvwx";
    let db = "postgres://u:S3cretPass1@h:5432/db";

    let body = format!(r#"{{"aws":"{aws}","ant":"{ant}","db":"{db}"}}"#);

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&promtect_url, &body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();

    // Upstream must NOT see any real secret value.
    assert!(!upstream_saw.contains(aws), "AWS key leaked to upstream");
    assert!(
        !upstream_saw.contains(ant),
        "Anthropic key leaked to upstream"
    );
    assert!(
        !upstream_saw.contains("S3cretPass1"),
        "DB password leaked to upstream"
    );

    // Upstream must see sentinel tokens.
    assert!(
        upstream_saw.contains("«promtect:"),
        "upstream should contain sentinels"
    );

    // Client response must have all three real values restored.
    assert!(resp_text.contains(aws), "AWS key not restored in response");
    assert!(
        resp_text.contains(ant),
        "Anthropic key not restored in response"
    );
    assert!(
        resp_text.contains("S3cretPass1"),
        "DB password not restored in response"
    );
}

/// Plain text with no secrets is forwarded and returned completely unchanged.
#[tokio::test]
async fn non_secret_body_passes_through_unchanged() {
    let body = r#"{"messages":[{"role":"user","content":"hello world, no secrets here"}]}"#;

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&promtect_url, body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();

    // Upstream receives exactly the original body — no spurious modifications.
    assert_eq!(
        upstream_saw, body,
        "non-secret body must pass through unchanged"
    );

    // Client receives the original body back (echoed by mock).
    let parsed: Value = serde_json::from_str(&resp_text).unwrap();
    assert_eq!(
        parsed["echo"].as_str().unwrap(),
        body,
        "non-secret body must be echoed back unchanged"
    );
}

/// A dead upstream port causes Promtect to return HTTP 502 to the client.
#[tokio::test]
async fn upstream_error_returns_502() {
    // Reserve an ephemeral port, then drop the listener so the port is closed
    // at test time — guarantees the upstream connection is refused (502) without
    // depending on a specific well-known port being free/closed on the host.
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = reserved.local_addr().unwrap();
    drop(reserved);
    let dead_ctx = promtect::proxy::Ctx {
        upstream: format!("http://{dead_addr}"),
        audit: Arc::new(promtect::audit::Audit::null()),
        client: reqwest::Client::new(),
        max_body_bytes: promtect::proxy::DEFAULT_MAX_BODY_BYTES,
        restore: true,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: None,
        output_scan: None,
    };
    let promtect_url = spawn(promtect::proxy::app(dead_ctx)).await;

    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(r#"{"ping":true}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502, "dead upstream must produce 502");
}

/// The same secret appearing twice in a body maps to ONE sentinel repeated twice,
/// not two different sentinels.
#[tokio::test]
async fn same_secret_twice_uses_one_sentinel() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"a":"{aws}","b":"{aws}"}}"#);

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&promtect_url, &body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();

    // The real key must be absent from what the upstream received.
    assert!(
        !upstream_saw.contains(aws),
        "AWS key must not appear in the body sent to upstream"
    );

    // Extract all sentinel tokens from the upstream body.
    let sentinel_re = regex::Regex::new(r"«promtect:[a-z_]+:[0-9a-f]+»").unwrap();
    let sentinels: Vec<&str> = sentinel_re
        .find_iter(&upstream_saw)
        .map(|m| m.as_str())
        .collect();

    assert_eq!(
        sentinels.len(),
        2,
        "two secret occurrences must produce two sentinel tokens"
    );
    assert_eq!(
        sentinels[0], sentinels[1],
        "same secret must map to the same sentinel (deduplication)"
    );

    // Both occurrences are restored in the client response.
    let count = resp_text.matches(aws).count();
    assert_eq!(
        count, 2,
        "both occurrences of the secret must be restored in the response"
    );
}

/// The sentinel in the mock's echo response is replaced with the real secret
/// before it is handed back to the client.
#[tokio::test]
async fn response_body_sentinel_is_restored() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"key":"{aws}"}}"#);

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&promtect_url, &body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();
    // Confirm the upstream saw a sentinel, not the real key.
    assert!(
        !upstream_saw.contains(aws),
        "key must be masked before reaching upstream"
    );
    assert!(
        upstream_saw.contains("«promtect:"),
        "upstream must receive a sentinel"
    );

    // The client response must have the real key, not the sentinel.
    assert!(
        resp_text.contains(aws),
        "real key must be restored in client response"
    );
    assert!(
        !resp_text.contains("«promtect:"),
        "sentinel must not leak into client response"
    );
}

/// The Content-Length the upstream receives matches the actual byte length of the
/// (potentially lengthened) masked body — no stale original-length header.
///
/// Note: reqwest may send chunked transfer-encoding rather than Content-Length.
/// In that case we assert instead that the upstream body round-trips correctly
/// (the masked body is well-formed and fully received), which is the meaningful
/// invariant this test pins.
#[tokio::test]
async fn forwarded_content_length_matches_masked_body() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    // A sentinel like «promtect:aws_key:0001» is longer than the original key,
    // so masking changes the byte length.
    let body = format!(r#"{{"key":"{aws}"}}"#);

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    post_through(&promtect_url, &body).await;

    let upstream_body = seen.body.lock().unwrap().clone();
    let upstream_headers = seen.headers.lock().unwrap().clone();

    // Invariant: the upstream body contains the sentinel, not the original key.
    assert!(
        !upstream_body.contains(aws),
        "masked body must not contain the original key"
    );

    if let Some(cl) = upstream_headers.get("content-length") {
        // When a content-length is present, it must match the masked body's byte count.
        let declared: usize = cl
            .to_str()
            .unwrap()
            .parse()
            .expect("content-length must be a valid integer");
        assert_eq!(
            declared,
            upstream_body.len(),
            "content-length must equal the byte length of the masked body"
        );
    } else {
        // Chunked or no Content-Length: assert the body is non-empty and well-formed.
        assert!(
            !upstream_body.is_empty(),
            "upstream must receive a non-empty masked body"
        );
        assert!(
            upstream_body.contains("«promtect:"),
            "chunked-encoded body must still contain the sentinel"
        );
    }
}

/// A sentinel from one request must never restore a secret from another. The
/// vault is per-request, so a `«promtect:aws_key:0001»` minted while masking
/// request 1's real key cannot be expanded back into that key when the SAME
/// literal sentinel appears in request 2's response. This pins the cross-request
/// secret-bleed fix: one shared `Ctx` (and thus one shared upstream/audit) but a
/// fresh vault per request.
#[tokio::test]
async fn vault_does_not_bleed_secrets_across_requests() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    // The deterministic sentinel: the first secret minted in a fresh vault is
    // always counter 1 -> 0001, kind aws_key.
    let sentinel = "«promtect:aws_key:0001»";

    let (mock_url, _seen) = spawn_mock().await;
    // ONE Ctx shared across both requests, exactly as the running server uses it.
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    // Request 1: a real AWS key is masked to `0001` inside request 1's vault.
    let (_, resp1) = post_through(&promtect_url, &format!(r#"{{"key":"{aws}"}}"#)).await;
    assert!(
        resp1.contains(aws),
        "request 1 must restore its own secret in its own response"
    );

    // Request 2: the body literally contains request 1's sentinel. It is not a
    // detectable secret, so it passes through to the (echoing) upstream unchanged
    // and comes back in the response, where restore runs against request 2's vault.
    let (_, resp2) = post_through(&promtect_url, &format!(r#"{{"note":"{sentinel}"}}"#)).await;

    // With a per-request vault, request 2's vault never learned `0001`, so the
    // sentinel stays literal and request 1's real key cannot leak.
    assert!(
        resp2.contains(sentinel),
        "request 2 must keep the literal sentinel (its vault never minted it)"
    );
    assert!(
        !resp2.contains(aws),
        "request 1's real secret must NOT bleed into request 2's response"
    );
}

/// A request body larger than the configured cap is refused with 413 and never
/// reaches the upstream — Promtect must not buffer unbounded input. A tiny cap
/// plus a small (4 KiB) fixture exercises this deterministically: the body fits
/// the socket buffer, so the client finishes sending and reads a clean 413
/// rather than racing a connection reset.
#[tokio::test]
async fn oversized_body_is_rejected_with_413() {
    let (mock_url, seen) = spawn_mock().await;
    let audit_path = std::env::temp_dir().join(format!(
        "promtect-oversized-body-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let small_cap = promtect::proxy::Ctx {
        upstream: mock_url.clone(),
        audit: Arc::new(promtect::audit::Audit::to_file(audit_path.clone())),
        client: reqwest::Client::new(),
        max_body_bytes: 64,
        restore: true,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: None,
        output_scan: None,
    };
    let promtect_url = spawn(promtect::proxy::app(small_cap)).await;

    let body = "x".repeat(4096); // far over the 64-byte cap, still tiny
    let (status, _text) = post_through(&promtect_url, &body).await;
    let metrics = promtect::metrics::aggregate(&audit_path);
    std::fs::remove_file(&audit_path).ok();

    assert_eq!(status, reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    // Rejected before forwarding: the upstream must never have seen the body.
    assert!(
        seen.body.lock().unwrap().is_empty(),
        "upstream must not receive a body that exceeded the cap"
    );
    assert_eq!(metrics.requests_total, 1);
    assert_eq!(metrics.requests_clean, 0);
    assert_eq!(metrics.requests_blocked_total, 1);
    assert_eq!(metrics.recent.len(), 1);
    assert!(metrics.recent[0].blocked);
}

/// A body within the cap passes straight through (masked, then forwarded). The
/// cap rejects only what exceeds it; normal traffic is unaffected.
#[tokio::test]
async fn body_within_cap_passes_through() {
    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await; // default 32 MiB cap
    let (status, _text) = post_through(&promtect_url, r#"{"content":"hello world"}"#).await;

    assert!(status.is_success());
    assert!(
        seen.body.lock().unwrap().contains("hello world"),
        "a body under the cap must reach the upstream"
    );
}

/// Every non-identity request content coding is rejected before the mock upstream
/// receives an HTTP request. The client-visible error is constant and does not
/// reflect either the body or attacker-controlled encoding value.
#[tokio::test]
async fn non_identity_content_encodings_return_value_free_415_without_forwarding() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"{aws}"}}"#);
    let encodings = [
        "gzip",
        "deflate",
        "br",
        "zstd",
        "snappy-private-value",
        "gzip, br",
        "identity, gzip",
        "GzIp",
        "gzip , br",
    ];

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    for encoding in encodings {
        let (status, response) = post_with_encoding(&promtect_url, &body, encoding).await;

        assert_eq!(
            status,
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{encoding:?} must be rejected"
        );
        assert_eq!(
            response,
            "promtect: unsupported request Content-Encoding; send an identity-encoded body",
            "the 415 response must be constant and value-free"
        );
        assert!(
            !response.contains(aws),
            "the response reflected the request body"
        );
        assert!(
            !response.contains(encoding),
            "the response reflected the Content-Encoding value"
        );
    }

    assert_eq!(
        seen.requests.load(Ordering::Relaxed),
        0,
        "rejected requests must not reach the upstream handler"
    );
}

/// Rejection happens before reqwest resolves or opens the configured upstream.
/// The controlled receiver counts accepted TCP sockets, not merely HTTP handlers.
#[tokio::test]
async fn rejected_content_encoding_opens_no_upstream_socket() {
    let (upstream_url, connections) = spawn_socket_counter().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&upstream_url))).await;

    let (status, _) = post_with_encoding(
        &promtect_url,
        r#"{"content":"AKIAIOSFODNN7EXAMPLE"}"#,
        "gzip",
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "Promtect opened a TCP socket to the upstream"
    );
}

/// Opaque non-UTF-8 header bytes cannot be emitted reliably by an HTTP client,
/// so drive the Axum router directly. The malformed value must still receive the
/// same fixed rejection, produce only fixed audit metadata, and open no socket.
#[tokio::test]
async fn non_utf8_content_encoding_is_value_free_and_opens_no_upstream_socket() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let body_marker = "non-utf8-private-body";
    let body = format!(r#"{{"content":"{secret}","marker":"{body_marker}"}}"#);
    let audit_path = std::env::temp_dir().join(format!(
        "promtect_non_utf8_encoding_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let (upstream_url, connections) = spawn_socket_counter().await;
    let mut proxy_ctx = ctx(&upstream_url);
    proxy_ctx.audit = Arc::new(promtect::audit::Audit::to_file(audit_path.clone()));
    let app = promtect::proxy::app(proxy_ctx);

    let mut request = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let opaque = HeaderValue::from_bytes(b"\xff")
        .expect("opaque non-UTF-8 header bytes are valid HeaderValue data");
    assert!(opaque.to_str().is_err(), "test value must be non-UTF-8");
    request.headers_mut().insert(CONTENT_ENCODING, opaque);

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let response_body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        response_body,
        "promtect: unsupported request Content-Encoding; send an identity-encoded body"
    );
    assert!(
        !response_body
            .as_ref()
            .windows(secret.len())
            .any(|w| w == secret.as_bytes())
    );
    assert!(
        !response_body
            .as_ref()
            .windows(body_marker.len())
            .any(|w| w == body_marker.as_bytes())
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "Promtect opened a TCP socket for a non-UTF-8 Content-Encoding"
    );

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let metrics = promtect::metrics::aggregate(&audit_path);
    assert!(audit.contains(r#""action":"request_rejected""#));
    assert!(audit.contains(r#""detector":"content_encoding""#));
    assert!(audit.contains("«unsupported-content-encoding»"));
    assert!(
        !audit.contains(secret),
        "audit contains the synthetic secret"
    );
    assert!(
        !audit.contains(body_marker),
        "audit reflects request-body content"
    );
    assert_eq!(metrics.requests_total, 1);
    assert_eq!(metrics.requests_clean, 0);
    assert_eq!(metrics.requests_blocked_total, 1);
    assert_eq!(metrics.recent.len(), 1);
    assert!(metrics.recent[0].blocked);

    let _ = std::fs::remove_file(audit_path);
}

/// Absent and identity-only request encodings keep the existing masking and
/// restoration path, including mixed-case and optional whitespace around tokens.
#[tokio::test]
async fn identity_and_absent_content_encoding_continue_through_masking_and_restoration() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"{aws}"}}"#);
    let encodings = [
        None,
        Some("identity"),
        Some("IdEnTiTy"),
        Some("identity , identity"),
    ];

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    for encoding in encodings {
        let (status, response) = match encoding {
            Some(value) => post_with_encoding(&promtect_url, &body, value).await,
            None => post_through(&promtect_url, &body).await,
        };

        assert!(status.is_success(), "{encoding:?} should be accepted");
        assert!(
            response.contains(aws),
            "{encoding:?} response did not restore the synthetic key"
        );
        let upstream_body = seen.body.lock().unwrap().clone();
        assert!(
            !upstream_body.contains(aws),
            "{encoding:?} bypassed request masking"
        );
        assert!(
            upstream_body.contains("«promtect:aws_key:"),
            "{encoding:?} did not reach the upstream as a sentinel"
        );
    }

    assert_eq!(
        seen.requests.load(Ordering::Relaxed),
        encodings.len() as u64
    );
}

/// The rejection audit event contains only a fixed action/reason marker and a
/// request ID. It never records the body, secret, or attacker-controlled coding.
#[tokio::test]
async fn rejected_content_encoding_writes_value_free_audit_event() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let encoding = "snappy-private-value";
    let body = format!(r#"{{"content":"{aws}","marker":"body-private-value"}}"#);
    let audit_path = std::env::temp_dir().join(format!(
        "promtect_rejected_encoding_{}.jsonl",
        uuid::Uuid::new_v4()
    ));

    let (mock_url, seen) = spawn_mock().await;
    let mut proxy_ctx = ctx(&mock_url);
    proxy_ctx.audit = Arc::new(promtect::audit::Audit::to_file(audit_path.clone()));
    let promtect_url = spawn(promtect::proxy::app(proxy_ctx)).await;

    let (status, response) = post_with_encoding(&promtect_url, &body, encoding).await;
    let audit = std::fs::read_to_string(&audit_path).unwrap();

    assert_eq!(status, reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response,
        "promtect: unsupported request Content-Encoding; send an identity-encoded body"
    );
    assert!(audit.contains(r#""action":"request_rejected""#));
    assert!(audit.contains(r#""detector":"content_encoding""#));
    assert!(audit.contains("«unsupported-content-encoding»"));
    assert!(!audit.contains(aws), "audit contains the synthetic secret");
    assert!(
        !audit.contains(encoding),
        "audit reflects the encoding value"
    );
    assert!(
        !audit.contains("body-private-value"),
        "audit reflects request-body content"
    );
    assert_eq!(seen.requests.load(Ordering::Relaxed), 0);

    let _ = std::fs::remove_file(audit_path);
}

// ── Streaming (SSE) restore ─────────────────────────────────────────────────

/// Mock upstream that echoes the (masked) request body back as a STREAMED
/// response, ONE BYTE PER CHUNK. This forces every sentinel to be split across
/// chunk boundaries — the worst case for the streaming restorer.
async fn mock_stream(State(seen): State<Seen>, body: String) -> axum::response::Response {
    *seen.body.lock().unwrap() = body.clone();
    let chunks: Vec<Result<bytes::Bytes, std::convert::Infallible>> = body
        .into_bytes()
        .into_iter()
        .map(|b| Ok(bytes::Bytes::from(vec![b])))
        .collect();
    axum::response::Response::builder()
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from_stream(futures_util::stream::iter(
            chunks,
        )))
        .unwrap()
}

/// Spawn a streaming mock upstream and return its URL plus the `Seen` handle.
async fn spawn_stream_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/", post(mock_stream))
        .with_state(seen.clone());
    let url = spawn(app).await;
    (url, seen)
}

fn truncate_before_sentinel_close(masked: &str) -> String {
    let close = masked
        .find('»')
        .expect("masked request contains a sentinel close");
    masked[..close].to_string()
}

async fn mock_interrupted_stream(
    State(seen): State<Seen>,
    body: String,
) -> axum::response::Response {
    *seen.body.lock().unwrap() = body.clone();
    let partial = truncate_before_sentinel_close(&body);
    let first = futures_util::stream::once(async move {
        Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(partial))
    });
    let failure = futures_util::stream::once(async {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        Err::<bytes::Bytes, std::io::Error>(std::io::Error::other("synthetic interrupted stream"))
    });
    axum::response::Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(futures_util::StreamExt::chain(
            first, failure,
        )))
        .unwrap()
}

async fn mock_timed_out_stream(State(seen): State<Seen>, body: String) -> axum::response::Response {
    *seen.body.lock().unwrap() = body.clone();
    let partial = truncate_before_sentinel_close(&body);
    let first = futures_util::stream::once(async move {
        Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(partial))
    });
    let stalled = futures_util::stream::once(async {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(b"late"))
    });
    axum::response::Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(futures_util::StreamExt::chain(
            first, stalled,
        )))
        .unwrap()
}

async fn assert_interrupted_stream_is_client_visible(
    upstream_handler: axum::routing::MethodRouter<Seen>,
    read_timeout: Option<std::time::Duration>,
) {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let request_body = format!(r#"{{"content":"{aws}"}}"#);
    let audit_path = std::env::temp_dir().join(format!(
        "promtect-stream-recovery-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let seen = Seen::default();
    let upstream = spawn(
        Router::new()
            .route("/", upstream_handler)
            .with_state(seen.clone()),
    )
    .await;
    let mut proxy_ctx = ctx(&upstream);
    proxy_ctx.audit = Arc::new(promtect::audit::Audit::to_file(audit_path.clone()));
    if let Some(timeout) = read_timeout {
        proxy_ctx.client = reqwest::Client::builder()
            .read_timeout(timeout)
            .build()
            .expect("timeout test client");
    }
    let proxy = spawn(promtect::proxy::app(proxy_ctx)).await;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/"))
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .expect("proxy response headers");
    assert_eq!(
        response
            .headers()
            .get("trailer")
            .and_then(|v| v.to_str().ok()),
        Some("promtect-stream-outcome")
    );
    let body_result = response.bytes().await;
    let masked = seen.body.lock().unwrap().clone();
    let audit = std::fs::read_to_string(&audit_path).expect("stream recovery audit");
    std::fs::remove_file(&audit_path).ok();

    assert!(
        body_result.is_err(),
        "ordinary clients must not accept a truncated upstream body as complete"
    );
    assert!(!masked.contains(aws));
    assert!(audit.contains("\"action\":\"stream_interrupted\""));
    assert!(!audit.contains(aws));
}

#[tokio::test]
async fn interrupted_stream_is_client_visible_and_audited() {
    assert_interrupted_stream_is_client_visible(post(mock_interrupted_stream), None).await;
}

#[tokio::test]
async fn interrupted_stream_emits_safe_prefix_then_aborts_http1_body() {
    let seen = Seen::default();
    let upstream = spawn(
        Router::new()
            .route("/", post(mock_interrupted_stream))
            .with_state(seen.clone()),
    )
    .await;
    let proxy = spawn(promtect::proxy::app(ctx(&upstream))).await;
    let authority = proxy
        .strip_prefix("http://")
        .expect("spawn returns an HTTP URL");
    let body = r#"{"content":"AKIAIOSFODNN7EXAMPLE"}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nTE: trailers\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut socket = tokio::net::TcpStream::connect(authority)
        .await
        .expect("connect raw HTTP/1.1 client to proxy");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write raw HTTP/1.1 request");
    let mut wire = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.read_to_end(&mut wire),
    )
    .await
    .expect("proxy closes Connection: close response")
    .expect("read raw HTTP/1.1 response");
    let masked = seen.body.lock().unwrap().clone();
    let partial = truncate_before_sentinel_close(&masked);
    let expected = partial
        .split_once('«')
        .map_or(partial.as_str(), |(prefix, _)| prefix);
    let wire_text = String::from_utf8_lossy(&wire).to_ascii_lowercase();

    assert!(wire_text.contains("trailer: promtect-stream-outcome\r\n"));
    assert!(
        wire.windows(expected.len())
            .any(|window| window == expected.as_bytes()),
        "bytes emitted before the held sentinel carry were not delivered before the body error"
    );
    assert!(
        !wire_text.ends_with("0\r\npromtect-stream-outcome: complete\r\n\r\n")
            && !wire_text.ends_with("0\r\npromtect-stream-outcome: interrupted\r\n\r\n"),
        "an interrupted response must not carry a successful terminal chunk: {wire_text:?}"
    );
}

#[tokio::test]
async fn timed_out_stream_is_client_visible_and_audited() {
    assert_interrupted_stream_is_client_visible(
        post(mock_timed_out_stream),
        Some(std::time::Duration::from_millis(50)),
    )
    .await;
}

/// A sentinel split across streamed chunk boundaries is fully reassembled and
/// restored: the client sees the real secret, never a sentinel, and the SSE
/// content-type is preserved.
#[tokio::test]
async fn streaming_sse_sentinel_split_is_restored() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"my key is {aws}"}}"#);

    let (mock_url, seen) = spawn_stream_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let text = resp.text().await.unwrap();

    // Upstream saw the masked body (a sentinel), never the real key.
    let upstream_saw = seen.body.lock().unwrap().clone();
    assert!(!upstream_saw.contains(aws), "real key leaked to upstream");
    assert!(
        upstream_saw.contains("«promtect:aws_key:"),
        "upstream should have received a sentinel"
    );

    // Client got the real key back, reassembled from byte-split chunks, with no
    // sentinel left over.
    assert!(
        text.contains(aws),
        "restored secret missing from streamed response: {text:?}"
    );
    assert!(
        !text.contains("«promtect:"),
        "a sentinel leaked into the client response: {text:?}"
    );
    assert_eq!(
        content_type.as_deref(),
        Some("text/event-stream"),
        "SSE content-type must be preserved"
    );
}

/// Strict mode (`restore: false`): the masked body still streams through without
/// hanging, but secrets are NEVER re-inserted — the response keeps the sentinel.
#[tokio::test]
async fn strict_mode_does_not_restore_secrets() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"my key is {aws}"}}"#);

    let (mock_url, seen) = spawn_stream_mock().await;
    let mut strict = ctx(&mock_url);
    strict.restore = false;
    let scan_calls = Arc::new(AtomicU64::new(0));
    let scan_calls_for_callback = Arc::clone(&scan_calls);
    strict.output_scan = Some(Arc::new(move |_text: &str| {
        scan_calls_for_callback.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }));
    let promtect_url = spawn(promtect::proxy::app(strict)).await;

    let (status, text) = post_through(&promtect_url, &body).await;
    assert!(status.is_success());

    // Masking still happened: upstream never saw the real key.
    let upstream_saw = seen.body.lock().unwrap().clone();
    assert!(!upstream_saw.contains(aws), "real key leaked to upstream");

    // But restore is off: the sentinel stays, the real secret never comes back.
    assert!(
        text.contains("«promtect:aws_key:"),
        "strict mode should leave the sentinel in the response: {text:?}"
    );
    assert!(
        !text.contains(aws),
        "strict mode must NOT restore the real secret: {text:?}"
    );
    assert_eq!(
        scan_calls.load(Ordering::SeqCst),
        0,
        "strict mode streams sentinels verbatim and must not run the restored-text output scan"
    );
}

// ── Content-type guard ──────────────────────────────────────────────────────

/// Mock upstream that echoes the request body back with a binary content-type.
async fn mock_octet(State(seen): State<Seen>, body: String) -> axum::response::Response {
    *seen.body.lock().unwrap() = body.clone();
    axum::response::Response::builder()
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Spawn an octet-stream mock upstream and return its URL plus the `Seen` handle.
async fn spawn_octet_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/", post(mock_octet))
        .with_state(seen.clone());
    let url = spawn(app).await;
    (url, seen)
}

/// SECURITY: masking is decided by the body's actual UTF-8 validity, NOT the
/// client-declared content-type — so a secret cannot bypass masking by labelling
/// a JSON body as `application/octet-stream`.
#[tokio::test]
async fn mislabeled_binary_request_is_still_masked() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"{aws}"}}"#); // valid UTF-8 text

    let (mock_url, seen) = spawn_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/octet-stream") // the lie
        .body(body)
        .send()
        .await
        .unwrap();

    let upstream_saw = seen.body.lock().unwrap().clone();
    assert!(
        !upstream_saw.contains(aws),
        "a mislabelled-binary text body must NOT bypass masking"
    );
    assert!(
        upstream_saw.contains("«promtect:aws_key:"),
        "the secret should have been masked"
    );
}

/// Raw-bytes mock upstream (the default `String`-body mock rejects non-UTF-8).
async fn mock_raw(State(seen): State<Seen>, body: bytes::Bytes) -> axum::response::Response {
    *seen.body.lock().unwrap() = String::from_utf8_lossy(&body).into_owned();
    axum::response::Response::builder()
        .status(200)
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_raw_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/", post(mock_raw))
        .with_state(seen.clone());
    (spawn(app).await, seen)
}

/// A genuinely binary (non-UTF-8) body is forwarded unscanned and byte-for-byte,
/// so the proxy never corrupts a binary upload.
#[tokio::test]
async fn non_utf8_binary_request_is_forwarded_unscanned() {
    let (mock_url, seen) = spawn_raw_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    // 0xFF 0xFE are never valid UTF-8 → treated as binary, forwarded verbatim.
    let body = vec![0xFF, 0xFE, b'A', b'K', b'I', b'A'];
    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());
    let upstream_saw = seen.body.lock().unwrap().clone();
    assert!(
        !upstream_saw.contains("«promtect:"),
        "a non-UTF-8 binary body must not be scanned/masked"
    );
    assert!(
        upstream_saw.contains("AKIA"),
        "the binary body must be forwarded unscanned"
    );
}

/// A response with a binary content-type is streamed back unchanged — never run
/// through the restorer (which would lossily corrupt it). The request itself is
/// still masked, so the sentinel survives in the binary response.
#[tokio::test]
async fn binary_response_is_not_restored() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"{aws}"}}"#);

    let (mock_url, seen) = spawn_octet_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let (status, text) = post_through(&promtect_url, &body).await;
    assert!(status.is_success());

    // The JSON request WAS masked: upstream saw a sentinel, not the key.
    assert!(
        !seen.body.lock().unwrap().contains(aws),
        "request should still be masked"
    );
    // The octet-stream response is NOT restored: sentinel stays, key absent.
    assert!(
        text.contains("«promtect:aws_key:"),
        "binary response must not be restored: {text:?}"
    );
    assert!(
        !text.contains(aws),
        "binary response must not have the secret re-inserted: {text:?}"
    );
}

// ── Response encoding + method/empty-body handling ──────────────────────────

/// Mock that echoes the request body back labelled `content-encoding: gzip`
/// (the bytes aren't really gzipped — we only need the header present).
async fn mock_compressed(State(seen): State<Seen>, body: String) -> axum::response::Response {
    *seen.body.lock().unwrap() = body.clone();
    axum::response::Response::builder()
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_compressed_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/", post(mock_compressed))
        .with_state(seen.clone());
    (spawn(app).await, seen)
}

/// A compressed (content-encoding) response is streamed through verbatim — NOT
/// run through the restorer (which would scan ciphertext) — and keeps its
/// content-encoding header so the client can still decode it.
#[tokio::test]
async fn compressed_response_is_passed_through_not_restored() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let body = format!(r#"{{"content":"{aws}"}}"#);

    let (mock_url, _seen) = spawn_compressed_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;

    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let enc = resp
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let text = resp.text().await.unwrap();

    assert_eq!(
        enc.as_deref(),
        Some("gzip"),
        "content-encoding must be preserved for the client to decode"
    );
    assert!(
        text.contains("«promtect:aws_key:"),
        "a compressed response must NOT be restored: {text:?}"
    );
    assert!(!text.contains(aws));
}

/// Echo mock that accepts ANY method and records "<METHOD> <body>".
async fn mock_any(
    State(seen): State<Seen>,
    method: axum::http::Method,
    body: String,
) -> Json<Value> {
    *seen.body.lock().unwrap() = format!("{method} {body}");
    Json(json!({ "ok": true }))
}

async fn spawn_any_mock() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new().fallback(mock_any).with_state(seen.clone());
    (spawn(app).await, seen)
}

/// A GET request (no body) and a POST with an empty body both proxy cleanly —
/// the method is forwarded and an empty body never panics or 413s.
#[tokio::test]
async fn get_and_empty_body_requests_are_handled() {
    let (mock_url, seen) = spawn_any_mock().await;
    let promtect_url = spawn(promtect::proxy::app(ctx(&mock_url))).await;
    let client = reqwest::Client::new();

    // GET, no body → method forwarded.
    let resp = client.get(format!("{promtect_url}/")).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(
        seen.body.lock().unwrap().starts_with("GET"),
        "GET method must be forwarded"
    );

    // POST with an empty body → success, upstream sees an empty body.
    let resp = client
        .post(format!("{promtect_url}/"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        seen.body.lock().unwrap().as_str(),
        "POST ",
        "empty POST body must forward as empty"
    );
}
