//! Integration tests for the Promtect proxy: header forwarding, multi-secret masking,
//! 502 on upstream error, sentinel deduplication, and response restore invariants.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};

// ── Shared mock-upstream state ────────────────────────────────────────────────

/// Records every request the mock upstream receives so tests can assert on it.
#[derive(Clone, Default)]
struct Seen {
    body: Arc<Mutex<String>>,
    headers: Arc<Mutex<HeaderMap>>,
}

/// Echo handler: stores the received headers + body, returns `{"echo": <body>}`.
async fn mock(State(seen): State<Seen>, headers: HeaderMap, body: String) -> Json<Value> {
    *seen.headers.lock().unwrap() = headers;
    *seen.body.lock().unwrap() = body.clone();
    Json(json!({ "echo": body }))
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
    let small_cap = promtect::proxy::Ctx {
        upstream: mock_url.clone(),
        audit: Arc::new(promtect::audit::Audit::null()),
        client: reqwest::Client::new(),
        max_body_bytes: 64,
        restore: true,
    };
    let promtect_url = spawn(promtect::proxy::app(small_cap)).await;

    let body = "x".repeat(4096); // far over the 64-byte cap, still tiny
    let (status, _text) = post_through(&promtect_url, &body).await;

    assert_eq!(status, reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    // Rejected before forwarding: the upstream must never have seen the body.
    assert!(
        seen.body.lock().unwrap().is_empty(),
        "upstream must not receive a body that exceeded the cap"
    );
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
