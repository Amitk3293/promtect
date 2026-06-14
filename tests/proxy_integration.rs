//! Integration tests for the Airlock proxy: header forwarding, multi-secret masking,
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

/// Build a fresh Airlock proxy `Ctx` pointing at `upstream_url`.
fn ctx(upstream_url: &str) -> airlock::proxy::Ctx {
    airlock::proxy::Ctx {
        upstream: upstream_url.to_string(),
        vault: Arc::new(airlock::vault::Vault::new()),
        audit: Arc::new(airlock::audit::Audit::null()),
        client: reqwest::Client::new(),
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

/// POST JSON body through Airlock; return the response body text.
async fn post_through(airlock_url: &str, body: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{airlock_url}/"))
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
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    let client = reqwest::Client::new();
    client
        .post(format!("{airlock_url}/"))
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
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&airlock_url, &body).await;

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
        upstream_saw.contains("«airlock:"),
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
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&airlock_url, body).await;

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

/// A dead upstream port causes Airlock to return HTTP 502 to the client.
#[tokio::test]
async fn upstream_error_returns_502() {
    // Reserve an ephemeral port, then drop the listener so the port is closed
    // at test time — guarantees the upstream connection is refused (502) without
    // depending on a specific well-known port being free/closed on the host.
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = reserved.local_addr().unwrap();
    drop(reserved);
    let dead_ctx = airlock::proxy::Ctx {
        upstream: format!("http://{dead_addr}"),
        vault: Arc::new(airlock::vault::Vault::new()),
        audit: Arc::new(airlock::audit::Audit::null()),
        client: reqwest::Client::new(),
    };
    let airlock_url = spawn(airlock::proxy::app(dead_ctx)).await;

    let resp = reqwest::Client::new()
        .post(format!("{airlock_url}/"))
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
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&airlock_url, &body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();

    // The real key must be absent from what the upstream received.
    assert!(
        !upstream_saw.contains(aws),
        "AWS key must not appear in the body sent to upstream"
    );

    // Extract all sentinel tokens from the upstream body.
    let sentinel_re = regex::Regex::new(r"«airlock:[a-z_]+:[0-9a-f]+»").unwrap();
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
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    let (_, resp_text) = post_through(&airlock_url, &body).await;

    let upstream_saw = seen.body.lock().unwrap().clone();
    // Confirm the upstream saw a sentinel, not the real key.
    assert!(
        !upstream_saw.contains(aws),
        "key must be masked before reaching upstream"
    );
    assert!(
        upstream_saw.contains("«airlock:"),
        "upstream must receive a sentinel"
    );

    // The client response must have the real key, not the sentinel.
    assert!(
        resp_text.contains(aws),
        "real key must be restored in client response"
    );
    assert!(
        !resp_text.contains("«airlock:"),
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
    // A sentinel like «airlock:aws_key:0001» is longer than the original key,
    // so masking changes the byte length.
    let body = format!(r#"{{"key":"{aws}"}}"#);

    let (mock_url, seen) = spawn_mock().await;
    let airlock_url = spawn(airlock::proxy::app(ctx(&mock_url))).await;

    post_through(&airlock_url, &body).await;

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
            upstream_body.contains("«airlock:"),
            "chunked-encoded body must still contain the sentinel"
        );
    }
}
