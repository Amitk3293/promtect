// Spins up a mock "upstream" that records the exact body it received, starts
// Promtect pointed at it, sends a request containing a fake AWS key THROUGH
// Promtect, and asserts the key never reached the upstream and the response was
// restored.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, routing::post};
use serde_json::json;

const FAKE_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

#[derive(Clone, Default)]
struct Seen {
    body: Arc<Mutex<String>>,
}

async fn mock_upstream(State(seen): State<Seen>, body: String) -> Json<serde_json::Value> {
    *seen.body.lock().unwrap() = body.clone();
    Json(json!({ "echo": body }))
}

async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn canary_secret_never_reaches_upstream() {
    // 1. Mock upstream that records what it received.
    let seen = Seen::default();
    let upstream_app = Router::new()
        .route("/v1/messages", post(mock_upstream))
        .with_state(seen.clone());
    let upstream_url = spawn(upstream_app).await;

    // 2. Promtect pointed at the mock upstream.
    use promtect::proxy::{Ctx, app};
    let ctx = Ctx {
        upstream: upstream_url.clone(),
        audit: Arc::new(promtect::audit::Audit::null()),
        client: reqwest::Client::new(),
        max_body_bytes: promtect::proxy::DEFAULT_MAX_BODY_BYTES,
        restore: true,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: None,
        output_scan: None,
    };
    let promtect_url = spawn(app(ctx)).await;

    // 3. Send a request containing the fake key THROUGH Promtect.
    //    (reqwest has no `json` feature enabled, so build the body manually.)
    let payload =
        json!({ "messages": [{ "role": "user", "content": format!("my key is {FAKE_KEY}") }] });
    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/v1/messages"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&payload).unwrap())
        .send()
        .await
        .unwrap();
    let resp_text = resp.text().await.unwrap();

    // 4a. The upstream must NEVER have seen the real key.
    let upstream_saw = seen.body.lock().unwrap().clone();
    assert!(
        !upstream_saw.contains(FAKE_KEY),
        "LEAK: upstream received the real key"
    );
    assert!(
        upstream_saw.contains("«promtect:aws_key:"),
        "upstream should have seen a sentinel"
    );

    // 4b. The response handed back to the client must be restored.
    assert!(
        resp_text.contains(FAKE_KEY),
        "response should be restored to the real value"
    );
}
