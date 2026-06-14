use crate::audit::Audit;
use crate::detect;
use crate::mask::{mask_text, restore_text};
use crate::vault::Vault;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use std::sync::Arc;

/// Shared, cheaply-clonable process-wide context for the proxy pipeline: the
/// upstream base URL, the (append-only, process-wide) audit log, and the outbound
/// client.
///
/// NOTE: there is deliberately NO vault here. The vault is created fresh per
/// request inside [`handle`] — a single shared vault would let a sentinel minted
/// in one request restore a secret belonging to a *different* request
/// (cross-request secret bleed). Scoping the vault to one request makes that
/// impossible by construction.
#[derive(Clone)]
pub struct Ctx {
    pub upstream: String,
    pub audit: Arc<Audit>,
    pub client: reqwest::Client,
}

/// Build the Airlock Axum router: a catch-all fallback that masks the request
/// body, forwards to `upstream`, and restores secrets in the response.
pub fn app(ctx: Ctx) -> Router {
    Router::new().fallback(handle).with_state(ctx)
}

async fn handle(State(ctx): State<Ctx>, req: Request) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();

    // INVARIANT: one vault per request. The same `&vault` masks the outbound body
    // and restores the inbound response, so only sentinels minted *for this
    // request* can ever be expanded back into a secret — no cross-request bleed.
    let vault = Vault::new();

    // Mask request body content. Auth headers forwarded untouched in forward().
    let masked = mask_text(&body_text, &vault, &ctx.audit, &request_id);

    // Second detect pass for the per-request summary (cheap; same input). This
    // avoids changing mask_text's signature while still producing an accurate
    // "caught vs clean" event. Secret values are never included in the summary.
    let hits = detect::detect(&body_text);
    let mut kinds: Vec<&str> = hits.iter().map(|m| m.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    ctx.audit.record_request(
        &request_id,
        hits.len(),
        &kinds,
        body_bytes.len(),
        masked.len(),
    );

    match forward(&ctx, method, &uri, &headers, masked.into_bytes()).await {
        Ok(r) => restore_response(r, &ctx, &vault, &request_id).await,
        Err(e) => Response::builder()
            .status(502)
            .body(Body::from(format!("airlock upstream error: {e}")))
            .unwrap(),
    }
}

async fn forward(
    ctx: &Ctx,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> reqwest::Result<reqwest::Response> {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let url = format!("{}{}", ctx.upstream.trim_end_matches('/'), path_and_query);

    let mut builder = ctx.client.request(method, url.as_str()).body(body);
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("accept-encoding")
        {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    builder.send().await
}

async fn restore_response(
    r: reqwest::Response,
    ctx: &Ctx,
    vault: &Vault,
    request_id: &str,
) -> Response {
    let status = r.status();
    let resp_headers = r.headers().clone();

    let bytes = r.bytes().await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    // Restore against the SAME per-request vault that did the masking above.
    let restored = restore_text(&text, vault, &ctx.audit, request_id);

    let mut out = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("content-encoding")
            || n.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out = out.header(name.clone(), value.clone());
    }
    out.body(Body::from(restored)).unwrap()
}
