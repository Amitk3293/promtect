use crate::audit::Audit;
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

#[derive(Clone)]
pub struct Ctx {
    pub upstream: String,
    pub vault: Arc<Vault>,
    pub audit: Arc<Audit>,
    pub client: reqwest::Client,
}

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

    // Mask request body content. Auth headers forwarded untouched in forward().
    let masked = mask_text(&body_text, &ctx.vault, &ctx.audit, &request_id);

    match forward(&ctx, method, &uri, &headers, masked.into_bytes()).await {
        Ok(r) => restore_response(r, &ctx, &request_id).await,
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

async fn restore_response(r: reqwest::Response, ctx: &Ctx, request_id: &str) -> Response {
    let status = r.status();
    let resp_headers = r.headers().clone();

    let bytes = r.bytes().await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let restored = restore_text(&text, &ctx.vault, &ctx.audit, request_id);

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
