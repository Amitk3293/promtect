use crate::audit::Audit;
use crate::detect;
use crate::mask::mask_text;
use crate::stream::{StreamRestorer, restore_stream};
use crate::vault::Vault;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use futures_util::StreamExt;
use std::sync::Arc;

/// Default cap on the request body Promtect will buffer in memory before masking.
/// A masking proxy has to read the whole body to scan it, so an unbounded read
/// is a memory-exhaustion vector. 32 MiB comfortably exceeds any real Anthropic
/// request while bounding the blast radius of a hostile or runaway client. The
/// effective limit lives on [`Ctx::max_body_bytes`] so it is both operator-tunable
/// (`PROMTECT_MAX_BODY_BYTES`) and testable without a multi-megabyte fixture.
pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Build a plain-text response without ever panicking. Used for Promtect's own
/// error replies (413/502), where we fully control status and headers. The
/// fallback arm only fires for an impossible invalid-status case and still
/// yields a valid `Response`, never a panic in the request path.
fn text_response(status: u16, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(msg.clone()))
        .unwrap_or_else(|_| Response::new(Body::from(msg)))
}

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
    /// Max request-body bytes buffered before the proxy returns 413. Defaults to
    /// [`DEFAULT_MAX_BODY_BYTES`]; lower it in tests to exercise the cap cheaply.
    pub max_body_bytes: usize,
    /// Whether to restore real secrets in the response (transparent mode, the
    /// default). When `false` (strict mode, `PROMTECT_RESTORE=false`), the masked
    /// upstream body is streamed through verbatim — sentinels are never expanded,
    /// so a secret provably never re-enters the response, logs, or terminal.
    pub restore: bool,
}

/// Build the Promtect Axum router: a catch-all fallback that masks the request
/// body, forwards to `upstream`, and restores secrets in the response.
pub fn app(ctx: Ctx) -> Router {
    Router::new().fallback(handle).with_state(ctx)
}

async fn handle(State(ctx): State<Ctx>, req: Request) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Buffer the body with a hard cap. `to_bytes` returns Err once the stream
    // exceeds the limit, so we refuse oversized bodies with 413 instead of
    // silently forwarding an empty/truncated one (the old `.unwrap_or_default()`
    // behaviour) or buffering without bound.
    let body_bytes = match axum::body::to_bytes(req.into_body(), ctx.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return text_response(
                413,
                format!(
                    "promtect: request body exceeds the {}-byte limit (or could not be read)",
                    ctx.max_body_bytes
                ),
            );
        }
    };
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();

    // INVARIANT: one vault per request. The same vault masks the outbound body
    // and restores the inbound response, so only sentinels minted *for this
    // request* can ever be expanded back into a secret — no cross-request bleed.
    // Held in an `Arc` so it can move into the response stream, which the server
    // polls after this handler returns.
    let vault = Arc::new(Vault::new());

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
        Ok(r) => restore_response(r, &ctx, vault, request_id).await,
        Err(e) => text_response(502, format!("promtect upstream error: {e}")),
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
    vault: Arc<Vault>,
    request_id: String,
) -> Response {
    let status = r.status();
    let resp_headers = r.headers().clone();

    let mut out = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        let n = name.as_str();
        // Drop length/encoding framing: the body is re-chunked and its length
        // changes when sentinels expand to real secrets, so a copied
        // content-length or transfer-encoding would describe the wrong body.
        if n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("content-encoding")
            || n.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out = out.header(name.clone(), value.clone());
    }

    let body = if ctx.restore {
        // Transparent mode: restore secrets incrementally as the response
        // streams. SSE answers reach the client token-by-token instead of being
        // buffered whole (the M0 "hang"). The vault moves into the stream, which
        // the server polls after this handler returns.
        let sr = StreamRestorer::new(vault, Arc::clone(&ctx.audit), request_id);
        Body::from_stream(restore_stream(r.bytes_stream().boxed(), sr))
    } else {
        // Strict mode (PROMTECT_RESTORE=false): never re-insert secrets. Stream
        // the masked body straight through; the per-request vault is dropped (and
        // its contents zeroized) unused.
        drop(vault);
        Body::from_stream(r.bytes_stream())
    };

    // Status and headers come from an already-parsed upstream response, so this
    // build cannot realistically fail; fall back to a clean 502 rather than panic.
    out.body(body)
        .unwrap_or_else(|_| text_response(502, "promtect: could not assemble upstream response"))
}
