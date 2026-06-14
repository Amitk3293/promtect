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

/// Resolve the upstream origin (scheme + host) from an explicit override or a
/// named mode. An explicit `PROMTECT_UPSTREAM` always wins — it is the chaining
/// knob, letting Promtect sit in front of another proxy (Headroom, LiteLLM, a
/// corporate proxy) or any custom endpoint. Otherwise `PROMTECT_MODE` selects a
/// known provider; the default is Anthropic.
///
/// Upstreams are origins only: the client's full request path is appended
/// verbatim (the proxy is path-transparent), so the caller points its tool's
/// base URL — including any `/v1` segment that tool expects — at Promtect.
/// Returns `Err` for an unrecognised mode.
pub fn resolve_upstream(
    mode: Option<&str>,
    upstream_override: Option<&str>,
) -> Result<String, String> {
    if let Some(u) = upstream_override {
        let u = u.trim();
        if !u.is_empty() {
            return Ok(u.trim_end_matches('/').to_string());
        }
    }
    match mode.map(|m| m.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("anthropic") => Ok("https://api.anthropic.com".to_string()),
        Some("openai") => Ok("https://api.openai.com".to_string()),
        Some("ollama") => Ok("http://localhost:11434".to_string()),
        Some("openrouter") => Ok("https://openrouter.ai".to_string()),
        Some(other) => Err(format!(
            "unknown PROMTECT_MODE '{other}' (expected anthropic|openai|ollama|openrouter); \
             or set PROMTECT_UPSTREAM to a custom URL"
        )),
    }
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

    // Content-type guard: scan textual bodies only. A binary/opaque body — a
    // multipart upload, an audio/image payload to an OpenAI endpoint — is
    // forwarded byte-for-byte, so the proxy never corrupts it by lossy UTF-8
    // conversion or a mistaken substitution. Default is to scan (secure).
    let forward_bytes = if is_binary_body(&headers) {
        // Pass through unscanned, but still record it as traffic (zero secrets)
        // so the request appears in metrics.
        ctx.audit
            .record_request(&request_id, 0, &[], body_bytes.len(), body_bytes.len());
        body_bytes.to_vec()
    } else {
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

        masked.into_bytes()
    };

    match forward(&ctx, method, &uri, &headers, forward_bytes).await {
        Ok(r) => restore_response(r, &ctx, vault, request_id).await,
        Err(e) => text_response(502, format!("promtect upstream error: {e}")),
    }
}

/// Whether a body is a known binary/opaque type that must NOT be scanned or
/// restored. Masking such a body would corrupt it (lossy UTF-8 conversion or a
/// mistaken substitution), so binary requests are forwarded and binary responses
/// are streamed back byte-for-byte. The default is *not* binary — an absent or
/// unrecognised content-type is still scanned, so a secret is never skipped just
/// because the type is missing (secure default).
fn is_binary_body(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(axum::http::header::CONTENT_TYPE) else {
        return false; // absent → treat as textual and scan it
    };
    let Ok(s) = value.to_str() else {
        return true; // non-ASCII content-type → opaque, do not touch
    };
    let s = s.to_ascii_lowercase();
    s.starts_with("multipart/")
        || s.starts_with("image/")
        || s.starts_with("audio/")
        || s.starts_with("video/")
        || s.starts_with("font/")
        || s.starts_with("application/octet-stream")
        || s.starts_with("application/pdf")
        || s.starts_with("application/zip")
        || s.starts_with("application/gzip")
        || s.starts_with("application/x-protobuf")
        || s.starts_with("application/grpc")
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

    // Restore only when enabled AND the response is textual. A binary response
    // (e.g. an image endpoint) must stream back byte-for-byte — running it
    // through the restorer would lossily corrupt it. `text/event-stream` is
    // textual, so SSE is restored.
    let body = if ctx.restore && !is_binary_body(&resp_headers) {
        // Transparent mode: restore secrets incrementally as the response
        // streams. SSE answers reach the client token-by-token instead of being
        // buffered whole (the M0 "hang"). The vault moves into the stream, which
        // the server polls after this handler returns.
        let sr = StreamRestorer::new(vault, Arc::clone(&ctx.audit), request_id);
        Body::from_stream(restore_stream(r.bytes_stream().boxed(), sr))
    } else {
        // Strict mode (PROMTECT_RESTORE=false) or a binary response: never
        // re-insert secrets. Stream the body straight through; the per-request
        // vault is dropped (and its contents zeroized) unused.
        drop(vault);
        Body::from_stream(r.bytes_stream())
    };

    // Status and headers come from an already-parsed upstream response, so this
    // build cannot realistically fail; fall back to a clean 502 rather than panic.
    out.body(body)
        .unwrap_or_else(|_| text_response(502, "promtect: could not assemble upstream response"))
}

#[cfg(test)]
mod tests {
    use super::resolve_upstream;

    #[test]
    fn default_mode_is_anthropic() {
        assert_eq!(
            resolve_upstream(None, None).unwrap(),
            "https://api.anthropic.com"
        );
        assert_eq!(
            resolve_upstream(Some("anthropic"), None).unwrap(),
            "https://api.anthropic.com"
        );
    }

    #[test]
    fn known_modes_resolve_to_origins() {
        assert_eq!(
            resolve_upstream(Some("openai"), None).unwrap(),
            "https://api.openai.com"
        );
        assert_eq!(
            resolve_upstream(Some("ollama"), None).unwrap(),
            "http://localhost:11434"
        );
        assert_eq!(
            resolve_upstream(Some("openrouter"), None).unwrap(),
            "https://openrouter.ai"
        );
        // Case- and whitespace-insensitive.
        assert_eq!(
            resolve_upstream(Some("  OpenAI "), None).unwrap(),
            "https://api.openai.com"
        );
    }

    #[test]
    fn explicit_upstream_overrides_mode_and_is_the_chaining_knob() {
        // Override wins even when a mode is set (e.g. chaining through Headroom).
        assert_eq!(
            resolve_upstream(Some("openai"), Some("http://127.0.0.1:8788")).unwrap(),
            "http://127.0.0.1:8788"
        );
        // Trailing slash is trimmed so path joining stays correct.
        assert_eq!(
            resolve_upstream(None, Some("http://localhost:4000/")).unwrap(),
            "http://localhost:4000"
        );
        // An empty override falls back to the mode default.
        assert_eq!(
            resolve_upstream(None, Some("   ")).unwrap(),
            "https://api.anthropic.com"
        );
    }

    #[test]
    fn unknown_mode_is_an_error() {
        let err = resolve_upstream(Some("gemini"), None).unwrap_err();
        assert!(err.contains("unknown PROMTECT_MODE"));
        assert!(err.contains("gemini"));
    }
}
