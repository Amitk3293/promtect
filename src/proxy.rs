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
    /// Count of requests the proxy has received. `guard` reads this after the
    /// wrapped tool exits: zero means the tool never used the proxy (it bypassed
    /// masking) — a tripwire worth warning about.
    pub requests: Arc<std::sync::atomic::AtomicU64>,
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
            // Only http(s): the API key in the request's auth header is forwarded to
            // this upstream verbatim, so a non-http scheme (or junk) must not be
            // accepted and silently used.
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err(format!("upstream URL must be http(s) (got {u:?})"));
            }
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

/// Parse `PROMTECT_RESTORE`. Restore is on by default; only an explicit falsey
/// value (`0`/`false`/`no`/`off`, case-insensitive) disables it (strict mode).
pub fn parse_restore(value: Option<&str>) -> bool {
    match value {
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        None => true,
    }
}

/// Parse a default-off boolean flag (e.g. `PROMTECT_BLOCK_RISKY`). Unset/empty →
/// `false`; only an explicit truthy value (`1`/`true`/`yes`/`on`, case-insensitive)
/// enables it. The inverse of [`parse_restore`]'s default-on behaviour.
pub fn parse_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Parse `PROMTECT_MAX_BODY_BYTES`. Unset → the default. A present-but-invalid
/// value (non-numeric, or `0`) is an error — we fail closed rather than silently
/// reverting to the large default, which would defeat an operator who lowered it.
pub fn parse_max_body_bytes(value: Option<&str>) -> Result<usize, String> {
    match value {
        None => Ok(DEFAULT_MAX_BODY_BYTES),
        Some(s) => match s.trim().parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!(
                "PROMTECT_MAX_BODY_BYTES must be a positive integer (got {s:?})"
            )),
        },
    }
}

/// Parse a port env var (`PROMTECT_PORT`, `PROMTECT_DASHBOARD_PORT`). Unset → the
/// given default. A present-but-invalid value (non-numeric, out of range, or 0)
/// is an error — we fail closed rather than silently binding the default port,
/// which would leave the operator pointing tools at the wrong place. `var_name` is
/// used only for the error message.
pub fn parse_port(var_name: &str, value: Option<&str>, default: u16) -> Result<u16, String> {
    match value {
        None => Ok(default),
        Some(s) => match s.trim().parse::<u16>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!("{var_name} must be an integer 1-65535 (got {s:?})")),
        },
    }
}

async fn handle(State(ctx): State<Ctx>, req: Request) -> Response {
    ctx.requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    // INVARIANT: one vault per request. The same vault masks the outbound body
    // and restores the inbound response, so only sentinels minted *for this
    // request* can ever be expanded back into a secret — no cross-request bleed.
    // Held in an `Arc` so it can move into the response stream, which the server
    // polls after this handler returns.
    let vault = Arc::new(Vault::new());

    // Scan the body only when it is genuinely text. We decide this from the ACTUAL
    // bytes (valid UTF-8?), NOT the client-declared `Content-Type` — otherwise a
    // request could bypass masking and leak a secret simply by mislabelling a JSON
    // body as `application/octet-stream`. A body that is not valid UTF-8 is binary
    // (or mislabelled binary) and is forwarded byte-for-byte, so the proxy never
    // corrupts it by lossy conversion or a mistaken substitution.
    let forward_bytes = match std::str::from_utf8(&body_bytes) {
        Ok(text) => {
            // Mask request body content. Auth headers forwarded untouched in forward().
            let masked = mask_text(text, &vault, &ctx.audit, &request_id);

            // Second detect pass for the per-request summary (cheap; same input).
            // Secret values are never included in the summary.
            let hits = detect::detect(text);
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
        }
        Err(_) => {
            // Non-UTF-8 (binary) body: forward unscanned, but record it as traffic
            // (zero secrets) so the request still appears in metrics.
            ctx.audit
                .record_request(&request_id, 0, &[], body_bytes.len(), body_bytes.len());
            body_bytes.to_vec()
        }
    };

    match forward(&ctx, method, &uri, &headers, forward_bytes).await {
        Ok(r) => restore_response(r, &ctx, vault, request_id).await,
        Err(e) => {
            // Log the detail locally; keep it out of the client-visible body so we
            // don't disclose the upstream host/path to the proxied tool (which may
            // echo or log the response). The error never contains the secret.
            eprintln!("promtect: upstream request failed: {e}");
            text_response(502, "promtect: upstream request failed".to_string())
        }
    }
}

/// Whether a *response* is a known binary/opaque type that must NOT be run
/// through the restorer — lossy UTF-8 handling of a binary body (e.g. an image
/// endpoint) would corrupt it, so it is streamed back byte-for-byte. The default
/// is *not* binary — an absent or unrecognised type is still restored (it only
/// ever re-inserts this request's own sentinels, never a cross-request value).
///
/// Note: the *request* side does NOT use this — masking is decided by actual
/// UTF-8 validity of the body, so a secret cannot bypass masking via a mislabelled
/// `Content-Type` (see `handle`).
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

/// Whether a response carries a non-identity `Content-Encoding` (gzip, br, …). A
/// compressed body must not be run through the restorer (it would scan ciphertext)
/// and must keep its encoding header so the client can decode it.
fn is_compressed(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let s = s.trim();
            !s.is_empty() && !s.eq_ignore_ascii_case("identity")
        })
        .unwrap_or(false)
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
        // reqwest sets Host/Content-Length for the new target and frames the body
        // itself, so forwarding the client's hop-by-hop framing would conflict.
        // accept-encoding is dropped so the upstream replies uncompressed (we scan
        // and restore the plaintext body).
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("transfer-encoding")
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

    // Restore only when enabled, the response is textual, AND it is not
    // compressed. We strip `accept-encoding` outbound so a compliant upstream
    // replies uncompressed; but if one compresses anyway, restoring would scan
    // ciphertext (finding nothing) and then we'd mislabel the body — so a
    // compressed response is streamed through verbatim WITH its content-encoding.
    let will_restore =
        ctx.restore && !is_binary_body(&resp_headers) && !is_compressed(&resp_headers);

    let mut out = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        let n = name.as_str();
        // content-length and transfer-encoding are always dropped: we re-chunk the
        // body and its length changes when sentinels expand to real secrets.
        if n.eq_ignore_ascii_case("content-length") || n.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        // content-encoding is dropped only when we restore (we emit identity
        // plaintext). When passing a compressed body through verbatim we KEEP it so
        // the client can still decode.
        if will_restore && n.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        out = out.header(name.clone(), value.clone());
    }

    // A binary response (e.g. an image endpoint) must stream back byte-for-byte —
    // running it through the restorer would lossily corrupt it. `text/event-stream`
    // is textual, so SSE is restored.
    let body = if will_restore {
        // Transparent mode: restore secrets incrementally as the response
        // streams. SSE answers reach the client token-by-token instead of being
        // buffered whole (the M0 "hang"). The vault moves into the stream, which
        // the server polls after this handler returns.
        let sr = StreamRestorer::new(vault, Arc::clone(&ctx.audit), request_id);
        Body::from_stream(restore_stream(r.bytes_stream().boxed(), sr))
    } else {
        // Strict mode (PROMTECT_RESTORE=false), or a binary/compressed response:
        // never re-insert secrets. Stream the body straight through; the
        // per-request vault is dropped (and its contents zeroized) unused.
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

    #[test]
    fn parse_restore_default_on_and_falsey_off() {
        assert!(super::parse_restore(None));
        assert!(super::parse_restore(Some("true")));
        assert!(super::parse_restore(Some("1")));
        assert!(super::parse_restore(Some("whatever")));
        for falsey in ["0", "false", "no", "off", "FALSE", "  Off "] {
            assert!(
                !super::parse_restore(Some(falsey)),
                "{falsey} should disable"
            );
        }
    }

    #[test]
    fn parse_max_body_bytes_fails_closed() {
        assert_eq!(
            super::parse_max_body_bytes(None).unwrap(),
            super::DEFAULT_MAX_BODY_BYTES
        );
        assert_eq!(super::parse_max_body_bytes(Some(" 1024 ")).unwrap(), 1024);
        // Present-but-invalid or zero must error, not silently default.
        assert!(super::parse_max_body_bytes(Some("0")).is_err());
        assert!(super::parse_max_body_bytes(Some("banana")).is_err());
        assert!(super::parse_max_body_bytes(Some("-5")).is_err());
        assert!(super::parse_max_body_bytes(Some("")).is_err());
    }

    #[test]
    fn parse_port_defaults_and_fails_closed() {
        assert_eq!(super::parse_port("P", None, 8787).unwrap(), 8787);
        assert_eq!(super::parse_port("P", Some(" 9000 "), 8787).unwrap(), 9000);
        // Present-but-invalid (non-numeric, out of range, 0) must error.
        assert!(super::parse_port("P", Some("abc"), 8787).is_err());
        assert!(super::parse_port("P", Some("0"), 8787).is_err());
        assert!(super::parse_port("P", Some("70000"), 8787).is_err());
        // The error names the offending variable.
        assert!(
            super::parse_port("PROMTECT_PORT", Some("x"), 8787)
                .unwrap_err()
                .contains("PROMTECT_PORT")
        );
    }
}
