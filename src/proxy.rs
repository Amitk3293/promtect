// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use crate::audit::Audit;
use crate::detect;
use crate::mask::mask_with_matches;
use crate::stream::{StreamRestorer, observe_stream_errors, restore_stream};
use crate::vault::Vault;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt as _;
use std::sync::Arc;

const STREAM_OUTCOME_HEADER: &str = "promtect-stream-outcome";

/// Default cap on the request body Promtect will buffer in memory before masking.
/// A masking proxy has to read the whole body to scan it, so an unbounded read
/// is a memory-exhaustion vector. 32 MiB comfortably exceeds any real Anthropic
/// request while bounding the blast radius of a hostile or runaway client. The
/// effective limit lives on [`Ctx::max_body_bytes`] so it is both operator-tunable
/// (`PROMTECT_MAX_BODY_BYTES`) and testable without a multi-megabyte fixture.
pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

const UNSUPPORTED_CONTENT_ENCODING_MESSAGE: &str =
    "promtect: unsupported request Content-Encoding; send an identity-encoded body";
const UNSUPPORTED_CONTENT_ENCODING_AUDIT_MARKER: &str = "«unsupported-content-encoding»";

/// Build a plain-text response without ever panicking. Used for Promtect's own
/// error replies (413/415/502), where we fully control status and headers. The
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
/// An extra detection pass composed on top of the core detectors at mask time.
///
/// The public core always leaves this `None` and never depends on anything that
/// sets it. A downstream build (`promtect-pro`) sets it to merge its own
/// detectors (entropy, PII/PCI) into the SAME mask / restore / value-free-audit
/// path. It is a leak-only seam: it can ADD matches, never remove the core's.
pub type ExtraDetector = Arc<dyn Fn(&str) -> Vec<crate::detect::Match> + Send + Sync>;

/// Process-wide "quiet" flag. When set (by `guard`, which wraps a full-screen TUI
/// like Claude Code), routine per-request masking notifications are suppressed so
/// they do not corrupt the tool's terminal. Security warnings (a leak, a blocked
/// request) and the guard end-of-session summary are NOT suppressed.
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Suppress (or restore) routine per-request stderr notifications process-wide.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, std::sync::atomic::Ordering::Relaxed);
}

/// Whether routine notifications are currently suppressed (see [`set_quiet`]).
pub fn is_quiet() -> bool {
    QUIET.load(std::sync::atomic::Ordering::Relaxed)
}

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
    /// Optional extra detection pass (see [`ExtraDetector`]). `None` in the public
    /// core; set by `promtect-pro` to compose its detectors into masking.
    pub extra_detect: Option<ExtraDetector>,
    /// Optional response-side output scan (see [`crate::stream::ResponseScanner`]).
    /// `None` in the public core; set by `promtect-pro` to flag secrets the model
    /// echoes back or generates. Observe-only — never alters the response bytes.
    pub output_scan: Option<crate::stream::ResponseScanner>,
}

/// Whether a detector hit can be masked exactly from the text it inspected.
///
/// Downstream detectors also use deliberately invalid spans as fail-closed
/// control markers when their own runtime bounds are exceeded. Treat every
/// malformed or value-mismatched hit as unmaskable so it can block without
/// spending more CPU on detector passes that cannot make the request safe.
fn match_is_maskable(text: &str, hit: &detect::Match) -> bool {
    hit.start < hit.end
        && hit.end <= text.len()
        && text.is_char_boundary(hit.start)
        && text.is_char_boundary(hit.end)
        && text
            .get(hit.start..hit.end)
            .is_some_and(|value| value == hit.value.as_str())
}

/// Extra (Pro) detectors run before the Core detector set so a bounded
/// downstream pass can reject work before Core scans the complete body. A
/// malformed extra hit is a fail-closed control result: return it immediately
/// and let the request path block without running Core. Valid extra matches are
/// then merged with Core exactly as before.
///
/// `None` still yields exactly the Core detector output. The merged list may
/// overlap — [`mask_with_matches`] coalesces overlaps before masking.
fn compose_matches(text: &str, extra: &Option<ExtraDetector>) -> Vec<detect::Match> {
    let extra_matches = extra.as_ref().map_or_else(Vec::new, |detect| detect(text));
    if extra_matches
        .iter()
        .any(|hit| !match_is_maskable(text, hit))
    {
        return extra_matches;
    }
    // Preserve Core-first merge precedence for overlapping valid spans; only
    // execution order changes so downstream bounds can fail before Core work.
    let mut matches = detect::detect(text);
    matches.extend(extra_matches);
    matches
}

/// Return whether a structurally valid hit is contained by one minted sentinel.
///
/// `minted_sentinel_spans` yields sorted, non-overlapping ranges because it is
/// backed by `Regex::find_iter`. Locate the last sentinel beginning at or before
/// the hit instead of scanning every sentinel for every detector match. This
/// keeps residual filtering O(matches × log(sentinels)) for large paid requests.
fn is_within_minted_sentinel(
    hit_start: usize,
    hit_end: usize,
    sentinel_spans: &[std::ops::Range<usize>],
) -> bool {
    let insertion = sentinel_spans.partition_point(|span| span.start <= hit_start);
    insertion
        .checked_sub(1)
        .and_then(|index| sentinel_spans.get(index))
        .is_some_and(|span| hit_end <= span.end)
}

/// Re-run the exact active request detector chain over a masked body.
///
/// The detector receives the complete masked body, preserving anchored and
/// context-sensitive rule semantics plus original byte offsets. Structurally
/// valid matches wholly contained inside an exact sentinel minted by this
/// request's vault are discarded; malformed matches, unknown sentinel-shaped
/// input, and matches extending outside a minted sentinel remain residual leaks
/// and fail closed. Reusing
/// [`compose_matches`] is the security invariant: a downstream paid or custom
/// detector cannot participate in masking while being omitted from the final
/// residual check.
fn scan_for_residual_leaks(
    masked: &str,
    extra: &Option<ExtraDetector>,
    vault: &Vault,
) -> Vec<detect::Match> {
    let sentinel_spans: Vec<_> = crate::mask::minted_sentinel_spans(masked, vault).collect();
    compose_matches(masked, extra)
        .into_iter()
        .filter(|hit| {
            let has_exact_span = hit.start < hit.end
                && masked
                    .get(hit.start..hit.end)
                    .is_some_and(|value| value == hit.value.as_str());
            let is_minted_sentinel_content =
                has_exact_span && is_within_minted_sentinel(hit.start, hit.end, &sentinel_spans);
            !is_minted_sentinel_content
        })
        .collect()
}

enum PreparedBody {
    Forward(Vec<u8>),
    Block(Response),
}

fn residual_block_response(
    ctx: &Ctx,
    request_id: &str,
    hit_count: usize,
    request_kinds: &[&str],
    body_len: usize,
    masked_len: usize,
    leaks: &[detect::Match],
) -> Response {
    let leak_kinds: Vec<&str> = {
        let mut kinds: Vec<&str> = leaks.iter().map(|hit| hit.kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    };
    eprintln!(
        "[promtect] ⚠️  LEAK req {}: {} pattern{} may not be masked ({}) \
         — request blocked",
        &request_id[..8],
        leaks.len(),
        if leaks.len() == 1 { "" } else { "s" },
        leak_kinds.join(", ")
    );
    ctx.audit
        .record_request(request_id, hit_count, request_kinds, body_len, masked_len);
    ctx.audit.record(
        "request_blocked",
        "residual_secret",
        "«residual-secret»",
        request_id,
    );
    text_response(
        400,
        format!(
            "promtect: {} secret pattern{} not masked before forwarding ({})",
            leaks.len(),
            if leaks.len() == 1 { "" } else { "s" },
            leak_kinds.join(", ")
        ),
    )
}

/// Perform UTF-8 validation, detection, masking, and the residual scan away from
/// Tokio's async workers. Detector regexes are synchronous and may inspect the
/// complete configured body limit; running them on an async worker can prevent
/// unrelated connections, timers, and shutdown from being polled.
fn prepare_body(body_bytes: Bytes, ctx: &Ctx, vault: &Vault, request_id: &str) -> PreparedBody {
    let text = match std::str::from_utf8(&body_bytes) {
        Ok(text) => text,
        Err(_) => {
            ctx.audit
                .record_request(request_id, 0, &[], body_bytes.len(), body_bytes.len());
            return PreparedBody::Forward(body_bytes.to_vec());
        }
    };

    let matches = compose_matches(text, &ctx.extra_detect);
    let hit_count = matches.len();
    let mut kinds: Vec<&str> = matches.iter().map(|hit| hit.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();

    // Invalid downstream spans are fail-closed control results. Block them
    // immediately, before copying/masking the body or running Core and residual
    // detector passes. This is how a bounded Pro rulebook rejects excess work.
    if matches.iter().any(|hit| !match_is_maskable(text, hit)) {
        return PreparedBody::Block(residual_block_response(
            ctx,
            request_id,
            hit_count,
            &kinds,
            body_bytes.len(),
            body_bytes.len(),
            &matches,
        ));
    }

    let masked = mask_with_matches(text, matches, vault, &ctx.audit, request_id);
    if hit_count > 0 && !is_quiet() {
        eprintln!(
            "[promtect] req {}: masked {} secret{} ({})",
            &request_id[..8],
            hit_count,
            if hit_count == 1 { "" } else { "s" },
            kinds.join(", ")
        );
    }

    if hit_count > 0 {
        let leaks = scan_for_residual_leaks(&masked, &ctx.extra_detect, vault);
        if !leaks.is_empty() {
            return PreparedBody::Block(residual_block_response(
                ctx,
                request_id,
                hit_count,
                &kinds,
                body_bytes.len(),
                masked.len(),
                &leaks,
            ));
        }
    }

    ctx.audit.record_request(
        request_id,
        hit_count,
        &kinds,
        body_bytes.len(),
        masked.len(),
    );
    PreparedBody::Forward(masked.into_bytes())
}

async fn prepare_body_async(
    body_bytes: Bytes,
    ctx: Ctx,
    vault: Arc<Vault>,
    request_id: String,
) -> Result<PreparedBody, tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || prepare_body(body_bytes, &ctx, &vault, &request_id)).await
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
        // Ollama Cloud: ollama.com acts as a remote Ollama host (native /api paths,
        // OLLAMA_API_KEY Bearer auth). This is the high-value masking case — unlike
        // local ollama, the prompt leaves the user's machine.
        Some("ollama-cloud") => Ok("https://ollama.com".to_string()),
        Some("openrouter") => Ok("https://openrouter.ai".to_string()),
        Some(other) => Err(format!(
            "unknown PROMTECT_MODE '{other}' \
             (expected anthropic|openai|ollama|ollama-cloud|openrouter); \
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

/// Resolves when SIGINT (Ctrl-C) or, on Unix, SIGTERM is received.
///
/// Pass this as the `with_graceful_shutdown` future on every `axum::serve`
/// call so both signal types trigger a clean connection drain. A failure to
/// register a signal handler is intentionally ignored: the process can still
/// be killed externally, and a missing handler must never block the masking
/// path (fail-open on auxiliary infrastructure).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

async fn handle(State(ctx): State<Ctx>, req: Request) -> Response {
    ctx.requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let request_id = uuid::Uuid::new_v4().to_string();
    let headers = req.headers().clone();

    // SECURITY: reject compressed or malformed request bodies using headers only,
    // before reading the body or constructing any upstream request. Promtect cannot
    // safely scan encoded bytes, and forwarding them unscanned would leak secrets.
    if !request_content_encoding_is_supported(&headers) {
        ctx.audit.record_blocked_request(&request_id);
        ctx.audit.record(
            "request_rejected",
            "content_encoding",
            UNSUPPORTED_CONTENT_ENCODING_AUDIT_MARKER,
            &request_id,
        );
        eprintln!(
            "[promtect] req {}: rejected unsupported request Content-Encoding",
            &request_id[..8]
        );
        return text_response(415, UNSUPPORTED_CONTENT_ENCODING_MESSAGE);
    }

    let method = req.method().clone();
    let uri = req.uri().clone();

    // Buffer the body with a hard cap. `to_bytes` returns Err once the stream
    // exceeds the limit, so we refuse oversized bodies with 413 instead of
    // silently forwarding an empty/truncated one (the old `.unwrap_or_default()`
    // behaviour) or buffering without bound.
    let body_bytes = match axum::body::to_bytes(req.into_body(), ctx.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            ctx.audit.record_blocked_request(&request_id);
            ctx.audit.record(
                "request_blocked",
                "body_limit",
                "«request-body-rejected»",
                &request_id,
            );
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
    let prepared = prepare_body_async(
        body_bytes,
        ctx.clone(),
        Arc::clone(&vault),
        request_id.clone(),
    )
    .await;
    let forward_bytes = match prepared {
        Ok(PreparedBody::Forward(bytes)) => bytes,
        Ok(PreparedBody::Block(response)) => return response,
        Err(error) => {
            // A blocking detector task can fail only if it panics or the runtime
            // shuts down. Either case fails closed and remains value-free.
            eprintln!("promtect: request scanning task failed: {error}");
            ctx.audit.record_blocked_request(&request_id);
            ctx.audit.record(
                "request_blocked",
                "scan_failure",
                "«request-scan-failed»",
                &request_id,
            );
            return text_response(500, "promtect: request scanning failed");
        }
    };

    match forward(&ctx, method, &uri, &headers, forward_bytes).await {
        Ok(r) => restore_response(r, &ctx, vault, request_id).await,
        Err(e) => {
            // Log the detail locally; keep it out of the client-visible body so we
            // don't disclose the upstream host/path to the proxied tool (which may
            // echo or log the response). The error never contains the secret.
            eprintln!("promtect: upstream request failed: {e}");
            ctx.audit.record(
                "request_failed",
                "upstream",
                "«upstream-request-failed»",
                &request_id,
            );
            text_response(502, "promtect: upstream request failed".to_string())
        }
    }
}

/// Whether every request `Content-Encoding` value is a non-empty, identity-only
/// coding list. An absent header is supported. Malformed bytes, empty tokens,
/// unknown codings, and any non-identity coding fail closed.
fn request_content_encoding_is_supported(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::CONTENT_ENCODING)
        .iter()
        .all(|value| {
            let Ok(value) = value.to_str() else {
                return false;
            };
            value.split(',').all(|coding| {
                let coding = coding.trim();
                !coding.is_empty() && coding.eq_ignore_ascii_case("identity")
            })
        })
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
    let source = if will_restore {
        // Transparent mode: restore secrets incrementally as the response
        // streams. SSE answers reach the client token-by-token instead of being
        // buffered whole (the M0 "hang"). The vault moves into the stream, which
        // the server polls after this handler returns.
        let sr = StreamRestorer::new(vault, Arc::clone(&ctx.audit), request_id.clone())
            .with_output_scanner(ctx.output_scan.clone());
        restore_stream(r.bytes_stream().boxed(), sr).boxed()
    } else {
        // Strict mode (PROMTECT_RESTORE=false), or a binary/compressed response:
        // never re-insert secrets. Stream the body straight through; the
        // per-request vault is dropped (and its contents zeroized) unused.
        drop(vault);
        r.bytes_stream().boxed()
    };

    let audit = Arc::clone(&ctx.audit);
    let outcome_request_id = request_id.clone();
    let (observed, outcome) = observe_stream_errors(source, audit, outcome_request_id);
    let body = Body::from_stream(observed).with_trailers(async move {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            STREAM_OUTCOME_HEADER,
            if outcome.was_interrupted() {
                axum::http::HeaderValue::from_static("interrupted")
            } else {
                axum::http::HeaderValue::from_static("complete")
            },
        );
        Some(Ok::<_, axum::Error>(trailers))
    });
    out = out.header("trailer", STREAM_OUTCOME_HEADER);

    // Status and headers come from an already-parsed upstream response, so this
    // build cannot realistically fail; fall back to a clean 502 rather than panic.
    out.body(Body::new(body))
        .unwrap_or_else(|_| text_response(502, "promtect: could not assemble upstream response"))
}

#[cfg(test)]
mod tests {
    use super::resolve_upstream;
    use super::{is_quiet, set_quiet};

    fn headers_with_content_encoding(value: &'static str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_ENCODING,
            axum::http::HeaderValue::from_static(value),
        );
        headers
    }

    #[test]
    fn request_content_encoding_accepts_absent_header() {
        assert!(super::request_content_encoding_is_supported(
            &axum::http::HeaderMap::new()
        ));
    }

    #[test]
    fn request_content_encoding_accepts_identity_with_case_and_whitespace() {
        for value in ["identity", "IdEnTiTy", "identity , identity"] {
            assert!(
                super::request_content_encoding_is_supported(&headers_with_content_encoding(value)),
                "{value:?} should be accepted"
            );
        }
    }

    #[test]
    fn request_content_encoding_rejects_every_non_identity_coding() {
        for value in [
            "gzip",
            "deflate",
            "br",
            "zstd",
            "snappy",
            "gzip, br",
            "identity, gzip",
            "GzIp",
            "gzip , br",
        ] {
            assert!(
                !super::request_content_encoding_is_supported(&headers_with_content_encoding(
                    value
                )),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn request_content_encoding_rejects_empty_or_malformed_lists() {
        for value in ["", " ", ",", "identity,", ",identity"] {
            assert!(
                !super::request_content_encoding_is_supported(&headers_with_content_encoding(
                    value
                )),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn request_content_encoding_rejects_when_any_repeated_header_is_non_identity() {
        let mut headers = headers_with_content_encoding("identity");
        headers.append(
            axum::http::header::CONTENT_ENCODING,
            axum::http::HeaderValue::from_static("br"),
        );

        assert!(!super::request_content_encoding_is_supported(&headers));
    }

    #[test]
    fn request_content_encoding_rejects_non_utf8_header_value() {
        let mut headers = axum::http::HeaderMap::new();
        let value = axum::http::HeaderValue::from_bytes(b"\xff")
            .expect("opaque non-UTF-8 header bytes are valid HeaderValue data");
        assert!(value.to_str().is_err(), "test value must be non-UTF-8");
        headers.insert(axum::http::header::CONTENT_ENCODING, value);

        assert!(!super::request_content_encoding_is_supported(&headers));
    }

    #[test]
    fn quiet_flag_round_trips() {
        set_quiet(true);
        assert!(is_quiet(), "quiet should be on after set_quiet(true)");
        set_quiet(false);
        assert!(!is_quiet(), "quiet should be off after set_quiet(false)");
    }

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
            resolve_upstream(Some("ollama-cloud"), None).unwrap(),
            "https://ollama.com"
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

    /// The composition seam: `compose_matches` returns exactly the core's detect()
    /// output when there is no extra pass, and merges an extra (Pro) pass on top
    /// when one is set. This is how the proxy injects promtect-pro's detectors.
    #[test]
    fn compose_matches_merges_extra_pass() {
        let text = "key AKIAIOSFODNN7EXAMPLE and CUSTOMSECRET here";
        let base = super::detect::detect(text).len();

        // None -> exactly the core detectors (public-proxy behavior is unchanged).
        assert_eq!(super::compose_matches(text, &None).len(), base);

        // An extra pass adds its own matches on top of the core's.
        let extra: super::ExtraDetector = std::sync::Arc::new(|t: &str| {
            t.find("CUSTOMSECRET")
                .map(|i| {
                    vec![super::detect::Match::new(
                        "custom",
                        "CUSTOMSECRET".to_string(),
                        i,
                        i + "CUSTOMSECRET".len(),
                    )]
                })
                .unwrap_or_default()
        });
        let composed = super::compose_matches(text, &Some(extra));
        assert_eq!(composed.len(), base + 1);
        assert!(composed.iter().any(|m| m.kind == "custom"));
    }

    #[test]
    fn compose_matches_short_circuits_core_for_an_unmaskable_extra_result() {
        let text = "AKIAIOSFODNN7EXAMPLE followed by a bounded detector failure";
        let extra: super::ExtraDetector = std::sync::Arc::new(|_| {
            vec![super::detect::Match::new(
                "rulebook_scan_limit",
                String::new(),
                usize::MAX,
                usize::MAX,
            )]
        });

        let composed = super::compose_matches(text, &Some(extra));

        assert_eq!(composed.len(), 1);
        assert_eq!(composed[0].kind, "rulebook_scan_limit");
        assert!(
            !composed.iter().any(|hit| hit.kind == "aws_key"),
            "Core must not scan after a downstream detector fails closed"
        );
    }

    #[tokio::test]
    async fn synchronous_detector_work_does_not_block_the_async_runtime() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::time::Duration;

        let started = Arc::new(AtomicBool::new(false));
        let started_for_detector = Arc::clone(&started);
        let extra: super::ExtraDetector = Arc::new(move |_| {
            started_for_detector.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Vec::new()
        });
        let ctx = super::Ctx {
            upstream: "http://127.0.0.1:1".to_owned(),
            audit: Arc::new(crate::audit::Audit::null()),
            client: reqwest::Client::new(),
            max_body_bytes: super::DEFAULT_MAX_BODY_BYTES,
            restore: true,
            requests: Arc::new(AtomicU64::new(0)),
            extra_detect: Some(extra),
            output_scan: None,
        };
        let prepare = super::prepare_body_async(
            bytes::Bytes::from_static(b"ordinary text"),
            ctx,
            Arc::new(crate::vault::Vault::new()),
            "test-request".to_owned(),
        );
        let heartbeat = async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let (heartbeat, prepared) = tokio::join!(
            tokio::time::timeout(Duration::from_millis(100), heartbeat),
            prepare
        );

        assert!(
            heartbeat.is_ok(),
            "the async timer must run while synchronous detection is active"
        );
        assert!(matches!(prepared, Ok(super::PreparedBody::Forward(_))));
    }

    #[test]
    fn residual_scan_reuses_extra_detector_after_masking_skips_a_bad_span() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let text = "payload CUSTOMSECRET";
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_detector = Arc::clone(&calls);
        let extra: super::ExtraDetector = Arc::new(move |candidate: &str| {
            let Some(start) = candidate.find("CUSTOMSECRET") else {
                return Vec::new();
            };
            let end = if calls_for_detector.fetch_add(1, Ordering::SeqCst) == 0 {
                candidate.len() + 1
            } else {
                start + "CUSTOMSECRET".len()
            };
            vec![super::detect::Match::new(
                "custom",
                "CUSTOMSECRET".to_owned(),
                start,
                end,
            )]
        });
        let active = Some(extra);
        let vault = crate::vault::Vault::new();
        let masked = crate::mask::mask_with_matches(
            text,
            super::compose_matches(text, &active),
            &vault,
            &crate::audit::Audit::null(),
            "request",
        );

        assert!(
            masked.contains("CUSTOMSECRET"),
            "the deliberately invalid first span must survive masking"
        );
        let leaks = super::scan_for_residual_leaks(&masked, &active, &vault);
        assert!(
            leaks.iter().any(|hit| hit.kind == "custom"),
            "the active extra detector must inspect and catch the residual canary"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn residual_scan_without_extra_remains_core_only() {
        let vault = crate::vault::Vault::new();
        let leaks =
            super::scan_for_residual_leaks("AKIAIOSFODNN7EXAMPLE and CUSTOMSECRET", &None, &vault);

        assert!(leaks.iter().any(|hit| hit.kind == "aws_key"));
        assert!(!leaks.iter().any(|hit| hit.kind == "custom"));
    }

    #[test]
    fn residual_scan_does_not_manufacture_matches_for_custom_rules() {
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            ["CUSTOMSECRET", "promtect"]
                .into_iter()
                .filter_map(|needle| {
                    candidate.find(needle).map(|start| {
                        super::detect::Match::new(
                            "custom",
                            needle.to_owned(),
                            start,
                            start + needle.len(),
                        )
                    })
                })
                .collect()
        });
        let active = Some(detector);
        let vault = crate::vault::Vault::new();
        let masked = crate::mask::mask_with_matches(
            "payload CUSTOMSECRET",
            super::compose_matches("payload CUSTOMSECRET", &active),
            &vault,
            &crate::audit::Audit::null(),
            "request",
        );

        assert!(masked.contains("«promtect:custom:"));
        assert!(
            super::scan_for_residual_leaks(&masked, &active, &vault).is_empty(),
            "custom matches wholly inside sentinel syntax must not become residual leaks"
        );
    }

    #[test]
    fn minted_span_binary_lookup_matches_linear_oracle_at_scale() {
        let spans: Vec<std::ops::Range<usize>> = (0..10_000)
            .map(|index| {
                let start = index * 64;
                start..start + 48
            })
            .collect();

        let mut hits = Vec::with_capacity(spans.len() * 3 + 2);
        for span in &spans {
            hits.push((span.start, span.end));
            hits.push((span.start + 7, span.end - 7));
            hits.push((span.end - 1, span.end + 1));
        }
        hits.push((0, 0));
        hits.push((spans.last().unwrap().end + 1, spans.last().unwrap().end + 2));

        for (start, end) in hits {
            let expected = spans
                .iter()
                .any(|span| span.start <= start && end <= span.end);
            assert_eq!(
                super::is_within_minted_sentinel(start, end, &spans),
                expected,
                "binary containment disagreed for {start}..{end}"
            );
        }
    }

    #[test]
    fn residual_scan_suppresses_many_request_minted_sentinel_matches() {
        let vault = crate::vault::Vault::new();
        let masked = (0..1_024)
            .map(|index| vault.sentinel_for("custom", &format!("secret-{index}")))
            .collect::<Vec<_>>()
            .join(" ");
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            candidate
                .match_indices("promtect")
                .map(|(start, value)| {
                    super::detect::Match::new(
                        "custom",
                        value.to_owned(),
                        start,
                        start + value.len(),
                    )
                })
                .collect()
        });

        assert!(
            super::scan_for_residual_leaks(&masked, &Some(detector), &vault).is_empty(),
            "matches wholly inside every request-minted sentinel must be suppressed"
        );
    }

    #[test]
    fn residual_scan_preserves_whole_body_context_across_a_sentinel() {
        let vault = crate::vault::Vault::new();
        let sentinel = vault.sentinel_for("custom", "masked_secret");
        let masked = format!("BEGIN {sentinel} residual_secret END");
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            if !candidate.starts_with("BEGIN ") || !candidate.ends_with(" END") {
                return Vec::new();
            }
            let Some(start) = candidate.find("residual_secret") else {
                return Vec::new();
            };
            vec![super::detect::Match::new(
                "context_rule",
                "residual_secret".to_owned(),
                start,
                start + "residual_secret".len(),
            )]
        });

        let leaks = super::scan_for_residual_leaks(&masked, &Some(detector), &vault);

        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].kind, "context_rule");
        assert_eq!(leaks[0].value.as_str(), "residual_secret");
    }

    #[test]
    fn residual_scan_does_not_create_artificial_fragment_anchors() {
        let vault = crate::vault::Vault::new();
        let sentinel = vault.sentinel_for("custom", "masked_secret");
        let masked = format!("prefix {sentinel} anchored_tail");
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            if candidate.strip_prefix(" anchored_tail").is_none() {
                return Vec::new();
            }
            vec![super::detect::Match::new(
                "anchored_rule",
                "anchored_tail".to_owned(),
                1,
                candidate.len(),
            )]
        });

        assert!(
            super::scan_for_residual_leaks(&masked, &Some(detector), &vault).is_empty(),
            "a tail fragment must not be presented to a rule as a new full input"
        );
    }

    #[test]
    fn residual_scan_blocks_a_match_partially_overlapping_a_minted_sentinel() {
        let vault = crate::vault::Vault::new();
        let sentinel = vault.sentinel_for("custom", "masked_secret");
        let masked = format!("prefix {sentinel} residual_tail");
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            let Some(start) = candidate.find("promtect") else {
                return Vec::new();
            };
            let end = candidate.len();
            vec![super::detect::Match::new(
                "overlap_rule",
                candidate[start..end].to_owned(),
                start,
                end,
            )]
        });

        let leaks = super::scan_for_residual_leaks(&masked, &Some(detector), &vault);

        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].kind, "overlap_rule");
    }

    #[test]
    fn residual_scan_does_not_trust_user_supplied_sentinel_shapes() {
        let vault = crate::vault::Vault::new();
        let masked = "prefix «promtect:custom:0000» suffix";
        let detector: super::ExtraDetector = std::sync::Arc::new(|candidate: &str| {
            let Some(start) = candidate.find("promtect") else {
                return Vec::new();
            };
            vec![super::detect::Match::new(
                "sentinel_shape_rule",
                "promtect".to_owned(),
                start,
                start + "promtect".len(),
            )]
        });

        let leaks = super::scan_for_residual_leaks(masked, &Some(detector), &vault);

        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].kind, "sentinel_shape_rule");
    }
}
