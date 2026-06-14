//! Local, offline observability server: the dashboard UI, a JSON metrics API,
//! and a Prometheus `/metrics` endpoint — all derived from the value-free audit log.
//!
//! The server intentionally re-reads and re-aggregates the audit log on every
//! request. This is a deliberate v1 trade-off: audit logs are small (one JSON
//! line per request/mask event), so the overhead is negligible and it avoids any
//! need for background refresh tasks or shared mutable state.
//!
//! Endpoints:
//! - `GET /`              → HTML dashboard (fully offline, no external CDN).
//! - `GET /api/metrics`   → JSON `Metrics` snapshot.
//! - `GET /metrics`       → Prometheus text-exposition format for scraping.

use crate::metrics;
use axum::{
    Router,
    extract::State,
    http::header,
    response::{Html, IntoResponse},
    routing::get,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Shared state for all dashboard handlers: the path to the value-free audit log.
///
/// Wrapped in `Arc` so it is `Clone` + `Send + Sync` across async handler tasks.
/// The path itself is immutable once the server is configured — no interior
/// mutability needed.
#[derive(Clone)]
pub struct DashCtx {
    /// Absolute or relative path to the JSONL audit log produced by
    /// [`crate::audit::Audit`]. A missing file is treated as an empty log
    /// (all-zero metrics), so the dashboard starts cleanly even before the proxy
    /// has handled any requests.
    pub audit_path: Arc<PathBuf>,
}

/// Build the dashboard router.
///
/// Registers three routes on an axum [`Router`] with shared [`DashCtx`] state:
/// - `/`             → [`index`] — the self-contained HTML dashboard.
/// - `/api/metrics`  → [`api_metrics`] — JSON metrics for client-side rendering.
/// - `/metrics`      → [`prometheus`] — Prometheus text-exposition scrape target.
///
/// The returned router is ready to be fed to `axum::serve`.
pub fn app(ctx: DashCtx) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/metrics", get(api_metrics))
        .route("/metrics", get(prometheus))
        .with_state(ctx)
}

/// Serve the static dashboard HTML page.
///
/// The page is embedded at compile time with `include_str!` so the binary is
/// fully self-contained: no runtime file-system access, no CDN, no network.
/// Stage 3 will replace the placeholder HTML with the polished UI.
async fn index() -> Html<&'static str> {
    // SAFETY: include_str! panics at compile time if the path is wrong, so this
    // is guaranteed to be valid UTF-8 at runtime.
    Html(include_str!("../assets/dashboard/index.html"))
}

/// Return all current metrics as JSON.
///
/// Reads and aggregates the audit log on each call. This keeps the handler
/// stateless and always reflects the latest data without requiring a background
/// task. The [`metrics::Metrics`] type derives `Serialize`, so axum's `Json`
/// extractor handles content-type negotiation automatically.
async fn api_metrics(State(ctx): State<DashCtx>) -> impl IntoResponse {
    axum::Json(metrics::aggregate(&ctx.audit_path))
}

/// Return current metrics in Prometheus text-exposition format (version 0.0.4).
///
/// The `Content-Type` header is set explicitly to `text/plain; version=0.0.4` as
/// required by the Prometheus specification so that scrapers can identify the
/// format. Body generation is delegated to [`metrics::Metrics::to_prometheus`].
async fn prometheus(State(ctx): State<DashCtx>) -> impl IntoResponse {
    let body = metrics::aggregate(&ctx.audit_path).to_prometheus();
    // Prometheus requires this exact Content-Type so its client library can
    // negotiate the exposition format; do not change it to `application/text`.
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}
