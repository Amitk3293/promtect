// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Local, offline observability server: the dashboard UI, a JSON metrics API,
//! and a Prometheus `/metrics` endpoint — all derived from the value-free audit log.
//!
//! The server re-reads a bounded snapshot of the audit log on every metrics
//! request. File and JSON work runs in Tokio's blocking pool behind per-dashboard
//! admission control, avoiding both executor stalls and unbounded blocking jobs.
//!
//! Endpoints:
//! - `GET /`              → HTML dashboard (fully offline, no external CDN).
//! - `GET /api/metrics`   → JSON `Metrics` snapshot.
//! - `GET /metrics`       → Prometheus text-exposition format for scraping.

use crate::metrics;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

/// Dashboard polling must not fan out an unbounded number of blocking file
/// scans. Two permits allow the JSON UI and a Prometheus scraper to refresh at
/// the same time; excess polls receive an explicit value-free HTTP 503.
const MAX_CONCURRENT_AGGREGATIONS: usize = 2;

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
    /// Actual response restoration mode of the proxy this dashboard describes.
    /// `false` is strict mode and must never be rendered as restore-on.
    pub restore_enabled: bool,
}

#[derive(Clone)]
struct DashState {
    ctx: DashCtx,
    aggregation_permits: Arc<tokio::sync::Semaphore>,
}

#[derive(Serialize)]
struct DashboardMetrics {
    #[serde(flatten)]
    metrics: metrics::Metrics,
    restore_enabled: bool,
}

#[derive(Serialize)]
struct MetricsUnavailable {
    error: &'static str,
}

#[derive(Debug)]
enum AggregationError {
    Busy,
    Failed,
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
    let state = DashState {
        ctx,
        aggregation_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_AGGREGATIONS)),
    };
    Router::new()
        .route("/", get(index))
        .route("/api/metrics", get(api_metrics))
        .route("/metrics", get(prometheus))
        .with_state(state)
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
async fn api_metrics(State(state): State<DashState>) -> Response {
    match aggregate_off_thread(state.ctx.audit_path, Arc::clone(&state.aggregation_permits)).await {
        Ok(metrics) => axum::Json(DashboardMetrics {
            metrics,
            restore_enabled: state.ctx.restore_enabled,
        })
        .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(MetricsUnavailable {
                error: "metrics temporarily unavailable",
            }),
        )
            .into_response(),
    }
}

/// Return current metrics in Prometheus text-exposition format (version 0.0.4).
///
/// The `Content-Type` header is set explicitly to `text/plain; version=0.0.4` as
/// required by the Prometheus specification so that scrapers can identify the
/// format. Body generation is delegated to [`metrics::Metrics::to_prometheus`].
async fn prometheus(State(state): State<DashState>) -> Response {
    match aggregate_off_thread(state.ctx.audit_path, state.aggregation_permits).await {
        Ok(metrics) => (
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            metrics.to_prometheus(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "promtect metrics temporarily unavailable\n",
        )
            .into_response(),
    }
}

async fn aggregate_off_thread(
    audit_path: Arc<PathBuf>,
    permits: Arc<tokio::sync::Semaphore>,
) -> Result<metrics::Metrics, AggregationError> {
    // `spawn_blocking` tasks cannot be aborted once started. Acquire without
    // waiting before spawning so repeated polls cannot create an unbounded queue
    // in Tokio's blocking pool.
    let Ok(permit) = permits.try_acquire_owned() else {
        return Err(AggregationError::Busy);
    };

    run_aggregation_task(permit, move || metrics::aggregate(&audit_path)).await
}

async fn run_aggregation_task<F>(
    permit: tokio::sync::OwnedSemaphorePermit,
    task: F,
) -> Result<metrics::Metrics, AggregationError>
where
    F: FnOnce() -> metrics::Metrics + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task()
    })
    .await
    {
        Ok(metrics) => Ok(metrics),
        // A runtime shutdown or panic must not expose file contents or crash the
        // dashboard. The handler reports explicit unavailability instead of a
        // false all-zero snapshot.
        Err(_) => Err(AggregationError::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn busy_aggregation_returns_explicit_unavailability_without_queueing() {
        let no_permits = Arc::new(tokio::sync::Semaphore::new(0));
        let missing = Arc::new(std::path::PathBuf::from("/not/read/when/busy"));

        let result = aggregate_off_thread(missing, no_permits).await;

        assert!(matches!(result, Err(AggregationError::Busy)));
    }

    #[tokio::test]
    async fn blocking_task_failure_is_explicit_unavailability() {
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = permits.try_acquire_owned().unwrap();

        let result = run_aggregation_task(permit, || panic!("synthetic task failure")).await;

        assert!(matches!(result, Err(AggregationError::Failed)));
    }

    #[tokio::test]
    async fn busy_api_never_renders_a_false_clean_snapshot() {
        let state = DashState {
            ctx: DashCtx {
                audit_path: Arc::new(PathBuf::from("/not/read/when/busy")),
                restore_enabled: true,
            },
            aggregation_permits: Arc::new(tokio::sync::Semaphore::new(0)),
        };

        let response = api_metrics(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("metrics temporarily unavailable"));
        assert!(!body.contains("requests_clean"));
        assert!(!body.contains("requests_total"));
    }
}
