use std::sync::Arc;

use airlock::{
    audit,
    proxy::{self, Ctx},
};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("selftest") {
        let ok = airlock::mask::selftest();
        println!(
            "airlock selftest: {}",
            if ok {
                "PASS — no leak"
            } else {
                "FAIL — leak detected"
            }
        );
        std::process::exit(if ok { 0 } else { 1 });
    }

    // ── dashboard subcommand ────────────────────────────────────────────────
    // Starts a local, offline HTTP server that exposes the aggregated audit-log
    // metrics three ways: a browser UI at `/`, JSON at `/api/metrics`, and
    // Prometheus text exposition at `/metrics`. The server never receives proxy
    // traffic — it only reads the audit JSONL that the proxy writes.
    if args.get(1).map(|s| s.as_str()) == Some("dashboard") {
        let port: u16 = std::env::var("AIRLOCK_DASHBOARD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8799);
        let bind = std::env::var("AIRLOCK_BIND").unwrap_or_else(|_| "127.0.0.1".into());
        if !airlock::net::is_loopback(&bind) {
            // Off-loopback binds are valid in container deployments, but the
            // operator must understand the exposure risk before doing it.
            eprintln!(
                "WARNING: airlock dashboard binding non-loopback {bind} — the metrics \
                 endpoint will be reachable off-host. Only do this behind trusted network controls."
            );
        }
        let audit_path =
            std::env::var("AIRLOCK_AUDIT").unwrap_or_else(|_| "airlock-audit.jsonl".into());
        let app = airlock::dashboard::app(airlock::dashboard::DashCtx {
            audit_path: std::sync::Arc::new(audit_path.into()),
        });
        let addr = format!("{bind}:{port}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("airlock dashboard: failed to bind {addr}: {e}"));
        println!(
            "airlock dashboard on http://{}:{port}  (UI: /, JSON: /api/metrics, Prometheus: /metrics)",
            if airlock::net::is_loopback(&bind) {
                "127.0.0.1"
            } else {
                bind.as_str()
            }
        );
        axum::serve(listener, app)
            .await
            .expect("airlock dashboard: server error");
        return;
    }

    let port: u16 = std::env::var("AIRLOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8787);
    let upstream =
        std::env::var("AIRLOCK_UPSTREAM").unwrap_or_else(|_| "https://api.anthropic.com".into());
    let audit_path =
        std::env::var("AIRLOCK_AUDIT").unwrap_or_else(|_| "airlock-audit.jsonl".into());

    let ctx = Ctx {
        upstream,
        audit: Arc::new(audit::Audit::to_file(audit_path.into())),
        client: reqwest::Client::new(),
    };

    let app = proxy::app(ctx);
    let bind = std::env::var("AIRLOCK_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{bind}:{port}");
    // Delegate to net::is_loopback so the safety decision is unit-tested in isolation.
    let is_loopback = airlock::net::is_loopback(&bind);
    if !is_loopback {
        eprintln!(
            "WARNING: airlock is binding a non-loopback address ({bind}). This is only safe \
             inside a container whose port is published to 127.0.0.1. Do NOT run this directly \
             on a host network — it would expose your secrets proxy to other machines."
        );
    }
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("airlock: failed to bind {addr}: {e}"));
    let hint = if is_loopback {
        format!("http://{addr}")
    } else {
        format!("http://127.0.0.1:{port}")
    };
    println!("airlock listening on {addr} -> point ANTHROPIC_BASE_URL at {hint}");
    axum::serve(listener, app)
        .await
        .expect("airlock: server error");
}
