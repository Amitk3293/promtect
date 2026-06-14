use std::sync::Arc;

use promtect::{
    audit,
    proxy::{self, Ctx},
};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("selftest") {
        let ok = promtect::mask::selftest();
        println!(
            "promtect selftest: {}",
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
        let port: u16 = std::env::var("PROMTECT_DASHBOARD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8799);
        let bind = std::env::var("PROMTECT_BIND").unwrap_or_else(|_| "127.0.0.1".into());
        if !promtect::net::is_loopback(&bind) {
            // Off-loopback binds are valid in container deployments, but the
            // operator must understand the exposure risk before doing it.
            eprintln!(
                "WARNING: promtect dashboard binding non-loopback {bind} — the metrics \
                 endpoint will be reachable off-host. Only do this behind trusted network controls."
            );
        }
        let audit_path =
            std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());
        let app = promtect::dashboard::app(promtect::dashboard::DashCtx {
            audit_path: std::sync::Arc::new(audit_path.into()),
        });
        let addr = format!("{bind}:{port}");
        // Graceful exit (not a panic/backtrace) when the port is taken — a common,
        // recoverable misconfiguration deserves a clear message, not a crash.
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "promtect dashboard: cannot bind {addr} ({e}).\n\
                     That port is already in use — set PROMTECT_DASHBOARD_PORT to a free port and retry."
                );
                std::process::exit(1);
            }
        };
        println!(
            "promtect dashboard on http://{}:{port}  (UI: /, JSON: /api/metrics, Prometheus: /metrics)",
            if promtect::net::is_loopback(&bind) {
                "127.0.0.1"
            } else {
                bind.as_str()
            }
        );
        axum::serve(listener, app)
            .await
            .expect("promtect dashboard: server error");
        return;
    }

    let port: u16 = std::env::var("PROMTECT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8787);
    // Upstream selection: PROMTECT_UPSTREAM (explicit override / chaining knob)
    // wins; otherwise PROMTECT_MODE picks a known provider; default Anthropic.
    let mode = std::env::var("PROMTECT_MODE").ok();
    let upstream_override = std::env::var("PROMTECT_UPSTREAM").ok();
    let upstream = match proxy::resolve_upstream(mode.as_deref(), upstream_override.as_deref()) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("promtect: {e}");
            std::process::exit(1);
        }
    };
    let audit_path =
        std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());

    // Operator-tunable body cap; defaults to 32 MiB. Bounds the memory a single
    // request can force Promtect to buffer while scanning for secrets. Fail closed
    // on a present-but-invalid value (or 0) rather than silently reverting to the
    // default — an operator who lowered the cap shouldn't get the large default
    // because of a typo, and 0 would reject every request.
    let max_body_bytes: usize = match std::env::var("PROMTECT_MAX_BODY_BYTES") {
        Err(_) => proxy::DEFAULT_MAX_BODY_BYTES,
        Ok(s) => match s.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!(
                    "promtect: PROMTECT_MAX_BODY_BYTES must be a positive integer (got {s:?})"
                );
                std::process::exit(1);
            }
        },
    };

    // Restore real secrets in the response (transparent mode) by default. Set
    // PROMTECT_RESTORE to a falsey value for strict mode, where the masked body
    // is forwarded verbatim and secrets never re-enter the response.
    let restore = std::env::var("PROMTECT_RESTORE")
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true);

    let upstream_for_log = upstream.clone();
    let ctx = Ctx {
        upstream,
        audit: Arc::new(audit::Audit::to_file(audit_path.into())),
        client: reqwest::Client::new(),
        max_body_bytes,
        restore,
    };

    let app = proxy::app(ctx);
    let bind = std::env::var("PROMTECT_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{bind}:{port}");
    // Delegate to net::is_loopback so the safety decision is unit-tested in isolation.
    let is_loopback = promtect::net::is_loopback(&bind);
    if !is_loopback {
        eprintln!(
            "WARNING: promtect is binding a non-loopback address ({bind}). This is only safe \
             inside a container whose port is published to 127.0.0.1. Do NOT run this directly \
             on a host network — it would expose your secrets proxy to other machines."
        );
    }
    // Graceful exit (not a panic/backtrace) when the port is taken.
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "promtect: cannot bind {addr} ({e}).\n\
                 That port is already in use — set PROMTECT_PORT to a free port and retry."
            );
            std::process::exit(1);
        }
    };
    let hint = if is_loopback {
        format!("http://{addr}")
    } else {
        format!("http://127.0.0.1:{port}")
    };
    let restore_note = if restore {
        ""
    } else {
        "  [strict: restore off]"
    };
    println!(
        "promtect listening on {addr} (upstream: {upstream_for_log}){restore_note}\n  point your tool's base URL at {hint}"
    );
    axum::serve(listener, app)
        .await
        .expect("promtect: server error");
}
