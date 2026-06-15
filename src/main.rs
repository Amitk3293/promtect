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

    // ── mask subcommand ─────────────────────────────────────────────────────
    // Pipe any text in, see exactly what Promtect would hide before it reaches
    // the model. Reads stdin, replaces every detected secret with its sentinel,
    // and writes the masked text to stdout. Pure local — no network, no audit
    // file, no restore. Handy for "what would this leak?" checks:
    //   echo 'deploy with AKIA...' | promtect mask
    //   cat .env | promtect mask
    if args.get(1).map(|s| s.as_str()) == Some("mask") {
        use std::io::{Read, Write};
        let mut input = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut input) {
            eprintln!("promtect mask: cannot read stdin ({e})");
            std::process::exit(1);
        }
        // Throwaway vault/audit: masking is one-way here, so neither the sentinel
        // map nor an audit trail needs to outlive the call.
        let vault = promtect::vault::Vault::new();
        let masked =
            promtect::mask::mask_text(&input, &vault, &promtect::audit::Audit::null(), "mask");
        print!("{masked}");
        std::io::stdout().flush().ok();
        return;
    }

    // ── guard subcommand ────────────────────────────────────────────────────
    // One-command protected session: start an ephemeral proxy, point the tool at
    // it, run the tool with the user's args, tear down on exit.
    //   promtect guard claude
    //   promtect guard codex "fix the s3 upload"
    //   promtect guard ollama run deepseek-r1
    //   promtect guard claude --headroom
    if args.get(1).map(|s| s.as_str()) == Some("guard") {
        match promtect::guard::plan_guard(&args[2..]) {
            Ok(plan) => std::process::exit(promtect::guard::guard(plan).await),
            Err(e) => {
                eprintln!(
                    "promtect guard: {e}\n\
                     usage: promtect guard <claude|codex|ollama|--exec CMD> \
                     [--headroom[=URL]] [--openrouter] [--upstream URL] [--strict] \
                     [--port N] [-- TOOL_ARGS...]"
                );
                std::process::exit(2);
            }
        }
    }

    // ── dashboard subcommand ────────────────────────────────────────────────
    // Starts a local, offline HTTP server that exposes the aggregated audit-log
    // metrics three ways: a browser UI at `/`, JSON at `/api/metrics`, and
    // Prometheus text exposition at `/metrics`. The server never receives proxy
    // traffic — it only reads the audit JSONL that the proxy writes.
    if args.get(1).map(|s| s.as_str()) == Some("dashboard") {
        let port = match proxy::parse_port(
            "PROMTECT_DASHBOARD_PORT",
            std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
            8799,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("promtect: {e}");
                std::process::exit(1);
            }
        };
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
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("promtect dashboard: server error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let port = match proxy::parse_port(
        "PROMTECT_PORT",
        std::env::var("PROMTECT_PORT").ok().as_deref(),
        8787,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("promtect: {e}");
            std::process::exit(1);
        }
    };
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
    // Where does this upstream send data, and is it rotate-worthy? Classify it for the
    // startup banner, and honor PROMTECT_BLOCK_RISKY (fail-closed: refuse high-risk
    // upstreams like DeepSeek or an unverified unknown host).
    let risk = promtect::provider::classify(&upstream);
    let block_risky = proxy::parse_truthy(std::env::var("PROMTECT_BLOCK_RISKY").ok().as_deref());
    if promtect::provider::is_blocked(&risk, block_risky) {
        eprintln!(
            "promtect: refusing to proxy to a high-risk upstream — {note}\n  \
             ({upstream}). Unset PROMTECT_BLOCK_RISKY to allow it.",
            note = risk.note,
        );
        std::process::exit(1);
    }

    let audit_path =
        std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());

    // Operator-tunable body cap (default 32 MiB); fail closed on an invalid value.
    let max_body_bytes =
        match proxy::parse_max_body_bytes(std::env::var("PROMTECT_MAX_BODY_BYTES").ok().as_deref())
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("promtect: {e}");
                std::process::exit(1);
            }
        };

    // Restore secrets in the response (transparent mode) by default; PROMTECT_RESTORE
    // falsey → strict mode (secrets never re-enter the response).
    let restore = proxy::parse_restore(std::env::var("PROMTECT_RESTORE").ok().as_deref());

    let upstream_for_log = upstream.clone();
    let ctx = Ctx {
        upstream,
        audit: Arc::new(audit::Audit::to_file(audit_path.into())),
        client: promtect::net::http_client(),
        max_body_bytes,
        restore,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        "promtect listening on {addr} (upstream: {upstream_for_log}){restore_note}\n  point your tool's base URL at {hint}\n  upstream risk: {risk_note}",
        risk_note = risk.note,
    );
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("promtect: server error: {e}");
        std::process::exit(1);
    }
}
