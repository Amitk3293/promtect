use std::sync::Arc;

use airlock::{
    audit,
    proxy::{self, Ctx},
    vault,
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
        vault: Arc::new(vault::Vault::new()),
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
