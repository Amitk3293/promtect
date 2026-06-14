mod audit;
mod detect;
mod mask;
mod proxy;
mod vault;

use proxy::Ctx;
use std::sync::Arc;

#[tokio::main]
async fn main() {
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
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("airlock listening on http://{addr} -> set ANTHROPIC_BASE_URL to it");
    axum::serve(listener, app).await.unwrap();
}
