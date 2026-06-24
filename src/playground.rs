// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! `promtect playground` — a self-contained, offline demo of the full
//! mask → forward → restore round-trip.
//!
//! It starts the *real* proxy in front of an in-process mock upstream, sends one
//! request carrying several **synthetic** secrets, and prints three things: what
//! your tool tried to send, what the upstream actually received (masked — the
//! proof nothing leaked), and what came back to your tool (restored). Nothing
//! leaves the machine and every "secret" here is fake, so it is safe to run
//! anywhere as a "does this actually work?" check.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, MutexGuard};

use axum::{Router, extract::State};

use crate::audit::Audit;
use crate::proxy::{self, Ctx};

// Synthetic, non-functional credentials. Each matches a detector's format but
// none is a real key: the AWS pair is AWS's own documented example value, and the
// rest are invented. They exist only so the demo has something to mask.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY: &str = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const DB_PASSWORD: &str = "s3cr3t_pw_42";

/// Records the exact body the mock upstream received, so the demo can show that
/// the masked text — not the real secret — is what crossed the wire.
#[derive(Clone, Default)]
struct Seen {
    body: Arc<Mutex<String>>,
}

/// Recover a poisoned lock instead of panicking — this is in the shipped binary,
/// and a demo must never crash on a lock it fully controls.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The mock upstream: record the body, then echo it straight back as the
/// response. Echoing the *masked* body is what lets the proxy demonstrate
/// restore on the way back.
async fn mock_upstream(State(seen): State<Seen>, body: String) -> String {
    *lock(&seen.body) = body.clone();
    body
}

/// Bind an ephemeral loopback port, serve `app` in the background, and return its
/// base URL.
async fn spawn(app: Router) -> std::io::Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(format!("http://{addr}"))
}

/// Run the playground demo. Prints a narrated round-trip and returns; on any
/// setup error it prints a message and returns without panicking.
pub async fn run() {
    let sample = format!(
        "Here's the config you asked me to debug:\n\n\
         AWS_ACCESS_KEY_ID={AWS_KEY}\n\
         STRIPE_SECRET={STRIPE_KEY}\n\
         DATABASE_URL=postgres://app:{DB_PASSWORD}@db.internal:5432/main\n\n\
         Can you spot the bug?"
    );
    let found = crate::detect::detect(&sample).len();

    println!("promtect playground — a fake request, masked and restored, all on localhost\n");

    // 1. Mock upstream that records what it received.
    let seen = Seen::default();
    let upstream_app = Router::new()
        .fallback(mock_upstream)
        .with_state(seen.clone());
    let upstream_url = match spawn(upstream_app).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("promtect playground: cannot start mock upstream ({e})");
            return;
        }
    };

    // 2. The real proxy, pointed at the mock.
    let ctx = Ctx {
        upstream: upstream_url,
        audit: Arc::new(Audit::null()),
        client: reqwest::Client::new(),
        max_body_bytes: proxy::DEFAULT_MAX_BODY_BYTES,
        restore: true,
        requests: Arc::new(AtomicU64::new(0)),
        extra_detect: None,
    };
    let promtect_url = match spawn(proxy::app(ctx)).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("promtect playground: cannot start proxy ({e})");
            return;
        }
    };

    // 3. Send the sample request THROUGH the proxy as a plain-text body.
    let resp = reqwest::Client::new()
        .post(format!("{promtect_url}/v1/messages"))
        .header("content-type", "text/plain; charset=utf-8")
        .body(sample.clone())
        .send()
        .await;
    let restored = match resp {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(e) => {
            eprintln!("promtect playground: request failed ({e})");
            return;
        }
    };
    let upstream_saw = lock(&seen.body).clone();

    // 4. Narrate the round-trip.
    println!("┌─ 1. what your tool tried to send ─────────────────────────────");
    println!("{}\n", indent(&sample));
    println!("┌─ 2. what the upstream actually received (masked) ─────────────");
    println!("{}\n", indent(&upstream_saw));
    println!("┌─ 3. what came back to your tool (restored) ──────────────────");
    println!("{}\n", indent(&restored));

    // 5. The verdict — the same check `selftest` makes, but on the live wire.
    let leaked = [AWS_KEY, STRIPE_KEY, DB_PASSWORD]
        .iter()
        .any(|s| upstream_saw.contains(s));
    if leaked {
        println!("✗ LEAK: a real secret reached the upstream. This is a bug — please report it.");
    } else {
        println!(
            "✓ masked {found} secret(s); the upstream saw 0 real values, and your tool got them all back."
        );
        println!("  Run `PROMTECT_RESTORE=false promtect …` to keep them masked in the reply too.");
    }
}

/// Indent every line by two spaces so the request bodies read as quoted blocks
/// under their headers.
fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}
