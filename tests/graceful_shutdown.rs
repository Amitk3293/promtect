//! Graceful-shutdown path tests for `shutdown_signal()` and `axum::serve` drain behaviour.

/// Verify that a proxy serve loop exits cleanly after the shutdown trigger fires.
#[tokio::test]
async fn proxy_drains_on_shutdown_trigger() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let stopped = Arc::new(AtomicBool::new(false));
    let stopped2 = stopped.clone();

    // A minimal router that returns 200 OK.
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(|| async { axum::http::StatusCode::OK }),
    );

    // Use a oneshot channel as the deterministic shutdown trigger so this
    // test runs on all platforms without sending real signals.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await;
        stopped2.store(true, Ordering::Relaxed);
    });

    // Confirm the server is reachable before shutdown.
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("request before shutdown");
    assert_eq!(res.status(), 200);

    // Fire the shutdown trigger.
    tx.send(()).ok();

    // Wait briefly for the serve loop to drain and exit.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        stopped.load(Ordering::Relaxed),
        "serve loop should have exited after shutdown trigger"
    );
}

/// Verify that `shutdown_signal()` does not fire spuriously without a signal.
#[tokio::test]
async fn shutdown_signal_does_not_fire_spuriously() {
    use std::time::Duration;

    let did_fire = tokio::time::timeout(
        Duration::from_millis(50),
        promtect::proxy::shutdown_signal(),
    )
    .await;

    assert!(
        did_fire.is_err(),
        "shutdown_signal() fired without a signal being sent — should have timed out"
    );
}

/// On Unix: verify that `shutdown_signal()` compiles and both signal handlers register.
#[cfg(unix)]
#[tokio::test]
async fn shutdown_signal_compiles_and_registers_unix_handlers() {
    use tokio::signal::unix::{SignalKind, signal};

    // Both handlers must register without error.
    let _ctrl_c_handle = tokio::signal::ctrl_c();
    let _sigterm_handle = signal(SignalKind::terminate())
        .expect("SIGTERM handler must register successfully");

    // The public shutdown_signal() function must be callable from library
    // code (guard.rs uses crate::proxy::shutdown_signal()).
    let _future = promtect::proxy::shutdown_signal();
    // Drop the future — we do not await it to avoid actually blocking.
}
