// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Promtect library crate — the masking pipeline (detect → vault → mask), the
//! loopback proxy, the value-free audit log, small net helpers, and the local
//! observability dashboard. Both the binary (`main.rs`) and the integration
//! tests depend on this crate.

use std::io::Write as _;
use std::sync::Once;

static VALUE_FREE_PANIC_HOOK: Once = Once::new();

/// Install Promtect's process-wide, value-free panic hook exactly once.
///
/// Detector panics can carry request text as their payload. Rust's default panic
/// hook prints that payload before an async task returns its [`tokio::task::JoinError`],
/// so Promtect-owned binaries install this fixed-message hook before handling any
/// input. The hook deliberately discards the panic payload, location, and prior
/// hook, and ignores stderr write failures to avoid a second panic while unwinding.
///
/// This changes global process behavior. Library embedders should not call it;
/// the Core and Pro entrypoints own the process and install it at startup.
///
/// # Panics
///
/// Rust panics if a process attempts to replace its panic hook from a panicking
/// thread. Promtect calls this only during binary startup.
pub fn install_value_free_panic_hook() {
    VALUE_FREE_PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {
            let _ = std::io::stderr()
                .lock()
                .write_all(b"promtect: internal task panicked; request failed closed\n");
        }));
    });
}

pub mod audit;
pub mod dashboard;
pub mod detect;
pub mod guard;
pub mod mask;
pub mod metrics;
pub mod net;
pub mod playground;
pub mod provider;
pub mod proxy;
pub mod run;
pub mod stream;
pub mod vault;
