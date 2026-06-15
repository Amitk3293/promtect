//! Promtect library crate — the masking pipeline (detect → vault → mask), the
//! loopback proxy, the value-free audit log, small net helpers, and the local
//! observability dashboard. Both the binary (`main.rs`) and the integration
//! tests depend on this crate.

pub mod audit;
pub mod dashboard;
pub mod detect;
pub mod mask;
pub mod metrics;
pub mod net;
pub mod proxy;
pub mod stream;
pub mod vault;
