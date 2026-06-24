//! Fail-open guarantee for the audit log (#42).
//!
//! The audit trail is defense-in-depth telemetry, never a gate: if the log
//! cannot be opened or written (unwritable directory, vanished mount, a path
//! that resolves into an unwritable location), masking MUST still proceed and
//! the recording call MUST return without panicking. These tests point an
//! `Audit` at locations that cannot be written and assert the calls are inert.

use promtect::audit::Audit;

/// `record` against a guaranteed-unwritable absolute path must not panic.
///
/// `/proc/nonexistent/...` cannot be created on Linux; on other platforms the
/// path simply will not exist as a writable target. Either way the open fails
/// and `record` must swallow the error (fail-open).
#[test]
fn record_into_unwritable_path_does_not_panic() {
    let audit = Audit::to_file("/proc/promtect-nonexistent/audit.jsonl");
    // Multiple calls also exercise the one-shot warning path without panicking.
    audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-1");
    audit.record("unmask", "aws_key", "«promtect:aws_key:0001»", "req-1");
}

/// `record_request` against a guaranteed-unwritable absolute path must not panic.
#[test]
fn record_request_into_unwritable_path_does_not_panic() {
    let audit = Audit::to_file("/proc/promtect-nonexistent/audit.jsonl");
    audit.record_request("req-1", 3, &["aws_key", "jwt"], 1024, 1000);
    audit.record_request("req-2", 0, &[], 10, 10);
}

/// On Unix, an audit file living inside a `0o000` directory cannot be opened
/// for append, yet `record`/`record_request` must remain fail-open. This is the
/// strongest form of the guarantee: a real permission denial mid-operation does
/// not block masking.
#[cfg(unix)]
#[test]
fn record_under_unwritable_dir_does_not_panic() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("promtect-failmode-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).expect("create temp dir for test");
    let target = dir.join("audit.jsonl");

    // Lock the directory so the audit file cannot be created or opened.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 the temp dir");

    let audit = Audit::to_file(target);
    audit.record(
        "mask",
        "db_password",
        "«promtect:db_password:0001»",
        "req-1",
    );
    audit.record_request("req-1", 1, &["db_password"], 64, 64);

    // Restore permissions so the temp dir can be cleaned up.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore temp dir perms");
    std::fs::remove_dir_all(&dir).ok();
}
