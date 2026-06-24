// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Mutable, lock-guarded state for a file-backed audit sink: the target path and
/// a cached open handle. The handle is reused across events so the log is not
/// re-`open(2)`d on every mask/unmask — this also shrinks the window in which a
/// swapped symlink at `path` could redirect a write (the cached fd points at the
/// inode opened earlier). On a write error the handle is dropped so the next
/// event re-opens, which is enough to recover from a rotated/truncated log.
struct FileSink {
    path: PathBuf,
    /// `None` until the first successful open; cleared on write error to force a
    /// re-open on the next event.
    handle: Option<std::fs::File>,
}

/// Append-only JSONL audit log. Records mask/unmask events — never secret values.
///
/// The log is FAIL-OPEN by contract: every open or write failure is swallowed so
/// that masking is never blocked or panicked by audit I/O. The first write
/// failure emits a single stderr warning (see `warned`) so the operator learns
/// the trail is incomplete, without otherwise changing behaviour.
pub struct Audit {
    sink: Mutex<Option<FileSink>>, // None = discard (used in tests)
    /// Set once, the first time a write fails, to gate a one-shot stderr warning.
    warned: AtomicBool,
}

impl Audit {
    pub fn to_file(path: impl Into<PathBuf>) -> Self {
        Audit {
            sink: Mutex::new(Some(FileSink {
                path: path.into(),
                handle: None,
            })),
            warned: AtomicBool::new(false),
        }
    }

    /// A logger that discards everything (for tests and the selftest subcommand).
    pub fn null() -> Self {
        Audit {
            sink: Mutex::new(None),
            warned: AtomicBool::new(false),
        }
    }

    /// Lock the sink, recovering the guard if a previous holder panicked. The
    /// audit log is best-effort and the guarded value carries no invariant a
    /// mid-write panic could corrupt (a path plus a cached fd), so a poisoned
    /// mutex must never escalate into a crash that takes down the proxy.
    fn sink_lock(&self) -> MutexGuard<'_, Option<FileSink>> {
        self.sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Open the audit log for append, creating it owner-only (`0600`) on Unix and
    /// repairing the mode of a pre-existing file that is group/other-accessible.
    ///
    /// The log is value-free (no secret values), but on a shared machine even the
    /// detector/count metadata is the operator's business alone — another local
    /// user has no reason to read which detectors fired. `OpenOptions::mode` only
    /// applies when the file is *created*, so a log created before Promtect (or by
    /// an older build) could linger world-readable; after opening we tighten any
    /// stray group/other bits back to `0600` (#41). The repair is best-effort: if
    /// `set_permissions` fails we still return the handle (fail-open).
    fn open_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Only touch perms when group/other bits are set; the common
            // freshly-created case (already 0600) does no extra syscall.
            if let Ok(meta) = f.metadata()
                && meta.permissions().mode() & 0o077 != 0
            {
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(f)
    }

    /// Append one already-serialised JSONL line, fail-open.
    ///
    /// Reuses the cached file handle, opening lazily on first use and re-opening
    /// once if a write fails (handling a rotated/truncated log). Any open or
    /// write error is swallowed so masking is never blocked; the first failure
    /// triggers a single stderr warning so the operator knows the trail is
    /// incomplete. Callers MUST pass a value-free line (no secret values).
    fn append_line(&self, line: &str) {
        let mut guard = self.sink_lock();
        let Some(sink) = guard.as_mut() else {
            return; // null sink: discard.
        };

        // Open lazily; a cached handle is reused across events.
        if sink.handle.is_none() {
            match Self::open_append(&sink.path) {
                Ok(f) => sink.handle = Some(f),
                Err(_) => {
                    self.warn_once();
                    return;
                }
            }
        }

        if let Some(f) = sink.handle.as_mut()
            && writeln!(f, "{}", line).is_err()
        {
            // A cached handle can go stale (log rotated/removed). Drop it and
            // retry once with a fresh open so the next event also re-opens if
            // this retry fails too.
            sink.handle = None;
            match Self::open_append(&sink.path) {
                Ok(mut f) => {
                    if writeln!(f, "{}", line).is_ok() {
                        sink.handle = Some(f);
                    } else {
                        self.warn_once();
                    }
                }
                Err(_) => self.warn_once(),
            }
        }
    }

    /// Emit a single process-lifetime stderr warning on the first audit write
    /// failure. Does NOT change fail-open behaviour — it only informs the
    /// operator that the audit trail is now incomplete. Subsequent failures are
    /// silent to avoid flooding stderr on a persistently unwritable log.
    fn warn_once(&self) {
        if !self.warned.swap(true, Ordering::Relaxed) {
            eprintln!(
                "promtect: warning: audit log write failed; masking continues but \
                 the audit trail is incomplete (this warning is shown once)"
            );
        }
    }

    /// Record a value-free per-request summary: how many secrets were masked, which
    /// detector kinds fired, and the request's byte sizes. Enables "caught vs clean"
    /// metrics (a clean request logs `masked=0`). NEVER logs secret values or body text.
    ///
    /// Appends one JSONL line of the form:
    /// ```json
    /// {"ts_ms":N,"action":"request","request_id":"...","masked":N,
    ///  "detectors":["aws_key",...],"bytes_in":N,"bytes_out":N}
    /// ```
    pub fn record_request(
        &self,
        request_id: &str,
        masked: usize,
        detectors: &[&str],
        bytes_in: usize,
        bytes_out: usize,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let line = serde_json::json!({
            "ts_ms": ts,
            "action": "request",
            "request_id": request_id,
            "masked": masked,
            "detectors": detectors,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
        });
        self.append_line(&line.to_string());
    }

    /// Record one event. `placeholder` is a sentinel id, NOT a secret.
    pub fn record(&self, action: &str, kind: &str, placeholder: &str, request_id: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let line = serde_json::json!({
            "ts_ms": ts,
            "action": action,     // "mask" | "unmask"
            "detector": kind,
            "placeholder": placeholder,
            "request_id": request_id,
        });
        self.append_line(&line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_request_writes_value_free_summary_line() {
        // record_request must write one JSONL line with counts/kinds, never secret values.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-req-{}.jsonl", uuid::Uuid::new_v4()));
        let audit = Audit::to_file(path.clone());
        audit.record_request("req-abc", 2, &["aws_key", "anthropic_key"], 512, 498);
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(contents.contains("\"action\":\"request\""));
        assert!(contents.contains("\"request_id\":\"req-abc\""));
        assert!(contents.contains("\"masked\":2"));
        assert!(contents.contains("\"bytes_in\":512"));
        assert!(contents.contains("\"bytes_out\":498"));
        assert!(contents.contains("aws_key"));
        assert!(contents.contains("anthropic_key"));
        // Invariant: body text and secret values are never written to the log.
        assert!(!contents.contains("AKIA"));
    }

    #[test]
    fn writes_jsonl_without_secret_value() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-audit-{}.jsonl", uuid::Uuid::new_v4()));
        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-xyz");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"action\":\"mask\""));
        assert!(contents.contains("req-xyz"));
        assert!(!contents.contains("AKIA")); // never logs the real secret
        std::fs::remove_file(&path).ok();
    }

    /// #41: a pre-existing world-readable (`0644`) audit file must be tightened
    /// to owner-only (`0600`) on first append. `OpenOptions::mode` applies only
    /// at creation, so without an explicit repair a log created before Promtect
    /// (or by an older build) would stay readable by other local users.
    #[cfg(unix)]
    #[test]
    fn pre_existing_0644_file_is_tightened_to_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-perm-{}.jsonl", uuid::Uuid::new_v4()));

        // Create the file 0644 *before* the audit ever touches it.
        std::fs::write(&path, b"{\"pre\":\"existing\"}\n").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "precondition: file starts world-readable"
        );

        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-perm");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        std::fs::remove_file(&path).ok();
        assert_eq!(mode, 0o600, "append must tighten perms to owner-only");
    }

    /// A freshly created log is owner-only (`0600`) from the start — the repair
    /// path must not loosen the create-time mode.
    #[cfg(unix)]
    #[test]
    fn freshly_created_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-fresh-{}.jsonl", uuid::Uuid::new_v4()));
        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-fresh");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        std::fs::remove_file(&path).ok();
        assert_eq!(mode, 0o600);
    }

    /// #47: the cached handle is reused across events and every event still lands
    /// on disk. This guards against the cache silently dropping writes.
    #[test]
    fn cached_handle_appends_every_event() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-cache-{}.jsonl", uuid::Uuid::new_v4()));
        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-1");
        audit.record("unmask", "aws_key", "«promtect:aws_key:0001»", "req-1");
        audit.record_request("req-1", 1, &["aws_key"], 100, 90);

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        // Three events → three JSONL lines.
        assert_eq!(contents.lines().count(), 3, "every event must be appended");
        assert!(contents.contains("\"action\":\"mask\""));
        assert!(contents.contains("\"action\":\"unmask\""));
        assert!(contents.contains("\"action\":\"request\""));
    }

    /// #47: the one-shot write-failure warning is gated by the `warned` flag —
    /// it is set exactly once and never panics, regardless of how many failing
    /// writes occur. Pointed at an unwritable path so every write fails.
    #[test]
    fn write_failure_warns_once_and_stays_fail_open() {
        let audit = Audit::to_file("/proc/promtect-nonexistent/audit.jsonl");
        assert!(!audit.warned.load(Ordering::Relaxed));
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-1");
        assert!(
            audit.warned.load(Ordering::Relaxed),
            "first failed write must arm the one-shot warning"
        );
        // Further failing writes must remain inert (no panic, flag stays set).
        audit.record("unmask", "aws_key", "«promtect:aws_key:0001»", "req-1");
        audit.record_request("req-1", 0, &[], 1, 1);
        assert!(audit.warned.load(Ordering::Relaxed));
    }

    /// A null sink never warns: discarding is the intended behaviour, not a failure.
    #[test]
    fn null_sink_never_warns() {
        let audit = Audit::null();
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "req-1");
        audit.record_request("req-1", 0, &[], 1, 1);
        assert!(!audit.warned.load(Ordering::Relaxed));
    }
}
