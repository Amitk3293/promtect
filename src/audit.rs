// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Seek, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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
    /// Optional guard-session scope prepended to request IDs in the audit only.
    /// This keeps concurrent guards sharing one append-only log attributable
    /// without changing the proxy's internal request identifier.
    request_scope: Option<Arc<str>>,
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
            request_scope: None,
            warned: AtomicBool::new(false),
        }
    }

    pub(crate) fn to_file_scoped(path: impl Into<PathBuf>, request_scope: String) -> Self {
        Audit {
            sink: Mutex::new(Some(FileSink {
                path: path.into(),
                handle: None,
            })),
            request_scope: Some(request_scope.into()),
            warned: AtomicBool::new(false),
        }
    }

    /// A logger that discards everything (for tests and the selftest subcommand).
    pub fn null() -> Self {
        Audit {
            sink: Mutex::new(None),
            request_scope: None,
            warned: AtomicBool::new(false),
        }
    }

    pub(crate) fn is_healthy(&self) -> bool {
        !self.warned.load(Ordering::Relaxed)
    }

    fn scoped_request_id(&self, request_id: &str) -> String {
        self.request_scope.as_ref().map_or_else(
            || request_id.to_string(),
            |scope| format!("{scope}:{request_id}"),
        )
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

    /// Open and repair a file-backed sink before a reader snapshots its length.
    /// Guard's Claude notice tailer uses this so a truncated prior-session tail
    /// cannot leave its initial cursor in the middle of the first new record.
    /// Unlike ordinary event writes, the caller receives open/validation errors
    /// so a guard can reject an unsafe audit path before starting the provider.
    pub(crate) fn prepare(&self) -> std::io::Result<()> {
        let mut guard = self.sink_lock();
        let Some(sink) = guard.as_mut() else {
            return Ok(());
        };
        if sink.handle.is_none() {
            match Self::open_append(&sink.path) {
                Ok(file) => sink.handle = Some(file),
                Err(error) => {
                    self.warn_once();
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Open an existing audit log for value-free readers without following a
    /// final-component symlink or accepting a non-regular/unowned target.
    /// Unlike the append path, this never creates, repairs, or changes the file.
    pub(crate) fn open_read(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        let mut opts = OpenOptions::new();
        opts.read(true);
        configure_no_follow(&mut opts);
        reject_symlink_without_atomic_no_follow(path)?;
        let file = opts.open(path)?;
        validate_audit_file(&file)?;
        Ok(file)
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
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        configure_no_follow(&mut opts);
        reject_symlink_without_atomic_no_follow(path)?;
        let mut f = opts.open(path)?;
        let metadata = validate_audit_file(&f)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Only touch perms when group/other bits are set; the common
            // freshly-created case (already 0600) does no extra syscall.
            if metadata.permissions().mode() & 0o077 != 0 {
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
        }
        Self::repair_truncated_tail(&mut f)?;
        Ok(f)
    }

    /// Remove an incomplete final JSONL record before the next append.
    ///
    /// A process crash can leave the final event without its terminating newline.
    /// Appending directly would concatenate the next valid JSON object onto that
    /// fragment and corrupt both records. Scan backwards in bounded chunks and
    /// truncate to the last complete line. The discarded bytes are never copied
    /// elsewhere, preserving the owner-only and value-free storage boundary even
    /// when the file was externally modified.
    fn repair_truncated_tail(file: &mut std::fs::File) -> std::io::Result<()> {
        const SCAN_CHUNK: usize = 8 * 1024;
        const MAX_TAIL: u64 = 64 * 1024;

        let len = file.metadata()?.len();
        if len == 0 {
            return Ok(());
        }

        file.seek(std::io::SeekFrom::End(-1))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)?;
        if last[0] == b'\n' {
            return Ok(());
        }

        let mut end = len;
        let scan_floor = len.saturating_sub(MAX_TAIL);
        let mut buf = [0_u8; SCAN_CHUNK];
        let complete_prefix = loop {
            let start = end.saturating_sub(SCAN_CHUNK as u64).max(scan_floor);
            let width = usize::try_from(end - start).unwrap_or(SCAN_CHUNK);
            file.seek(std::io::SeekFrom::Start(start))?;
            file.read_exact(&mut buf[..width])?;

            if let Some(offset) = buf[..width].iter().rposition(|byte| *byte == b'\n') {
                break Some(start + offset as u64 + 1);
            }
            if start == scan_floor {
                break (scan_floor == 0).then_some(0);
            }
            end = start;
        };

        let Some(complete_prefix) = complete_prefix else {
            // A record larger than the maximum emitted audit line is malformed.
            // Reset instead of synchronously scanning an attacker-sized file.
            file.set_len(0)?;
            return Ok(());
        };

        // Preserve a complete JSON object whose only defect is a missing final
        // newline. Audit events are tiny; cap validation so an untrusted huge tail
        // cannot force an equally huge allocation during startup recovery.
        let tail_len = len - complete_prefix;
        if tail_len <= MAX_TAIL {
            let mut tail = vec![0_u8; usize::try_from(tail_len).unwrap_or(0)];
            file.seek(std::io::SeekFrom::Start(complete_prefix))?;
            file.read_exact(&mut tail)?;
            if serde_json::from_slice::<serde_json::Value>(&tail).is_ok() {
                file.write_all(b"\n")?;
                return Ok(());
            }
        }

        file.set_len(complete_prefix)?;
        Ok(())
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
        self.record_request_outcome(request_id, masked, detectors, bytes_in, bytes_out, false);
    }

    /// Record a request rejected before its body could be safely summarized.
    ///
    /// Early 413/415 paths still need a first-class request row in metrics, but
    /// they must not be counted as clean traffic. Body sizes and detector kinds
    /// are deliberately zero/empty because those paths stop before safe parsing.
    pub(crate) fn record_blocked_request(&self, request_id: &str) {
        self.record_request_outcome(request_id, 0, &[], 0, 0, true);
    }

    fn record_request_outcome(
        &self,
        request_id: &str,
        masked: usize,
        detectors: &[&str],
        bytes_in: usize,
        bytes_out: usize,
        blocked: bool,
    ) {
        let request_id = self.scoped_request_id(request_id);
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
            "blocked": blocked,
        });
        self.append_line(&line.to_string());
    }

    /// Record one event. `placeholder` is a sentinel id, NOT a secret.
    pub fn record(&self, action: &str, kind: &str, placeholder: &str, request_id: &str) {
        let request_id = self.scoped_request_id(request_id);
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

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(unix_no_follow_flag());
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

#[cfg(any(unix, windows))]
fn reject_symlink_without_atomic_no_follow(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_symlink_without_atomic_no_follow(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::new(
            ErrorKind::PermissionDenied,
            "audit log path must not be a symbolic link",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_audit_file(file: &std::fs::File) -> std::io::Result<std::fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "audit log target must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != effective_user_id()? {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "audit log target must be owned by the current user",
            ));
        }
    }
    Ok(metadata)
}

#[cfg(target_os = "linux")]
const fn unix_no_follow_flag() -> i32 {
    0o400_000
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
const fn unix_no_follow_flag() -> i32 {
    0x100
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios"
    ))
))]
compile_error!("audit log O_NOFOLLOW is not defined for this Unix target");

#[cfg(unix)]
fn effective_user_id() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;

    static UID: OnceLock<u32> = OnceLock::new();
    if let Some(uid) = UID.get() {
        return Ok(*uid);
    }

    #[cfg(target_os = "linux")]
    let uid = std::fs::metadata("/proc/self")?.uid();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let uid = std::fs::metadata(std::env::temp_dir())?.uid();

    Ok(*UID.get_or_init(|| uid))
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
        assert!(contents.contains("\"blocked\":false"));
        assert!(contents.contains("\"bytes_in\":512"));
        assert!(contents.contains("\"bytes_out\":498"));
        assert!(contents.contains("aws_key"));
        assert!(contents.contains("anthropic_key"));
        // Invariant: body text and secret values are never written to the log.
        assert!(!contents.contains("AKIA"));
    }

    #[test]
    fn blocked_request_summary_is_explicit_and_value_free() {
        let path = std::env::temp_dir().join(format!(
            "promtect-blocked-request-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let audit = Audit::to_file(path.clone());
        audit.record_blocked_request("req-blocked");

        let contents = std::fs::read_to_string(&path).expect("read blocked request audit");
        std::fs::remove_file(&path).ok();

        assert!(contents.contains("\"request_id\":\"req-blocked\""));
        assert!(contents.contains("\"blocked\":true"));
        assert!(contents.contains("\"masked\":0"));
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

    #[cfg(unix)]
    #[test]
    fn symlink_audit_path_never_mutates_its_target() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir();
        let suffix = uuid::Uuid::new_v4();
        let target = dir.join(format!("promtect-audit-target-{suffix}.jsonl"));
        let link = dir.join(format!("promtect-audit-link-{suffix}.jsonl"));
        let original = b"arbitrary file without a newline";
        std::fs::write(&target, original).expect("seed target");
        symlink(&target, &link).expect("create audit symlink");

        let audit = Audit::to_file(link.clone());
        let prepare_result = audit.prepare();
        let read_result = Audit::open_read(&link);
        audit.record("mask", "aws_key", "opaque-sentinel", "req-symlink");

        let actual = std::fs::read(&target).expect("read target after rejected audit writes");
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
        assert!(
            prepare_result.is_err(),
            "append prepare unexpectedly accepted the symlink"
        );
        assert!(
            read_result.is_err(),
            "notice reader unexpectedly accepted the symlink"
        );
        assert_eq!(actual, original, "symlink target must remain byte-exact");
    }

    #[test]
    fn non_regular_audit_target_is_rejected_without_mutation() {
        let path =
            std::env::temp_dir().join(format!("promtect-audit-directory-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create audit target directory");

        let result = Audit::open_append(&path);

        let is_still_directory = path.is_dir();
        std::fs::remove_dir(&path).ok();
        assert!(
            result.is_err() && is_still_directory,
            "non-regular targets must be rejected without mutation"
        );
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

    #[test]
    fn truncated_tail_is_removed_before_next_valid_event() {
        let path = std::env::temp_dir().join(format!(
            "promtect-tail-repair-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            b"{\"action\":\"request\",\"request_id\":\"complete\"}\n{\"action\":\"mask\"",
        )
        .expect("seed truncated audit log");

        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "next");

        let contents = std::fs::read_to_string(&path).expect("read repaired audit log");
        std::fs::remove_file(&path).ok();
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).expect("every retained line must be valid JSON"))
            .collect();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["request_id"], "complete");
        assert_eq!(records[1]["request_id"], "next");
        assert!(!contents.contains("{\"action\":\"mask\"{\""));
    }

    #[test]
    fn complete_final_json_without_newline_is_preserved() {
        let path = std::env::temp_dir().join(format!(
            "promtect-tail-newline-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            b"{\"action\":\"request\",\"request_id\":\"complete\"}",
        )
        .expect("seed newline-less audit log");

        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«promtect:aws_key:0001»", "next");
        let contents = std::fs::read_to_string(&path).expect("read repaired audit log");
        std::fs::remove_file(&path).ok();

        assert_eq!(contents.lines().count(), 2);
        assert!(
            contents
                .lines()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        );
    }

    #[test]
    fn oversized_malformed_tail_resets_without_scanning_sparse_prefix() {
        const SPARSE_LEN: u64 = 512 * 1024 * 1024;

        let path = std::env::temp_dir().join(format!(
            "promtect-tail-sparse-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create sparse malformed audit");
        file.set_len(SPARSE_LEN).expect("create sparse prefix");
        file.seek(std::io::SeekFrom::Start(SPARSE_LEN - 1))
            .expect("seek to sparse tail");
        file.write_all(b"x").expect("write malformed tail");
        drop(file);

        let audit = Audit::to_file(path.clone());
        audit.prepare().expect("repair sparse malformed audit");

        let repaired_len = std::fs::metadata(&path).expect("stat repaired audit").len();
        std::fs::remove_file(&path).ok();
        assert_eq!(repaired_len, 0, "oversized malformed tail must reset");
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
