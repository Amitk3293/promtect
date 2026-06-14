use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Append-only JSONL audit log. Records mask/unmask events — never secret values.
pub struct Audit {
    sink: Mutex<Option<PathBuf>>, // None = discard (used in tests)
}

impl Audit {
    pub fn to_file(path: PathBuf) -> Self {
        Audit {
            sink: Mutex::new(Some(path)),
        }
    }

    /// A logger that discards everything (for tests and the selftest subcommand).
    pub fn null() -> Self {
        Audit {
            sink: Mutex::new(None),
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
        let guard = self.sink.lock().unwrap();
        if let Some(path) = guard.as_ref()
            && let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = writeln!(f, "{}", line);
        }
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
        let guard = self.sink.lock().unwrap();
        if let Some(path) = guard.as_ref()
            && let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_request_writes_value_free_summary_line() {
        // record_request must write one JSONL line with counts/kinds, never secret values.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("airlock-req-{}.jsonl", uuid::Uuid::new_v4()));
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
        let path = dir.join(format!("airlock-audit-{}.jsonl", uuid::Uuid::new_v4()));
        let audit = Audit::to_file(path.clone());
        audit.record("mask", "aws_key", "«airlock:aws_key:0001»", "req-xyz");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"action\":\"mask\""));
        assert!(contents.contains("req-xyz"));
        assert!(!contents.contains("AKIA")); // never logs the real secret
        std::fs::remove_file(&path).ok();
    }
}
