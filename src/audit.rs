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
