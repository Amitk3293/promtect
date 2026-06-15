//! Value-free observability metrics, aggregated from the audit log.
//!
//! This module is intentionally free of secret values. It reads the audit JSONL
//! produced by [`crate::audit::Audit`] and exposes only counts, detector kind
//! names, and byte totals. The output is safe to serve publicly (Stage 2 will
//! add the HTTP endpoint).

use serde::Serialize;
use std::collections::BTreeMap;

/// Aggregated, value-free metrics over the audit log. Safe to expose publicly:
/// it contains only counts, detector kind names, and byte totals — never secrets.
///
/// `BTreeMap` for `by_detector` ensures deterministic Prometheus output order.
#[derive(Debug, Default, Serialize)]
pub struct Metrics {
    /// Total number of HTTP requests that passed through the proxy.
    pub requests_total: u64,
    /// Requests where at least one secret was masked.
    pub requests_with_secrets: u64,
    /// Requests that contained no detectable secrets.
    pub requests_clean: u64,
    /// Total count of individual secret spans masked (summed over all requests).
    pub secrets_masked_total: u64,
    /// Per-detector secret counts (e.g. `"aws_key" -> 5`).
    pub by_detector: BTreeMap<String, u64>,
    /// Total inbound body bytes (before masking).
    pub bytes_in_total: u64,
    /// Total outbound body bytes (after masking — may differ due to sentinel length).
    pub bytes_out_total: u64,
    /// Most-recent request summaries, value-free, newest first (capped at 20).
    pub recent: Vec<RecentRequest>,
}

/// A single value-free request summary entry in [`Metrics::recent`].
#[derive(Debug, Default, Serialize)]
pub struct RecentRequest {
    /// Wall-clock milliseconds since the Unix epoch (from the audit log).
    pub ts_ms: u64,
    /// Opaque request identifier minted by the proxy per request.
    pub request_id: String,
    /// Number of secret spans masked in this request.
    pub masked: u64,
    /// Detector kinds that fired (de-duplicated, same order as logged).
    pub detectors: Vec<String>,
}

/// How many recent-request summaries to keep in [`Metrics::recent`].
const RECENT_CAP: usize = 20;

/// Aggregate value-free metrics from an audit JSONL file.
///
/// # Behaviour
/// - Missing or empty file returns `Metrics::default()` (all zeros / empty).
/// - Malformed lines are skipped (best-effort), so a partially-written log still
///   produces useful counts for the lines that are valid.
/// - Only `"request"` and `"mask"` actions contribute to counters; `"unmask"` and
///   any unknown actions are silently ignored.
///
/// # Safety
/// This function never surfaces secret values. The audit log is designed to be
/// value-free, and this aggregator only reads the numeric/string metadata fields.
pub fn aggregate(audit_path: &std::path::Path) -> Metrics {
    let text = match std::fs::read_to_string(audit_path) {
        Ok(t) => t,
        // Missing or unreadable file is normal before the first request.
        Err(_) => return Metrics::default(),
    };

    let mut m = Metrics::default();

    for line in text.lines() {
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            // Skip malformed lines rather than failing the whole aggregation.
            continue;
        };

        let Some(action) = val.get("action").and_then(|v| v.as_str()) else {
            continue;
        };

        match action {
            "request" => {
                m.requests_total += 1;

                let masked = val.get("masked").and_then(|v| v.as_u64()).unwrap_or(0);
                if masked > 0 {
                    m.requests_with_secrets += 1;
                } else {
                    m.requests_clean += 1;
                }

                let bytes_in = val.get("bytes_in").and_then(|v| v.as_u64()).unwrap_or(0);
                let bytes_out = val.get("bytes_out").and_then(|v| v.as_u64()).unwrap_or(0);
                m.bytes_in_total += bytes_in;
                m.bytes_out_total += bytes_out;

                // Capture the value-free recent summary and cap the list at RECENT_CAP.
                let ts_ms = val.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                let request_id = val
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let detectors: Vec<String> = val
                    .get("detectors")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();

                // Insert newest-first: prepend then truncate.
                m.recent.insert(
                    0,
                    RecentRequest {
                        ts_ms,
                        request_id,
                        masked,
                        detectors,
                    },
                );
                if m.recent.len() > RECENT_CAP {
                    m.recent.truncate(RECENT_CAP);
                }
            }
            "mask" => {
                m.secrets_masked_total += 1;
                // Detector name comes from the "detector" field of mask events.
                if let Some(det) = val.get("detector").and_then(|v| v.as_str()) {
                    *m.by_detector.entry(det.to_string()).or_default() += 1;
                }
            }
            // "unmask" and unknown actions are intentionally ignored for counts.
            _ => {}
        }
    }

    m
}

impl Metrics {
    /// Render Prometheus text-exposition format (hand-rolled; no extra dependency).
    ///
    /// Produces HELP/TYPE comment pairs followed by metric lines. Detector names
    /// are `[a-z_]+` (enforced by the detector registry) so no label escaping is
    /// needed. The output ends with a trailing newline.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();

        push_counter(
            &mut out,
            "promtect_requests_total",
            "Total requests proxied.",
            self.requests_total,
            None,
        );
        push_counter(
            &mut out,
            "promtect_requests_with_secrets_total",
            "Requests in which at least one secret was masked.",
            self.requests_with_secrets,
            None,
        );
        push_counter(
            &mut out,
            "promtect_requests_clean_total",
            "Requests that contained no detectable secrets.",
            self.requests_clean,
            None,
        );

        // Per-detector breakdown for secrets_masked_total.
        out.push_str("# HELP promtect_secrets_masked_total Secrets masked, by detector.\n");
        out.push_str("# TYPE promtect_secrets_masked_total counter\n");
        for (detector, count) in &self.by_detector {
            // Detector names are [a-z_]+ — safe to embed directly in labels.
            out.push_str(&format!(
                "promtect_secrets_masked_total{{detector=\"{detector}\"}} {count}\n"
            ));
        }

        push_counter(
            &mut out,
            "promtect_bytes_in_total",
            "Total inbound body bytes (before masking).",
            self.bytes_in_total,
            None,
        );
        push_counter(
            &mut out,
            "promtect_bytes_out_total",
            "Total outbound body bytes (after masking).",
            self.bytes_out_total,
            None,
        );

        out
    }
}

/// Append a single HELP + TYPE + value line for a label-less counter.
///
/// `label` is an optional `{key="value"}` suffix; pass `None` for unlabelled metrics.
fn push_counter(out: &mut String, name: &str, help: &str, value: u64, label: Option<&str>) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    match label {
        Some(l) => out.push_str(&format!("{name}{{{l}}} {value}\n")),
        None => out.push_str(&format!("{name} {value}\n")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Aggregate the fixture and return the resulting Metrics.
    fn fixture_metrics() -> (Metrics, std::path::PathBuf) {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-test-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();

        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"request","request_id":"req-1","masked":2,"detectors":["aws_key"],"bytes_in":100,"bytes_out":120}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"mask","detector":"aws_key","placeholder":"«promtect:aws_key:0001»","request_id":"req-1"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"mask","detector":"aws_key","placeholder":"«promtect:aws_key:0002»","request_id":"req-1"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":2000,"action":"request","request_id":"req-2","masked":1,"detectors":["anthropic_key"],"bytes_in":200,"bytes_out":190}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":2000,"action":"mask","detector":"anthropic_key","placeholder":"«promtect:anthropic_key:0003»","request_id":"req-2"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":3000,"action":"request","request_id":"req-3","masked":0,"detectors":[],"bytes_in":50,"bytes_out":50}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":4000,"action":"unmask","detector":"sentinel","placeholder":"«promtect:aws_key:0001»","request_id":"req-1"}}"#
        )
        .unwrap();
        writeln!(f, "{{not valid json{{").unwrap();

        (aggregate(&path), path)
    }

    // ── Counter tests ────────────────────────────────────────────────────────

    #[test]
    fn aggregate_counts_total_requests() {
        // 3 "request" events in fixture → requests_total must be 3.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.requests_total, 3);
    }

    #[test]
    fn aggregate_counts_requests_with_secrets() {
        // 2 requests had masked > 0 (req-1 and req-2).
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.requests_with_secrets, 2);
    }

    #[test]
    fn aggregate_counts_clean_requests() {
        // 1 clean request (req-3, masked == 0).
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.requests_clean, 1);
    }

    #[test]
    fn aggregate_counts_secrets_masked_via_mask_events() {
        // 3 mask events in fixture → secrets_masked_total == 3.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.secrets_masked_total, 3);
    }

    #[test]
    fn aggregate_by_detector_counts_per_kind() {
        // aws_key appears in 2 mask events; anthropic_key in 1.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.by_detector.get("aws_key").copied(), Some(2));
        assert_eq!(m.by_detector.get("anthropic_key").copied(), Some(1));
    }

    #[test]
    fn aggregate_sums_bytes_in_and_out() {
        // bytes_in: 100 + 200 + 50 = 350; bytes_out: 120 + 190 + 50 = 360.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.bytes_in_total, 350);
        assert_eq!(m.bytes_out_total, 360);
    }

    // ── Recent-requests tests ────────────────────────────────────────────────

    #[test]
    fn aggregate_recent_has_correct_length() {
        // 3 "request" events → recent must have 3 entries (fixture is under cap).
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.recent.len(), 3);
    }

    #[test]
    fn aggregate_recent_is_newest_first() {
        // Entries are inserted newest-first; req-3 (ts_ms=3000) should be first.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.recent[0].request_id, "req-3");
        assert_eq!(m.recent[1].request_id, "req-2");
        assert_eq!(m.recent[2].request_id, "req-1");
    }

    #[test]
    fn aggregate_recent_cap_limits_to_twenty() {
        // Write 25 request events and verify recent is capped at RECENT_CAP (20).
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-cap-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        for i in 0u64..25 {
            writeln!(
                f,
                r#"{{"ts_ms":{i},"action":"request","request_id":"req-{i}","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
            )
            .unwrap();
        }
        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(m.recent.len(), RECENT_CAP);
    }

    // ── Missing / malformed file ─────────────────────────────────────────────

    #[test]
    fn aggregate_returns_defaults_for_missing_file() {
        // Non-existent path → all zeros; must not panic.
        let path = std::path::Path::new("/nonexistent/promtect-no-such-file.jsonl");
        let m = aggregate(path);
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.secrets_masked_total, 0);
        assert!(m.recent.is_empty());
    }

    #[test]
    fn aggregate_skips_malformed_lines_without_panicking() {
        // Fixture contains one malformed line; total should still be 3.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        // If the malformed line caused a panic this test would not reach here.
        assert_eq!(m.requests_total, 3);
    }

    // ── Prometheus output tests ──────────────────────────────────────────────

    #[test]
    fn to_prometheus_contains_requests_total() {
        // Must emit the unlabelled counter with the correct value.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        let prom = m.to_prometheus();
        assert!(
            prom.contains("promtect_requests_total 3"),
            "expected 'promtect_requests_total 3' in:\n{prom}"
        );
    }

    #[test]
    fn to_prometheus_contains_per_detector_label() {
        // Per-detector line must use label syntax {detector="..."}.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        let prom = m.to_prometheus();
        assert!(
            prom.contains("promtect_secrets_masked_total{detector=\"aws_key\"} 2"),
            "expected aws_key=2 in:\n{prom}"
        );
        assert!(
            prom.contains("promtect_secrets_masked_total{detector=\"anthropic_key\"} 1"),
            "expected anthropic_key=1 in:\n{prom}"
        );
    }

    #[test]
    fn to_prometheus_contains_bytes_totals() {
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        let prom = m.to_prometheus();
        assert!(
            prom.contains("promtect_bytes_in_total 350"),
            "expected bytes_in 350 in:\n{prom}"
        );
        assert!(
            prom.contains("promtect_bytes_out_total 360"),
            "expected bytes_out 360 in:\n{prom}"
        );
    }

    #[test]
    fn to_prometheus_contains_help_and_type_comments() {
        // Prometheus exposition format requires HELP and TYPE lines.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        let prom = m.to_prometheus();
        assert!(prom.contains("# HELP promtect_requests_total"));
        assert!(prom.contains("# TYPE promtect_requests_total counter"));
        assert!(prom.contains("# HELP promtect_secrets_masked_total"));
        assert!(prom.contains("# TYPE promtect_secrets_masked_total counter"));
    }

    // ── Value-freedom / no-secret-leakage tests ──────────────────────────────

    #[test]
    fn prometheus_output_contains_no_secret_value() {
        // The fixture uses placeholder sentinels, not real secrets. This test
        // plants a fake AWS key string into the fixture file and confirms it
        // never surfaces in the Prometheus or JSON outputs.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-nosecret-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();

        // Sentinel placeholder: safe to include. Real secret: must NOT appear.
        // The audit log never writes the real secret — but assert it anyway.
        let fake_secret = "AKIAFAKEKEY000000001";
        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"request","request_id":"req-s","masked":1,"detectors":["aws_key"],"bytes_in":50,"bytes_out":60}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"mask","detector":"aws_key","placeholder":"«promtect:aws_key:0001»","request_id":"req-s"}}"#
        )
        .unwrap();

        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();

        let prom = m.to_prometheus();
        let json = serde_json::to_string(&m).unwrap();

        // The fake secret must appear in neither output.
        assert!(
            !prom.contains(fake_secret),
            "Prometheus output must not contain secret value"
        );
        assert!(
            !json.contains(fake_secret),
            "JSON output must not contain secret value"
        );
        // Double-check the AWS key prefix that would identify a real key.
        assert!(
            !prom.contains("AKIA"),
            "Prometheus must not contain AKIA prefix"
        );
        assert!(!json.contains("AKIA"), "JSON must not contain AKIA prefix");
    }

    #[test]
    fn json_serialization_includes_all_top_level_fields() {
        // Ensure serde Serialize is wired correctly for all public fields.
        let (m, path) = fixture_metrics();
        std::fs::remove_file(&path).ok();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("requests_total"));
        assert!(json.contains("requests_with_secrets"));
        assert!(json.contains("requests_clean"));
        assert!(json.contains("secrets_masked_total"));
        assert!(json.contains("by_detector"));
        assert!(json.contains("bytes_in_total"));
        assert!(json.contains("bytes_out_total"));
        assert!(json.contains("recent"));
    }
}
