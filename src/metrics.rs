// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Value-free observability metrics, aggregated from the audit log.
//!
//! This module is intentionally free of secret values. It reads the audit JSONL
//! produced by [`crate::audit::Audit`] and exposes only counts, detector kind
//! names, and byte totals. The output is safe to serve publicly (Stage 2 will
//! add the HTTP endpoint).

use serde::Serialize;
use std::collections::BTreeMap;
use std::io::BufRead;

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
    /// Total secrets the Pro output scan flagged in responses — ones the model
    /// echoed back or generated, which were never in the request. Stays `0` unless
    /// the Pro response output scan ran (the public core emits no such events).
    pub output_secrets_total: u64,
    /// Per-detector counts of output-scan findings (same kind names as
    /// [`Metrics::by_detector`], e.g. `"aws_key" -> 2`).
    pub output_by_detector: BTreeMap<String, u64>,
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

/// True iff `name` is a safe Prometheus label value for `detector="..."`.
///
/// # WHY (security)
/// Detector names in [`aggregate`] come from the audit *file*, which is parsed as
/// UNTRUSTED input. They are later interpolated unescaped into the Prometheus
/// exposition as `detector="{name}"`. A planted name containing a `"` or a `\n`
/// could close the label and forge an entire metric line (label injection). The
/// genuine detector registry only ever emits `[a-z0-9_]+` kinds, so we constrain
/// to exactly that charset and drop anything else — this both blocks injection
/// and rejects malformed/garbage names without needing label escaping.
///
/// An empty name is rejected (it could not name a real detector).
fn is_valid_detector_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Aggregate value-free metrics from an audit JSONL file.
///
/// # Behaviour
/// - Missing or empty file returns `Metrics::default()` (all zeros / empty).
/// - The file is read line-by-line through a buffered reader; it is never loaded
///   into memory in one allocation, so a pathologically large audit log cannot
///   OOM the dashboard.
/// - Malformed lines (bad JSON, or an I/O error mid-stream) are skipped
///   (best-effort), so a partially-written log still produces useful counts for
///   the lines that are valid.
/// - Detector names that are not `[a-z0-9_]+` are dropped (see
///   [`is_valid_detector_name`]) so an untrusted name cannot inject a label line.
/// - Only `"request"` and `"mask"` actions contribute to counters; `"unmask"` and
///   any unknown actions are silently ignored.
/// - `recent` is returned newest-first by `ts_ms` (the on-disk order is not
///   trusted because the proxy is concurrent), capped at [`RECENT_CAP`].
///
/// # Safety
/// This function never surfaces secret values. The audit log is designed to be
/// value-free, and this aggregator only reads the numeric/string metadata fields.
pub fn aggregate(audit_path: &std::path::Path) -> Metrics {
    let file = match std::fs::File::open(audit_path) {
        Ok(f) => f,
        // Missing or unreadable file is normal before the first request.
        Err(_) => return Metrics::default(),
    };
    // WHY: buffered line-by-line read instead of read_to_string — the audit file
    // is unbounded and attacker-influenceable in size; we must not allocate it
    // whole. Each line is parsed and dropped before the next is read.
    let reader = std::io::BufReader::new(file);

    let mut m = Metrics::default();

    for line in reader.lines() {
        // A mid-stream I/O error (e.g. concurrent truncation) ends iteration; the
        // counts gathered so far are still valid and returned.
        let Ok(line) = line else {
            break;
        };

        let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) else {
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

                // Capture the value-free recent summary.
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

                m.recent.push(RecentRequest {
                    ts_ms,
                    request_id,
                    masked,
                    detectors,
                });
                // No interim cap: the final sort+truncate at the end of this
                // function handles ordering correctly without O(N²) interim sorts.
            }
            "mask" => {
                m.secrets_masked_total += 1;
                // Detector name comes from the "detector" field of mask events.
                // It is untrusted (from the file): only count validated names so a
                // planted name cannot forge a Prometheus label line downstream.
                if let Some(det) = val.get("detector").and_then(|v| v.as_str())
                    && is_valid_detector_name(det)
                {
                    *m.by_detector.entry(det.to_string()).or_default() += 1;
                }
            }
            // Pro output scan: a secret found in the RESPONSE (model-echoed or
            // generated). Same value-free shape as a mask event; counted into its
            // own totals so the dashboard can distinguish inbound-reply leaks from
            // outbound request masking.
            "output_secret" => {
                m.output_secrets_total += 1;
                if let Some(det) = val.get("detector").and_then(|v| v.as_str())
                    && is_valid_detector_name(det)
                {
                    *m.output_by_detector.entry(det.to_string()).or_default() += 1;
                }
            }
            // "unmask" and unknown actions are intentionally ignored for counts.
            _ => {}
        }
    }

    // Final sort so the output is newest-first regardless of on-disk ordering.
    // (The interim trims above only ran when over-cap; small files skip them.)
    sort_recent_newest_first(&mut m.recent);
    m.recent.truncate(RECENT_CAP);

    m
}

/// Sort recent-request summaries newest-first by `ts_ms` (descending).
///
/// A stable sort is used so that entries sharing a `ts_ms` keep their relative
/// read order, giving deterministic output for same-millisecond requests.
fn sort_recent_newest_first(recent: &mut [RecentRequest]) {
    recent.sort_by_key(|b| std::cmp::Reverse(b.ts_ms));
}

impl Metrics {
    /// Render Prometheus text-exposition format (hand-rolled; no extra dependency).
    ///
    /// Produces HELP/TYPE comment pairs followed by metric lines. Detector names
    /// in `by_detector` are constrained to `[a-z0-9_]+` by [`aggregate`] (the
    /// audit file is untrusted), so no label escaping is needed here and no
    /// planted name can inject a metric line. The output ends with a trailing
    /// newline.
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
            // Names here are already validated to [a-z0-9_]+ by aggregate(), so
            // direct interpolation into the label cannot break out or inject.
            out.push_str(&format!(
                "promtect_secrets_masked_total{{detector=\"{detector}\"}} {count}\n"
            ));
        }

        // Pro output scan: secrets found in the RESPONSE (model-echoed/generated).
        push_counter(
            &mut out,
            "promtect_output_secrets_total",
            "Secrets the output scan found in responses (model-echoed or generated).",
            self.output_secrets_total,
            None,
        );
        out.push_str(
            "# HELP promtect_output_secrets_by_detector Output-scan findings, by detector.\n",
        );
        out.push_str("# TYPE promtect_output_secrets_by_detector counter\n");
        for (detector, count) in &self.output_by_detector {
            // Names are validated to [a-z0-9_]+ by aggregate(); safe to interpolate.
            out.push_str(&format!(
                "promtect_output_secrets_by_detector{{detector=\"{detector}\"}} {count}\n"
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
        writeln!(
            f,
            r#"{{"ts_ms":5000,"action":"output_secret","detector":"aws_key","placeholder":"«output-scan»","request_id":"req-2"}}"#
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
    fn aggregate_counts_output_scan_findings() {
        // 1 "output_secret" event in the fixture (aws_key) → counted into the
        // output-scan totals and exported to Prometheus, separate from masking.
        let (m, path) = fixture_metrics();
        let prom = m.to_prometheus();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.output_secrets_total, 1);
        assert_eq!(m.output_by_detector.get("aws_key"), Some(&1));
        assert!(prom.contains("promtect_output_secrets_total 1"));
        assert!(prom.contains("promtect_output_secrets_by_detector{detector=\"aws_key\"} 1"));
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

    // ── #47 Low: hardening regressions ───────────────────────────────────────

    /// Pins: a detector name from the (untrusted) audit file carrying a `"` or a
    /// newline must not forge or inject a Prometheus metric line. Names that are
    /// not `[a-z0-9_]+` are dropped at aggregation time, so they never reach the
    /// label string in `to_prometheus`.
    #[test]
    fn prometheus_label_injection_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-inject-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();

        // A planted name that closes the label and appends a forged line. JSON
        // string-escapes the quote and newline so the line itself stays valid
        // JSON — the danger is only after it is parsed back to a Rust string.
        // Written via write_all (not writeln!) so the literal braces in the JSON
        // are not interpreted as format placeholders.
        let lines = [
            r#"{"action":"mask","detector":"x\" } 1\npromtect_forged_total 999","request_id":"evil"}"#,
            // A separate planted name using a raw quote in the kind.
            r#"{"action":"mask","detector":"a\"b","request_id":"evil"}"#,
            // A legitimate name, to prove valid detectors still pass through.
            r#"{"action":"mask","detector":"aws_key","request_id":"ok"}"#,
        ];
        for line in lines {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }

        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();

        let prom = m.to_prometheus();

        // The forged line must not appear anywhere in the output.
        assert!(
            !prom.contains("promtect_forged_total"),
            "injected metric line leaked into Prometheus output:\n{prom}"
        );
        // No label line may contain the planted-name fragments. Each malformed
        // name embeds a `"` mid-string; a clean output has exactly one quoted
        // detector per line, so the planted fragments must be absent entirely.
        assert!(
            !prom.contains("x\\\"") && !prom.contains("x\" "),
            "malformed detector name 'x...' reached the label string:\n{prom}"
        );
        assert!(
            !prom.contains("a\"b") && !prom.contains("a\\\"b"),
            "malformed detector name 'a\"b' reached the label string:\n{prom}"
        );
        // The invalid names must have been dropped from the breakdown entirely.
        assert!(
            !m.by_detector
                .keys()
                .any(|k| k.contains('"') || k.contains('\n')),
            "invalid detector name retained in by_detector: {:?}",
            m.by_detector.keys().collect::<Vec<_>>()
        );
        // The legitimate detector is still counted.
        assert_eq!(m.by_detector.get("aws_key").copied(), Some(1));
    }

    /// Pins: `recent` is sorted newest-first by `ts_ms`, even when the audit log
    /// is interleaved / out-of-order on disk (the proxy is concurrent, so lines
    /// are not guaranteed to be in timestamp order).
    #[test]
    fn aggregate_recent_sorts_out_of_order_timestamps() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-order-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();

        // Deliberately out of timestamp order on disk: 2000, then 1000, then 3000.
        writeln!(
            f,
            r#"{{"ts_ms":2000,"action":"request","request_id":"mid","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":1000,"action":"request","request_id":"old","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"ts_ms":3000,"action":"request","request_id":"new","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
        )
        .unwrap();

        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();

        // Newest ts_ms first regardless of file order.
        assert_eq!(m.recent[0].request_id, "new");
        assert_eq!(m.recent[1].request_id, "mid");
        assert_eq!(m.recent[2].request_id, "old");
    }

    /// Pins: the cap keeps the NEWEST entries by `ts_ms`, not the first-read ones.
    /// With out-of-order input, sorting must precede truncation so the oldest
    /// rows are the ones dropped.
    #[test]
    fn aggregate_recent_cap_keeps_newest_after_sort() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-cap-order-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        // Write 25 rows with DESCENDING ts_ms so the first-read rows are newest.
        // After a correct sort-then-truncate, the kept rows are ts_ms 24..5.
        for i in (0u64..25).rev() {
            writeln!(
                f,
                r#"{{"ts_ms":{i},"action":"request","request_id":"req-{i}","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
            )
            .unwrap();
        }
        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();

        assert_eq!(m.recent.len(), RECENT_CAP);
        // Newest first, and the oldest 5 (ts_ms 0..4) must have been dropped.
        assert_eq!(m.recent[0].ts_ms, 24);
        assert_eq!(m.recent[RECENT_CAP - 1].ts_ms, 5);
    }

    /// Pins: a large audit file is processed line-by-line (streamed), proving the
    /// aggregator does not need to materialise the whole file in one allocation.
    /// This is a behavioural proxy for the unbounded-read fix — all lines count.
    #[test]
    fn aggregate_streams_many_lines_without_loading_whole_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "promtect-metrics-many-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        // 50_000 request rows: well past anything we'd want in one String, but
        // small enough to stay fast in CI.
        {
            let mut w = std::io::BufWriter::new(&mut f);
            for i in 0u64..50_000 {
                writeln!(
                    w,
                    r#"{{"ts_ms":{i},"action":"request","request_id":"r-{i}","masked":0,"detectors":[],"bytes_in":1,"bytes_out":1}}"#
                )
                .unwrap();
            }
        }
        let m = aggregate(&path);
        std::fs::remove_file(&path).ok();

        // Every line was counted, and recent is still capped.
        assert_eq!(m.requests_total, 50_000);
        assert_eq!(m.recent.len(), RECENT_CAP);
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
        // Output-scan fields must serialize too, so the dashboard JSON exposes them.
        assert!(json.contains("output_secrets_total"));
        assert!(json.contains("output_by_detector"));
    }
}
