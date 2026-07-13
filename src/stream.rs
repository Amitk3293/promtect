// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Streaming secret restoration.
//!
//! The proxy must not buffer the whole upstream response before restoring
//! secrets — Claude Code (and every other tool) streams its answer as
//! Server-Sent Events, and buffering turns that into a multi-second "hang".
//! [`StreamRestorer`] restores sentinels incrementally as bytes arrive, holding
//! back only the minimum tail that might still be part of a sentinel or a
//! partial UTF-8 codepoint.
//!
//! ## Correctness
//!
//! The hard case is a sentinel split across a chunk boundary
//! (`…«promtect:aws_key:00` | `01»…`). We never emit bytes that could still be
//! part of an arriving sentinel, so a sentinel is only ever restored once it is
//! fully present. This makes streamed output byte-for-byte identical to
//! restoring the fully-buffered body — proven by the equivalence property test
//! in `tests/property.rs`.

use crate::audit::Audit;
use crate::mask::restore_scan;
use crate::vault::Vault;
use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream::BoxStream};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A response-side detection pass, injected by `promtect-pro` (license-gated):
/// it scans the restored response text for secrets the model echoed back or
/// generated itself (which were never in the request, so the request-side mask
/// never saw them). `None` in the public core.
///
/// This is OBSERVE-ONLY. The scanner's matches drive an audit entry and a stderr
/// warning; they never alter the bytes streamed to the client, so restored output
/// stays byte-for-byte identical to a build without it.
pub type ResponseScanner = Arc<dyn Fn(&str) -> Vec<crate::detect::Match> + Send + Sync>;

/// Overlap window (bytes) carried between restored chunks so a generated secret
/// split across a chunk boundary is still seen whole by the output scan.
/// ponytail: fixed 256-byte window — a secret longer than this split exactly on a
/// boundary can be missed; acceptable for a warn-only backstop, widen if needed.
const OUTPUT_SCAN_OVERLAP: usize = 256;

/// First byte of the two-byte UTF-8 encoding of `«` (U+00AB) and `»` (U+00BB).
const GUILLEMET_LEAD: u8 = 0xC2;
/// Second byte of `«` (U+00AB).
const OPEN_TAIL: u8 = 0xAB;
/// Second byte of `»` (U+00BB).
const CLOSE_TAIL: u8 = 0xBB;

/// Incrementally restores vault sentinels in a streamed response body.
///
/// Feed each upstream chunk to [`StreamRestorer::push`]; call
/// [`StreamRestorer::finish`] once at end-of-stream to flush the tail. Both
/// return bytes ready to forward to the client.
pub struct StreamRestorer {
    vault: Arc<Vault>,
    audit: Arc<Audit>,
    request_id: String,
    /// Longest sentinel registered for this request. A run of bytes that opens
    /// with `«` but exceeds this length without closing cannot be a sentinel, so
    /// we stop holding it — this bounds the carry buffer and stops a stray `«`
    /// from stalling the stream. Zero when the request had no secrets (the body
    /// then streams straight through, modulo partial-codepoint safety).
    cap: usize,
    /// Bytes held back because they might be part of a still-arriving sentinel or
    /// a partial multi-byte UTF-8 codepoint.
    carry: Vec<u8>,
    /// Sentinels already written to the audit log, so each is recorded exactly
    /// once across the whole stream rather than once per chunk it appears in.
    audited: HashSet<String>,
    /// Optional response-side detection pass (Pro, license-gated). `None` leaves
    /// the restorer byte-for-byte identical to the public core.
    scanner: Option<ResponseScanner>,
    /// Trailing window of already-restored text, prepended to the next chunk so a
    /// generated secret split across a chunk boundary is still scanned whole.
    scan_tail: String,
    /// Distinct (kind, value) secrets already reported by the output scan, so each
    /// is warned about once across the stream, not once per chunk or overlap.
    flagged: HashSet<(&'static str, String)>,
}

impl StreamRestorer {
    /// Build a restorer for one request. `cap` is read from the vault, which is
    /// already fully populated by the time the response streams back (masking of
    /// the request completed before the upstream call).
    pub fn new(vault: Arc<Vault>, audit: Arc<Audit>, request_id: String) -> Self {
        let cap = vault.max_sentinel_len();
        Self {
            vault,
            audit,
            request_id,
            cap,
            carry: Vec::new(),
            audited: HashSet::new(),
            scanner: None,
            scan_tail: String::new(),
            flagged: HashSet::new(),
        }
    }

    /// Attach an optional response-side output scanner (Pro). `None` is a no-op,
    /// keeping the public core's behavior unchanged. Builder style so existing
    /// call sites and tests that don't scan stay untouched.
    #[must_use]
    pub fn with_output_scanner(mut self, scanner: Option<ResponseScanner>) -> Self {
        self.scanner = scanner;
        self
    }

    /// Feed one upstream chunk. Returns the bytes now safe to emit, with every
    /// complete, known sentinel replaced by its real secret. Bytes that might
    /// still be part of an arriving sentinel — or a partial UTF-8 codepoint — are
    /// retained until the next `push` or `finish`.
    pub fn push(&mut self, chunk: &[u8]) -> Bytes {
        self.carry.extend_from_slice(chunk);
        let cut = self.safe_cut();
        if cut == 0 {
            return Bytes::new();
        }
        let safe: Vec<u8> = self.carry.drain(..cut).collect();
        // `safe` ends on a UTF-8 boundary by construction (cut <= valid_up_to),
        // so the lossy conversion never inserts a replacement char.
        let text = String::from_utf8_lossy(&safe);
        Bytes::from(self.restore_str(&text))
    }

    /// Flush any retained bytes at end-of-stream, restoring what can be restored.
    /// A trailing open `«` that never closed is emitted verbatim.
    pub fn finish(&mut self) -> Bytes {
        if self.carry.is_empty() {
            return Bytes::new();
        }
        let rest = std::mem::take(&mut self.carry);
        match std::str::from_utf8(&rest) {
            Ok(text) => Bytes::from(self.restore_str(text)),
            // Stream ended mid-codepoint (truncated/corrupt upstream). Emit the raw
            // bytes verbatim rather than lossily inserting U+FFFD — matching the
            // whole-buffer path, which forwards non-UTF-8 bodies byte-for-byte. Any
            // held-back sentinel is valid UTF-8, so it never lands in this branch.
            Err(_) => Bytes::from(rest),
        }
    }

    /// Largest prefix length of `carry` that is safe to restore and emit now:
    /// the minimum of the last UTF-8 boundary and the start of any trailing,
    /// still-possible sentinel.
    fn safe_cut(&self) -> usize {
        let buf = &self.carry;
        // Never split a multi-byte codepoint: only the final 1–3 bytes can be an
        // incomplete codepoint in a valid UTF-8 stream.
        let utf8_bound = match std::str::from_utf8(buf) {
            Ok(_) => buf.len(),
            Err(e) => e.valid_up_to(),
        };
        // Hold back a trailing `«` that has not closed yet — but only while it is
        // still short enough to become a real sentinel.
        let open_bound = match last_unclosed_open(buf) {
            Some(p) if buf.len() - p <= self.cap => p,
            _ => buf.len(),
        };
        utf8_bound.min(open_bound)
    }

    /// Replace every known sentinel in `s` with its secret, auditing each distinct
    /// sentinel once per stream. Delegates to the single-pass `mask::restore_scan`
    /// so the streaming and whole-buffer paths share identical (cascade-free)
    /// restore semantics.
    fn restore_str(&mut self, s: &str) -> String {
        let restored = restore_scan(
            s,
            &self.vault,
            &self.audit,
            &self.request_id,
            &mut self.audited,
        );
        // Observe-only: scan the restored text but return it unchanged.
        self.scan_output(&restored);
        restored
    }

    /// Scan restored output for secrets the model produced (not from the request).
    /// Each distinct (kind, value) is recorded value-free in the audit log and
    /// warned to stderr exactly once. The streamed bytes are never modified.
    fn scan_output(&mut self, restored: &str) {
        // Clone the Arc first so `self` is free to mutate (flagged/audit) below.
        let Some(scanner) = self.scanner.clone() else {
            return;
        };
        // Prepend the overlap tail so a secret straddling two chunks is seen whole.
        let hay = format!("{}{}", self.scan_tail, restored);
        for m in scanner(&hay) {
            // Ignore the user's own request secrets that we just restored — those
            // are expected in the response. Only flag values the response itself
            // introduced (a secret the model echoed or generated).
            if self.vault.knows_secret(m.value.as_str()) {
                continue;
            }
            if self.flagged.insert((m.kind, m.value.as_str().to_owned())) {
                // Value-free: only the detector kind is recorded, never the secret.
                self.audit
                    .record("output_secret", m.kind, "«output-scan»", &self.request_id);
                // Suppressed under guard (quiet mode) so it does not corrupt a
                // wrapped TUI; the event is still audited and shown in the summary.
                if !crate::proxy::is_quiet() {
                    let id = self.request_id.get(..8).unwrap_or(self.request_id.as_str());
                    eprintln!(
                        "[promtect] \u{26a0}\u{fe0f}  output req {id}: response contained a {} the model produced \u{2014} not from your prompt",
                        m.kind
                    );
                }
            }
        }
        // Roll the overlap window forward over the just-scanned text.
        self.scan_tail = tail_of(&hay, OUTPUT_SCAN_OVERLAP);
    }
}

/// Last `n` bytes of `s` as an owned string, snapped up to the next UTF-8 char
/// boundary so the result is always valid UTF-8. Returns the whole string when
/// it is already `<= n` bytes.
fn tail_of(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let mut start = s.len() - n;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_owned()
}

/// Byte index of the last `«` that has no `»` after it — a sentinel that may
/// still be completing at the tail of `buf`. Returns `None` when the final
/// guillemets are balanced (no open sentinel at the end).
fn last_unclosed_open(buf: &[u8]) -> Option<usize> {
    let open = rfind_pair(buf, GUILLEMET_LEAD, OPEN_TAIL);
    let close = rfind_pair(buf, GUILLEMET_LEAD, CLOSE_TAIL);
    match (open, close) {
        (Some(o), Some(c)) if o > c => Some(o),
        (Some(o), None) => Some(o),
        _ => None,
    }
}

/// Index of the last position where the two bytes `a`,`b` appear in order.
fn rfind_pair(buf: &[u8], a: u8, b: u8) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    (0..=buf.len() - 2)
        .rev()
        .find(|&i| buf[i] == a && buf[i + 1] == b)
}

/// State for [`restore_stream`]'s `unfold`: reading the upstream, about to emit a
/// deferred error (after the carry was flushed), or finished.
enum St<E> {
    // The restorer is boxed: it now carries an output-scan window and dedup set,
    // so keeping it inline would make this variant far larger than the others.
    Reading(BoxStream<'static, Result<Bytes, E>>, Box<StreamRestorer>),
    Erroring(E),
    Done,
}

/// Adapt an upstream byte stream into a restored byte stream: every chunk runs
/// through `sr`, and a final flush is emitted when the upstream ends. On a
/// mid-stream upstream error the retained carry is flushed FIRST (so no held bytes
/// are silently dropped), then the error is forwarded and the stream ends.
pub fn restore_stream<E>(
    upstream: BoxStream<'static, Result<Bytes, E>>,
    sr: StreamRestorer,
) -> impl Stream<Item = Result<Bytes, E>> + Send
where
    E: Send + 'static,
{
    futures_util::stream::unfold(St::Reading(upstream, Box::new(sr)), |st| async move {
        match st {
            St::Reading(mut up, mut sr) => match up.next().await {
                Some(Ok(chunk)) => {
                    let out = sr.push(&chunk);
                    Some((Ok(out), St::Reading(up, sr)))
                }
                // Upstream errored mid-stream: flush whatever the restorer held
                // back so those bytes are not lost, THEN surface the error next.
                Some(Err(e)) => {
                    let tail = sr.finish();
                    if tail.is_empty() {
                        Some((Err(e), St::Done))
                    } else {
                        Some((Ok(tail), St::Erroring(e)))
                    }
                }
                // Upstream finished: flush the retained tail, then end.
                None => {
                    let tail = sr.finish();
                    Some((Ok(tail), St::Done))
                }
            },
            St::Erroring(e) => Some((Err(e), St::Done)),
            St::Done => None,
        }
    })
}

/// Shared completion state for a downstream response stream.
///
/// The response body exposes this as the value-free
/// `promtect-stream-outcome` HTTP trailer after all payload bytes. A trailer is
/// used because an interruption is not knowable when the response headers are
/// first sent, and adding a marker to an SSE/NDJSON payload would corrupt the
/// provider protocol.
#[derive(Clone)]
pub(crate) struct StreamOutcome {
    interrupted: Arc<AtomicBool>,
}

impl StreamOutcome {
    pub(crate) fn was_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Acquire)
    }
}

/// Observe failures in a byte-preserving downstream response stream.
///
/// Every successful upstream byte and every source error is forwarded unchanged.
/// The error also produces one value-free audit event. Keeping the error in the
/// stream makes ordinary clients fail on truncated SSE, NDJSON, JSON, or binary
/// bodies instead of accepting a clean EOF merely because they ignore trailers.
pub(crate) fn observe_stream_errors<E, S>(
    stream: S,
    audit: Arc<Audit>,
    request_id: String,
) -> (impl Stream<Item = Result<Bytes, E>> + Send, StreamOutcome)
where
    E: Send + 'static,
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
{
    let outcome = StreamOutcome {
        interrupted: Arc::new(AtomicBool::new(false)),
    };
    let outcome_for_stream = outcome.clone();
    let observed = stream.map(move |item| match item {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            outcome_for_stream
                .interrupted
                .store(true, Ordering::Release);
            audit.record(
                "stream_interrupted",
                "upstream",
                "«stream-interrupted»",
                &request_id,
            );
            Err(error)
        }
    });
    (observed, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::restore_text;

    /// Register a secret and return (vault, sentinel) so tests can build bodies
    /// containing real sentinels.
    fn vault_with(secret: &str, kind: &str) -> (Arc<Vault>, String) {
        let vault = Arc::new(Vault::new());
        let sentinel = vault.sentinel_for(kind, secret);
        (vault, sentinel)
    }

    /// Drive a `StreamRestorer` over `body` split into chunks of `size` bytes and
    /// return the concatenated output.
    fn run_chunked(vault: Arc<Vault>, body: &[u8], size: usize) -> Vec<u8> {
        let mut sr = StreamRestorer::new(vault, Audit::null().into(), "req".into());
        let mut out = Vec::new();
        for chunk in body.chunks(size.max(1)) {
            out.extend_from_slice(&sr.push(chunk));
        }
        out.extend_from_slice(&sr.finish());
        out
    }

    #[test]
    fn whole_buffer_in_one_push_matches_restore_text() {
        let (vault, sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let body = format!("answer: {sentinel} done");
        let got = run_chunked(Arc::clone(&vault), body.as_bytes(), body.len());

        let expected = restore_text(&body, &vault, &Audit::null(), "req");
        assert_eq!(String::from_utf8(got).unwrap(), expected);
    }

    /// A scanner that just reuses the core detectors, for output-scan tests.
    fn detect_scanner() -> ResponseScanner {
        Arc::new(|t: &str| crate::detect::detect(t))
    }

    /// The output scan flags a secret the response introduced, but ignores the
    /// user's own request secret that the restorer puts back.
    #[test]
    fn output_scan_flags_model_secret_but_ignores_restored_request_secret() {
        let (vault, sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let model_key = "AKIA1234567890ABCDEF";
        let body = format!("your key {sentinel} and a fresh one {model_key} ok");
        let mut sr =
            StreamRestorer::new(Arc::clone(&vault), Audit::null().into(), "reqid1234".into())
                .with_output_scanner(Some(detect_scanner()));
        for chunk in body.as_bytes().chunks(8) {
            let _ = sr.push(chunk);
        }
        let _ = sr.finish();

        assert!(
            !sr.flagged.iter().any(|(_, v)| v == "AKIAIOSFODNN7EXAMPLE"),
            "restored request secret must be ignored by the output scan"
        );
        assert!(
            sr.flagged
                .iter()
                .any(|(k, v)| *k == "aws_key" && v == model_key),
            "model-generated key must be flagged, got {:?}",
            sr.flagged
        );
    }

    /// The output scan is observe-only: streamed bytes are identical with and
    /// without a scanner attached.
    #[test]
    fn output_scan_does_not_change_streamed_bytes() {
        let (vault, sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let body = format!("a {sentinel} b AKIA1234567890ABCDEF c");
        let baseline = run_chunked(Arc::clone(&vault), body.as_bytes(), 5);

        let mut sr = StreamRestorer::new(Arc::clone(&vault), Audit::null().into(), "req".into())
            .with_output_scanner(Some(detect_scanner()));
        let mut scanned = Vec::new();
        for chunk in body.as_bytes().chunks(5) {
            scanned.extend_from_slice(&sr.push(chunk));
        }
        scanned.extend_from_slice(&sr.finish());

        assert_eq!(
            baseline, scanned,
            "output scan must not alter streamed bytes"
        );
    }

    /// A secret split across chunk boundaries is still caught via the overlap window.
    #[test]
    fn output_scan_catches_secret_split_across_chunks() {
        let vault = Arc::new(Vault::new());
        let model_key = "AKIA1234567890ABCDEF";
        let body = format!("prefix text then {model_key} suffix");
        let mut sr = StreamRestorer::new(vault, Audit::null().into(), "req".into())
            .with_output_scanner(Some(detect_scanner()));
        // 4-byte chunks guarantee the key is split across several pushes.
        for chunk in body.as_bytes().chunks(4) {
            let _ = sr.push(chunk);
        }
        let _ = sr.finish();

        assert!(
            sr.flagged
                .iter()
                .any(|(k, v)| *k == "aws_key" && v == model_key),
            "a key split across chunks must still be caught, got {:?}",
            sr.flagged
        );
    }

    #[test]
    fn sentinel_split_byte_by_byte_is_restored() {
        let (vault, sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let body = format!("data: {{\"x\":\"{sentinel}\"}}\n\n");
        // One byte at a time is the worst case for boundary handling.
        let got = run_chunked(Arc::clone(&vault), body.as_bytes(), 1);
        let got = String::from_utf8(got).unwrap();

        let expected = restore_text(&body, &vault, &Audit::null(), "req");
        assert_eq!(got, expected);
        // The real secret made it back into the stream, and no sentinel leaked.
        assert!(got.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!got.contains("«promtect:"));
    }

    #[test]
    fn every_chunk_size_matches_whole_buffer() {
        let (vault, sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        // Multibyte content around — and DIRECTLY adjacent to — the sentinel
        // exercises partial-codepoint cuts and the guillemet-vs-codepoint boundary
        // (`«` is 0xC2 0xAB; 0xC2 can never be a UTF-8 continuation byte, so a `«`
        // lead always lands on a codepoint boundary — this proves it at every cut).
        let body = format!("héllo {sentinel} wörld {sentinel}! Ã{sentinel}Ω{sentinel}");
        let expected = restore_text(&body, &vault, &Audit::null(), "req");
        for size in 1..=body.len() {
            let got = run_chunked(Arc::clone(&vault), body.as_bytes(), size);
            assert_eq!(
                String::from_utf8(got).unwrap(),
                expected,
                "mismatch at chunk size {size}"
            );
        }
    }

    #[test]
    fn no_secrets_streams_through_unchanged() {
        // cap == 0: nothing to restore, body must pass through verbatim.
        let vault = Arc::new(Vault::new());
        let body = "data: {\"hello\":\"wörld «not a sentinel»\"}\n\n";
        let got = run_chunked(vault, body.as_bytes(), 3);
        assert_eq!(String::from_utf8(got).unwrap(), body);
    }

    #[test]
    fn truncated_trailing_codepoint_emitted_verbatim() {
        // Upstream closes mid-codepoint: the final byte 0xC3 opens a 2-byte
        // sequence that never completes. finish() must emit it raw, not lossily
        // insert U+FFFD — output stays byte-identical to the (already-truncated)
        // input, matching the proxy's verbatim pass-through for non-UTF-8 bytes.
        let vault = Arc::new(Vault::new());
        let body: &[u8] = b"hello w\xC3";
        let got = run_chunked(vault, body, body.len());
        assert_eq!(got, body);
    }

    #[test]
    fn unknown_sentinel_is_left_intact() {
        let (vault, _real) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let body = "stray «promtect:aws_key:9999» here";
        let got = run_chunked(Arc::clone(&vault), body.as_bytes(), 4);
        assert_eq!(String::from_utf8(got).unwrap(), body);
    }

    #[test]
    fn trailing_open_guillemet_is_flushed_verbatim() {
        let (vault, _s) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        // Opens a sentinel-looking run that never closes; must not be swallowed.
        let body = "tail «promtect:aws_key:00";
        let got = run_chunked(Arc::clone(&vault), body.as_bytes(), 2);
        assert_eq!(String::from_utf8(got).unwrap(), body);
    }

    #[test]
    fn empty_input_is_handled() {
        let (vault, _s) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let mut sr = StreamRestorer::new(vault, Audit::null().into(), "r".into());
        assert!(sr.push(b"").is_empty());
        assert!(sr.finish().is_empty());
    }

    /// Two sentinels back-to-back (no separator) must each restore correctly at
    /// EVERY split point — including a cut landing exactly between `»` and `«`.
    #[test]
    fn adjacent_sentinels_split_at_boundary_restore() {
        let vault = Arc::new(Vault::new());
        let s1 = vault.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        let s2 = vault.sentinel_for("anthropic_key", "sk-ant-api03-secretvalue123456");
        let body = format!("{s1}{s2}");
        let expected = restore_text(&body, &vault, &Audit::null(), "r");
        for size in 1..=body.len() {
            let got = run_chunked(Arc::clone(&vault), body.as_bytes(), size);
            assert_eq!(
                String::from_utf8(got).unwrap(),
                expected,
                "mismatch at chunk size {size}"
            );
        }
        assert!(expected.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(expected.contains("sk-ant-api03-secretvalue123456"));
        assert!(!expected.contains("«promtect:"));
    }

    /// On a mid-stream upstream error with bytes still HELD in the carry, those
    /// bytes are flushed (emitted verbatim) BEFORE the error — never silently
    /// dropped — exercising the `St::Erroring` path.
    #[tokio::test]
    async fn upstream_error_flushes_held_carry_then_errors() {
        #[derive(Debug)]
        struct TestErr;
        let (vault, _s) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let sr = StreamRestorer::new(vault, Audit::null().into(), "r".into());
        // First chunk opens a sentinel that is held in carry; then the error.
        let upstream = futures_util::stream::iter(vec![
            Ok::<Bytes, TestErr>(Bytes::from("x «promtect:aws_key:00")),
            Err(TestErr),
        ])
        .boxed();
        let items: Vec<Result<Bytes, TestErr>> = restore_stream(upstream, sr).collect().await;

        assert!(
            matches!(items.last(), Some(Err(_))),
            "must end with the error"
        );
        let emitted: Vec<u8> = items
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .flat_map(|b| b.to_vec())
            .collect();
        assert_eq!(
            String::from_utf8(emitted).unwrap(),
            "x «promtect:aws_key:00",
            "held carry bytes must be flushed, not dropped, before the error"
        );
    }

    #[tokio::test]
    async fn observed_interruption_preserves_bytes_propagates_error_and_audits() {
        #[derive(Debug)]
        struct TestErr;

        let path = std::env::temp_dir().join(format!(
            "promtect-stream-outcome-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let audit = Arc::new(Audit::to_file(path.clone()));
        let (vault, _sentinel) = vault_with("AKIAIOSFODNN7EXAMPLE", "aws_key");
        let sr = StreamRestorer::new(vault, Arc::clone(&audit), "request-1".into());
        let partial = "data: «promtect:aws_key:00";
        let upstream = futures_util::stream::iter(vec![
            Ok::<Bytes, TestErr>(Bytes::from(partial)),
            Err(TestErr),
        ])
        .boxed();

        let restored = restore_stream(upstream, sr);
        let (observed, outcome) =
            observe_stream_errors(restored, Arc::clone(&audit), "request-1".into());
        let items: Vec<Result<Bytes, TestErr>> = observed.collect().await;
        assert!(
            matches!(items.last(), Some(Err(_))),
            "successful bytes must be followed by the source error"
        );
        let emitted: Vec<u8> = items
            .iter()
            .filter_map(|item| item.as_ref().ok())
            .flat_map(|bytes| bytes.iter().copied())
            .collect();
        drop(audit);

        let log = std::fs::read_to_string(&path).expect("read stream outcome audit");
        std::fs::remove_file(&path).ok();
        assert_eq!(emitted, partial.as_bytes());
        assert!(outcome.was_interrupted());
        assert!(log.contains("\"action\":\"stream_interrupted\""));
        assert!(!log.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
