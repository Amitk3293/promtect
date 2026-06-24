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
        }
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
        restore_scan(
            s,
            &self.vault,
            &self.audit,
            &self.request_id,
            &mut self.audited,
        )
    }
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
    Reading(BoxStream<'static, Result<Bytes, E>>, StreamRestorer),
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
    futures_util::stream::unfold(St::Reading(upstream, sr), |st| async move {
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
}
