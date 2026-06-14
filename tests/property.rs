//! Property tests for the masking round-trip — the product's core invariant.
//! restore(mask(x)) == x, and a masked body never contains a planted secret.
//!
//! Inputs are built from random "safe" text (printable ASCII EXCLUDING the
//! guillemet sentinel delimiters « ») interleaved with synthetic secrets, so the
//! input can never accidentally collide with a generated sentinel. (Adversarial
//! inputs that embed a literal `«promtect:...»` are a documented out-of-scope edge.)

use promtect::{
    audit::Audit,
    mask::{mask_text, restore_text},
    stream::StreamRestorer,
    vault::Vault,
};
use proptest::prelude::*;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Printable ASCII text that cannot contain sentinel delimiters.
/// «  and » are Unicode codepoints > 127, so plain ASCII (0x20..=0x7E) already
/// excludes them — the comment is here to make the invariant explicit.
fn safe_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        // ' ' (0x20) to '~' (0x7E): the full printable ASCII range.
        // This range never produces « (U+00AB) or » (U+00BB).
        prop::char::ranges(std::borrow::Cow::Borrowed(&[' '..='~'])),
        0..40,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// A synthetic secret whose shape matches one of the detectors.
/// Each variant is generated with a fixed-length uppercase/lowercase/digit
/// suffix so it always hits its corresponding regex.
fn synthetic_secret() -> impl Strategy<Value = String> {
    // Uppercase hex-ish chars for AWS-style tokens.
    let uc = prop::collection::vec(
        prop_oneof![
            Just('A'),
            Just('B'),
            Just('C'),
            Just('D'),
            Just('E'),
            Just('F'),
            Just('0'),
            Just('1'),
            Just('2'),
            Just('3'),
            Just('4'),
            Just('5'),
            Just('6'),
            Just('7'),
            Just('8'),
            Just('9')
        ],
        16,
    )
    .prop_map(|v| v.into_iter().collect::<String>());

    // Lowercase alnum for Anthropic-style tokens (20 chars).
    let lc20 = prop::collection::vec(
        prop_oneof![
            prop::char::ranges(std::borrow::Cow::Borrowed(&['a'..='z'])),
            prop::char::ranges(std::borrow::Cow::Borrowed(&['0'..='9']))
        ],
        20,
    )
    .prop_map(|v| v.into_iter().collect::<String>());

    // Alphanumeric for GitHub tokens (exactly 36 chars).
    let alnum36 = prop::collection::vec(
        prop_oneof![
            prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z'])),
            prop::char::ranges(std::borrow::Cow::Borrowed(&['a'..='z'])),
            prop::char::ranges(std::borrow::Cow::Borrowed(&['0'..='9']))
        ],
        36,
    )
    .prop_map(|v| v.into_iter().collect::<String>());

    prop_oneof![
        // AWS access key: AKIA + 16 uppercase alnum
        uc.clone().prop_map(|s| format!("AKIA{s}")),
        // Anthropic key: sk-ant-api03- + 20 lowercase alnum
        lc20.clone().prop_map(|s| format!("sk-ant-api03-{s}")),
        // GitHub token: ghp_ + 36 alnum
        alnum36.prop_map(|s| format!("ghp_{s}")),
    ]
}

/// One segment in the assembled input: either innocuous text or a secret.
#[derive(Debug, Clone)]
enum Segment {
    Safe(String),
    Secret(String),
}

/// Strategy producing a list of 0..6 segments alternating safe/secret.
/// Secrets are always separated from adjacent content by a literal space,
/// preventing two adjacent secrets from concatenating into an undetectable span.
fn segments() -> impl Strategy<Value = Vec<Segment>> {
    prop::collection::vec(
        prop_oneof![
            safe_text().prop_map(Segment::Safe),
            synthetic_secret().prop_map(Segment::Secret),
        ],
        0..6,
    )
}

/// Like `segments()` but GUARANTEES at least one `Secret` segment.
///
/// The plain `segments()` strategy frequently yields zero secrets, which makes
/// the no-leak property vacuous (its loop iterates over an empty `planted_secrets`
/// and asserts nothing). Here we prepend a mandatory `synthetic_secret()` so the
/// assembled input always contains a real secret to hide.
fn segments_with_secret() -> impl Strategy<Value = Vec<Segment>> {
    (synthetic_secret(), segments()).prop_map(|(s, mut rest)| {
        rest.insert(0, Segment::Secret(s));
        rest
    })
}

/// Build the full input string and the list of planted secrets from a segment vec.
/// Adjacent segments are joined with a single space so that no two secrets run
/// together; this prevents the (documented) edge case where overlapping detector
/// spans could leave a secret partially exposed.
fn assemble(segs: &[Segment]) -> (String, Vec<String>) {
    let mut parts: Vec<String> = Vec::new();
    let mut secrets: Vec<String> = Vec::new();
    for seg in segs {
        match seg {
            Segment::Safe(s) => parts.push(s.clone()),
            Segment::Secret(s) => {
                secrets.push(s.clone());
                // Wrap secrets in spaces so they are word-boundary-isolated from
                // adjacent safe text or other secrets.
                parts.push(format!(" {s} "));
            }
        }
    }
    (parts.join(""), secrets)
}

/// Restore `masked` through the streaming restorer, fed in `size`-byte chunks.
/// This is the streaming-path equivalent of `restore_text` on the whole buffer.
fn stream_restore(vault: Arc<Vault>, masked: &str, size: usize) -> String {
    let mut sr = StreamRestorer::new(vault, Arc::new(Audit::null()), "prop".into());
    let mut out = Vec::new();
    for chunk in masked.as_bytes().chunks(size.max(1)) {
        let restored = sr.push(chunk);
        out.extend_from_slice(restored.as_ref());
    }
    let tail = sr.finish();
    out.extend_from_slice(tail.as_ref());
    String::from_utf8(out).expect("restored stream is valid UTF-8")
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn restore_undoes_mask(segs in segments()) {
        // Core invariant: the round-trip is lossless for sentinel-free inputs.
        let (input, _) = assemble(&segs);
        let vault = Vault::new();
        let audit = Audit::null();
        let masked = mask_text(&input, &vault, &audit, "prop");
        let restored = restore_text(&masked, &vault, &audit, "prop");
        prop_assert_eq!(restored, input);
    }

    #[test]
    fn masked_body_hides_every_planted_secret(segs in segments_with_secret()) {
        // No-leak invariant: a detected secret value never survives masking.
        let (input, planted_secrets) = assemble(&segs);
        // Precondition: `segments_with_secret()` guarantees a secret, so the loop
        // below always asserts something. This guards against the property going
        // vacuous (passing trivially because there was nothing to check).
        prop_assume!(!planted_secrets.is_empty());
        let vault = Vault::new();
        let audit = Audit::null();
        let masked = mask_text(&input, &vault, &audit, "prop");
        for secret in &planted_secrets {
            prop_assert!(
                !masked.contains(secret.as_str()),
                "leaked: {secret}"
            );
        }
    }

    /// Streaming proof: restoring the masked body chunk-by-chunk at ANY byte
    /// boundary yields exactly the same result as restoring the whole buffer —
    /// which is the original input. This is the correctness guarantee for SSE
    /// streaming, where sentinels are split across arbitrary chunk boundaries.
    #[test]
    fn streaming_restore_equals_whole_buffer(
        segs in segments_with_secret(),
        chunk in 1usize..40,
    ) {
        let (input, planted) = assemble(&segs);
        prop_assume!(!planted.is_empty());
        let vault = Arc::new(Vault::new());
        let audit = Audit::null();
        let masked = mask_text(&input, &vault, &audit, "prop");

        let whole = restore_text(&masked, &vault, &audit, "prop");
        let streamed = stream_restore(Arc::clone(&vault), &masked, chunk);

        prop_assert_eq!(&streamed, &whole, "chunked != whole at chunk size {}", chunk);
        prop_assert_eq!(&streamed, &input, "round-trip broken at chunk size {}", chunk);
    }
}
