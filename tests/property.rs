//! Property tests for the masking round-trip — the product's core invariant.
//! restore(mask(x)) == x, and a masked body never contains a planted secret.
//!
//! Inputs are built from random "safe" text (printable ASCII EXCLUDING the
//! guillemet sentinel delimiters « ») interleaved with synthetic secrets, so the
//! input can never accidentally collide with a generated sentinel. (Adversarial
//! inputs that embed a literal `«airlock:...»` are a documented out-of-scope edge.)

use airlock::{
    audit::Audit,
    mask::{mask_text, restore_text},
    vault::Vault,
};
use proptest::prelude::*;

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

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
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
    fn masked_body_hides_every_planted_secret(segs in segments()) {
        // No-leak invariant: a detected secret value never survives masking.
        let (input, planted_secrets) = assemble(&segs);
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
}
