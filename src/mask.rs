use crate::audit::Audit;
use crate::detect;
use crate::vault::Vault;

/// Replace every detected secret in `text` with its vault sentinel.
/// Records one audit event per unique sentinel (not per occurrence). Returns the masked text.
pub fn mask_text(text: &str, vault: &Vault, audit: &Audit, request_id: &str) -> String {
    // detect() returns non-overlapping spans sorted by start. Splice from the END
    // so earlier byte offsets stay valid as we mutate the string.
    let mut matches = detect::detect(text);
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
    let mut out = text.to_string();
    // Track sentinels already audited this call: conversation history causes the same
    // value to appear many times in one request body, producing one sentinel but many
    // occurrences. Audit once per unique sentinel, not once per occurrence.
    let mut audited: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in matches {
        let sentinel = vault.sentinel_for(m.kind, &m.value);
        out.replace_range(m.start..m.end, &sentinel);
        if audited.insert(sentinel.clone()) {
            audit.record("mask", m.kind, &sentinel, request_id);
        }
    }
    out
}

/// Compiled matcher for a Promtect sentinel token `«promtect:KIND:HEX»`.
/// The kind segment allows digits so a kind like "s3_key" still round-trips; the
/// counter segment is lowercase hex from `format!("{:04x}")`.
static SENTINEL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"«promtect:[a-z0-9_]+:[0-9a-f]+»").expect("promtect sentinel regex")
});

/// Replace every known sentinel in `text` with its real secret in a SINGLE pass,
/// auditing each distinct sentinel once (tracked in `audited`, which the streaming
/// caller threads across chunks). Unknown sentinels are emitted verbatim.
///
/// Single-pass rebuild — rather than a cascade of `str::replace` calls — is
/// deliberate: repeated replacement could re-expand a secret whose value happens
/// to equal another sentinel's literal text, corrupting output and making the
/// result depend on iteration order. Scanning once replaces each token exactly
/// once, with no cascade and no order dependence.
pub(crate) fn restore_scan(
    text: &str,
    vault: &Vault,
    audit: &Audit,
    request_id: &str,
    audited: &mut std::collections::HashSet<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in SENTINEL_RE.find_iter(text) {
        out.push_str(&text[last..m.start()]);
        let token = m.as_str();
        match vault.secret_for(token) {
            Some(secret) => {
                out.push_str(&secret);
                // Log the detector kind carried in the sentinel (e.g. "aws_key"),
                // not a flat "sentinel" literal, so unmask events are attributable
                // by detector exactly like the corresponding mask events.
                if audited.insert(token.to_string()) {
                    audit.record("unmask", sentinel_kind(token), token, request_id);
                }
            }
            // Unknown sentinel (not minted for this request): leave it verbatim.
            None => out.push_str(token),
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

/// Replace every known sentinel in `text` with its real secret.
pub fn restore_text(text: &str, vault: &Vault, audit: &Audit, request_id: &str) -> String {
    let mut audited = std::collections::HashSet::new();
    restore_scan(text, vault, audit, request_id, &mut audited)
}

/// Extract the detector kind from a sentinel token `«promtect:KIND:HEX»`.
/// Falls back to `"sentinel"` for a malformed token — `find_sentinels` only ever
/// yields well-formed tokens, but restore must never panic on adversarial
/// upstream content, so this stays total.
pub(crate) fn sentinel_kind(token: &str) -> &str {
    token
        .strip_prefix("«promtect:")
        .and_then(|rest| rest.split(':').next())
        .filter(|kind| !kind.is_empty())
        .unwrap_or("sentinel")
}

/// Extract candidate sentinel tokens `«promtect:...»` from text.
pub fn find_sentinels(text: &str) -> Vec<String> {
    SENTINEL_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Local proof: mask a canary secret, confirm it is gone from the masked text,
/// then confirm restore returns the original. Pure in-memory, no network.
pub fn selftest() -> bool {
    let vault = Vault::new();
    let audit = Audit::null();
    let canary = "AKIAIOSFODNN7EXAMPLE";
    let text = format!("canary secret: {canary}");
    let masked = mask_text(&text, &vault, &audit, "selftest");
    if masked.contains(canary) {
        return false; // leak
    }
    let restored = restore_text(&masked, &vault, &audit, "selftest");
    restored == text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_then_restore_is_identity() {
        let vault = Vault::new();
        let audit = Audit::null();
        let original = r#"{"messages":[{"role":"user","content":"key is AKIAIOSFODNN7EXAMPLE"}]}"#;
        let masked = mask_text(original, &vault, &audit, "req1");
        assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(masked.contains("«promtect:aws_key:"));
        let restored = restore_text(&masked, &vault, &audit, "req1");
        assert_eq!(restored, original);
    }

    /// Restore is single-pass: if one secret's VALUE equals another secret's
    /// sentinel literal, restoring must NOT re-expand the injected text. A naive
    /// cascade of `str::replace` calls would corrupt this; the single-pass scan
    /// replaces each token exactly once.
    #[test]
    fn restore_does_not_cascade() {
        let vault = Vault::new();
        let s1 = vault.sentinel_for("aws_key", "AKIA0000");
        // s2's real value is the literal text of s1's sentinel.
        let s2 = vault.sentinel_for("env_secret", &s1);
        let text = format!("{s1} {s2}");
        let got = restore_text(&text, &vault, &Audit::null(), "req");
        // s1 → its secret; s2 → the literal s1 text, NOT re-expanded into AKIA0000.
        assert_eq!(got, format!("AKIA0000 {s1}"));
    }

    #[test]
    fn restore_ignores_unknown_sentinels() {
        let vault = Vault::new();
        let audit = Audit::null();
        let text = "unknown «promtect:aws_key:9999» stays";
        assert_eq!(restore_text(text, &vault, &audit, "req1"), text);
    }

    #[test]
    fn selftest_passes() {
        assert!(selftest());
    }

    /// mask_text must write exactly ONE `mask` audit event per unique sentinel even
    /// when the same secret value appears multiple times in the input (e.g. repeated
    /// in conversation history).
    #[test]
    fn mask_logs_one_event_per_unique_sentinel() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-mask-{}.jsonl", uuid::Uuid::new_v4()));

        let vault = Vault::new();
        let audit = Audit::to_file(path.clone());
        let secret = "AKIAIOSFODNN7EXAMPLE";

        // Same secret appearing 3 times in one request body — same value → same sentinel.
        let text = format!("key={secret} again={secret} third={secret}");
        let masked = mask_text(&text, &vault, &audit, "req1");

        // All occurrences replaced.
        assert!(!masked.contains(secret));

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // Only one mask event logged, not three.
        let mask_lines = contents.matches("\"action\":\"mask\"").count();
        assert_eq!(
            mask_lines, 1,
            "expected exactly one mask event per unique sentinel"
        );
        assert!(
            !contents.contains(secret),
            "audit must not log the secret value"
        );
    }

    /// restore_text must write exactly ONE `unmask` audit event per distinct
    /// sentinel even when that sentinel appears multiple times in the text, and
    /// the event must record the placeholder id only — never the real secret.
    /// (Covers FIX 4: de-duplicated audit logging, and FIX 5: unmask event is
    /// actually emitted and value-free.)
    #[test]
    fn restore_logs_one_unmask_event_per_sentinel_without_secret() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-unmask-{}.jsonl", uuid::Uuid::new_v4()));

        let vault = Vault::new();
        let audit = Audit::to_file(path.clone());
        let secret = "AKIAIOSFODNN7EXAMPLE";

        // Register the secret and learn its sentinel via the normal mask path.
        let masked = mask_text(&format!("key={secret}"), &vault, &audit, "reqX");
        let sentinel = find_sentinels(&masked)
            .into_iter()
            .next()
            .expect("mask must produce a sentinel");

        // Build text containing the SAME sentinel twice; str::replace handles both
        // occurrences in one pass, so only one audit event should be recorded.
        let twice = format!("a {sentinel} b {sentinel} c");
        let restored = restore_text(&twice, &vault, &audit, "reqX");

        // Both occurrences are expanded back to the real secret.
        assert_eq!(restored.matches(secret).count(), 2);

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // Exactly one unmask event for this sentinel — no duplicate no-op records.
        let unmask_lines = contents.matches("\"action\":\"unmask\"").count();
        assert_eq!(unmask_lines, 1, "expected exactly one unmask event");
        // The placeholder id is logged...
        assert!(
            contents.contains(&sentinel),
            "unmask must log the sentinel id"
        );
        // ...but the real secret value is NEVER logged.
        assert!(
            !contents.contains(secret),
            "audit must not log the secret value"
        );
    }

    /// An `unmask` event must attribute the detector kind carried in the sentinel
    /// (here `aws_key`), not a flat `"sentinel"` literal — so unmask is queryable
    /// by detector exactly like mask.
    #[test]
    fn unmask_event_records_real_detector_kind() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("promtect-kind-{}.jsonl", uuid::Uuid::new_v4()));

        let vault = Vault::new();
        let audit = Audit::to_file(path.clone());
        let secret = "AKIAIOSFODNN7EXAMPLE";

        let masked = mask_text(&format!("key={secret}"), &vault, &audit, "reqK");
        let restored = restore_text(&masked, &vault, &audit, "reqK");
        assert_eq!(restored, format!("key={secret}"));

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(contents.contains("\"action\":\"unmask\""));
        // The detector is the real kind, and the old "sentinel" placeholder is gone.
        assert!(
            contents.contains("\"detector\":\"aws_key\""),
            "unmask must record the detector kind from the sentinel"
        );
        assert!(
            !contents.contains("\"detector\":\"sentinel\""),
            "unmask must not log the flat \"sentinel\" literal"
        );
    }

    /// A sentinel whose detector kind contains a digit (e.g. a future `s3_key`)
    /// must still be recognised by `find_sentinels`, otherwise restore would
    /// silently leave it un-expanded.
    #[test]
    fn find_sentinels_matches_digit_bearing_kind() {
        let toks = find_sentinels("a «promtect:s3_key:000a» b");
        assert_eq!(toks, vec!["«promtect:s3_key:000a»".to_string()]);
        assert_eq!(sentinel_kind("«promtect:s3_key:000a»"), "s3_key");
    }
}
