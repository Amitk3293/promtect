use crate::audit::Audit;
use crate::detect;
use crate::vault::Vault;

/// Replace every detected secret in `text` with its vault sentinel.
/// Records one audit event per masked secret. Returns the masked text.
pub fn mask_text(text: &str, vault: &Vault, audit: &Audit, request_id: &str) -> String {
    // detect() returns non-overlapping spans sorted by start. Splice from the END
    // so earlier byte offsets stay valid as we mutate the string.
    let mut matches = detect::detect(text);
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
    let mut out = text.to_string();
    for m in matches {
        let sentinel = vault.sentinel_for(m.kind, &m.value);
        out.replace_range(m.start..m.end, &sentinel);
        audit.record("mask", m.kind, &sentinel, request_id);
    }
    out
}

/// Replace every known sentinel in `text` with its real secret.
pub fn restore_text(text: &str, vault: &Vault, audit: &Audit, request_id: &str) -> String {
    let mut out = text.to_string();
    for token in find_sentinels(text) {
        if let Some(secret) = vault.secret_for(&token) {
            out = out.replace(&token, &secret);
            audit.record("unmask", "sentinel", &token, request_id);
        }
    }
    out
}

/// Extract candidate sentinel tokens `«airlock:...»` from text.
pub fn find_sentinels(text: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"«airlock:[a-z_]+:[0-9a-f]+»").expect("airlock sentinel regex")
    });
    RE.find_iter(text).map(|m| m.as_str().to_string()).collect()
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
        assert!(masked.contains("«airlock:aws_key:"));
        let restored = restore_text(&masked, &vault, &audit, "req1");
        assert_eq!(restored, original);
    }

    #[test]
    fn restore_ignores_unknown_sentinels() {
        let vault = Vault::new();
        let audit = Audit::null();
        let text = "unknown «airlock:aws_key:9999» stays";
        assert_eq!(restore_text(text, &vault, &audit, "req1"), text);
    }

    #[test]
    fn selftest_passes() {
        assert!(selftest());
    }
}
