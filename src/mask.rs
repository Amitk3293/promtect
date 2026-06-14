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

/// Replace every known sentinel in `text` with its real secret.
pub fn restore_text(text: &str, vault: &Vault, audit: &Audit, request_id: &str) -> String {
    // De-duplicate tokens first: `find_sentinels` yields a token once per
    // occurrence, but `str::replace` already replaces ALL occurrences in one
    // pass. Without dedup, a sentinel appearing N times would log N-1 redundant
    // no-op `unmask` events. A HashSet collapses them so each distinct sentinel
    // is restored — and audited — exactly once.
    let unique: std::collections::HashSet<String> = find_sentinels(text).into_iter().collect();
    let mut out = text.to_string();
    for token in unique {
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

    /// mask_text must write exactly ONE `mask` audit event per unique sentinel even
    /// when the same secret value appears multiple times in the input (e.g. repeated
    /// in conversation history).
    #[test]
    fn mask_logs_one_event_per_unique_sentinel() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("airlock-mask-{}.jsonl", uuid::Uuid::new_v4()));

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
        let path = dir.join(format!("airlock-unmask-{}.jsonl", uuid::Uuid::new_v4()));

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
}
