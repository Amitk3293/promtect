// Items are public API consumed by later tasks (mask, proxy); suppress until wired up.
#![allow(dead_code)]

use regex::Regex;
use std::sync::LazyLock;

/// A detected secret span. `start..end` are byte offsets into the scanned text;
/// `value` is the exact substring that will be masked.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Match {
    pub kind: &'static str,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

/// One regex detector. `group` picks which capture is the secret: 0 = the whole
/// match (token-shaped secrets), N = a sub-group (the value in `KEY=value`, the
/// password in a DB URL). `guard` drops obvious config placeholders.
struct RegexDetector {
    kind: &'static str,
    re: Regex,
    group: usize,
    guard: bool,
}

impl RegexDetector {
    fn find(&self, text: &str, out: &mut Vec<Match>) {
        for caps in self.re.captures_iter(text) {
            if let Some(m) = caps.get(self.group) {
                let value = m.as_str();
                if self.guard && looks_like_placeholder(value) {
                    continue;
                }
                out.push(Match {
                    kind: self.kind,
                    value: value.to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
}

/// Reject values that look like config defaults / examples, not real secrets.
fn looks_like_placeholder(v: &str) -> bool {
    if v.len() < 6 {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    const DENY: &[&str] = &[
        "changeme",
        "change_me",
        "password",
        "passwd",
        "secret",
        "token",
        "example",
        "examplekey",
        "your_key",
        "yourkey",
        "test",
        "none",
        "null",
        "true",
        "false",
        "redacted",
    ];
    if DENY.contains(&lower.as_str()) {
        return true;
    }
    lower.starts_with("your_")
        || lower.starts_with("your-")
        || lower.ends_with("_here")
        || lower.ends_with("-here")
        || v.starts_with('<')
        || v.starts_with("${")
        || v.starts_with("{{")
        || v.chars().all(|c| c == 'x' || c == 'X')
        || v.chars().all(|c| c == '*')
}

static DETECTORS: LazyLock<Vec<RegexDetector>> = LazyLock::new(|| {
    fn d(kind: &'static str, pat: &str) -> RegexDetector {
        RegexDetector {
            kind,
            re: Regex::new(pat).unwrap(),
            group: 0,
            guard: false,
        }
    }
    fn dg(kind: &'static str, pat: &str, group: usize, guard: bool) -> RegexDetector {
        RegexDetector {
            kind,
            re: Regex::new(pat).unwrap(),
            group,
            guard,
        }
    }
    vec![
        // --- Prefix-anchored provider tokens (whole match) ---
        d("aws_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        d("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
        d("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
        d("stripe_key", r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        d("github_token", r"\bgh[posru]_[A-Za-z0-9]{36,251}\b"),
        d("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        d("gitlab_pat", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        d("slack_token", r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
        d("slack_app", r"\bxapp-[A-Za-z0-9-]{10,}\b"),
        d("google_api", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        d(
            "sendgrid_key",
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        ),
        d("hf_token", r"\bhf_[A-Za-z0-9]{34}\b"),
        d("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        // --- Structural ---
        d(
            "jwt",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        ),
        d(
            "private_key",
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        ),
        // --- Context-keyed values (group 1 = the secret), guarded ---
        dg(
            "aws_secret",
            r#"(?i)aws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})"#,
            1,
            false,
        ),
        dg(
            "db_password",
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mariadb|mssql)://[^:@/\s]+:([^@/\s]+)@",
            1,
            true,
        ),
        dg(
            "env_secret",
            r#"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)\b["']?\s*[:=]\s*["']?([^\s"',}]{8,})"#,
            1,
            true,
        ),
    ]
});

/// Find all known-pattern secrets in `text`, de-overlapped, sorted by start.
/// Adding a detector = one line in `DETECTORS`.
pub fn detect(text: &str) -> Vec<Match> {
    let mut hits: Vec<Match> = Vec::new();
    for det in DETECTORS.iter() {
        det.find(text, &mut hits);
    }
    dedupe_overlaps(hits)
}

/// When spans overlap, keep the earliest/longest and drop the rest, so the same
/// bytes aren't masked twice (e.g. a DB password vs a generic env value).
fn dedupe_overlaps(mut hits: Vec<Match>) -> Vec<Match> {
    hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut kept: Vec<Match> = Vec::new();
    let mut last_end = 0usize;
    for m in hits {
        if m.start >= last_end {
            last_end = m.end;
            kept.push(m);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        let mut k: Vec<&'static str> = detect(text).into_iter().map(|m| m.kind).collect();
        k.sort();
        k
    }

    #[test]
    fn finds_aws_key_with_correct_span() {
        let text = "id=AKIAIOSFODNN7EXAMPLE";
        let hits = detect(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "aws_key");
        assert_eq!(&text[hits[0].start..hits[0].end], "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn finds_provider_tokens() {
        assert!(kinds("t ghp_0123456789abcdefghijklmnopqrstuvwxyzAB").contains(&"github_token"));
        assert!(kinds("k sk-ant-api03-abcdefghijklmnopqrstuvwx").contains(&"anthropic_key"));
        assert!(kinds("g AIzaSyA1234567890abcdefghijklmnopqrstuv").contains(&"google_api"));
    }

    #[test]
    fn finds_pem_private_key() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        let hits = detect(pem);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "private_key");
    }

    #[test]
    fn finds_db_password_not_whole_url() {
        // Note: password parsing stops at the first '@'. Passwords containing a
        // literal '@' (uncommon; usually %40-encoded) are a known M1 gap.
        let hits = detect("DATABASE_URL=postgres://app:s3cr3tPass1@db.internal:5432/prod");
        assert!(
            hits.iter()
                .any(|m| m.kind == "db_password" && m.value == "s3cr3tPass1")
        );
    }

    #[test]
    fn env_secret_is_guarded_against_placeholders() {
        assert!(detect("PASSWORD=changeme").is_empty());
        assert!(detect("API_KEY=your_key_here").is_empty());
        assert!(
            detect("API_KEY=A9f83Kd0parealtoken")
                .iter()
                .any(|m| m.kind == "env_secret")
        );
    }

    #[test]
    fn ignores_plain_prose() {
        assert!(detect("the quick brown fox jumps over the lazy dog").is_empty());
    }
}
