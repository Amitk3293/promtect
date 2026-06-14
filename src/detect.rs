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
            re: Regex::new(pat).expect(kind),
            group: 0,
            guard: false,
        }
    }
    fn dg(kind: &'static str, pat: &str, group: usize, guard: bool) -> RegexDetector {
        RegexDetector {
            kind,
            re: Regex::new(pat).expect(kind),
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
        // PASSWORD capture excludes only `@` (the userinfo/host separator) and
        // whitespace. A `/` is legal inside a password and must NOT abort the
        // match; the username class keeps `/` excluded so the `user:pass` split is
        // unambiguous. (Passwords containing a literal `@` remain a known gap.)
        dg(
            "db_password",
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mariadb|mssql)://[^:@/\s]+:([^@\s\\]+)@",
            1,
            true,
        ),
        // `[a-z0-9_]*` allows a compound prefix (e.g. `DB_`, `MY_`) before the
        // keyword: `\b` does not match across `_`, so the old `\b`-anchored form
        // missed `DB_PASSWORD`, `MY_TOKEN`, `APP_SECRET`. The keyword group stays
        // NON-capturing so the value remains capture group 1.
        // The value class also excludes `\` (backslash): in a JSON-encoded body a
        // newline is the two chars `\n`, NOT real whitespace, so without this the
        // value would greedily run across many lines and swallow whole blocks of
        // content (and several other secrets) into one giant sentinel.
        dg(
            "env_secret",
            r#"(?i)[a-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*["']?([^\s"',}\\]{8,})"#,
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

    /// A `/` inside the password must not abort the whole-URL match: the password
    /// capture excludes only `@` and whitespace, so `p4ss/word` is captured intact.
    #[test]
    fn db_password_allows_slash_in_password() {
        let hits = detect("DATABASE_URL=postgres://app:p4ss/word@db:5432/x");
        assert!(
            hits.iter()
                .any(|m| m.kind == "db_password" && m.value == "p4ss/word"),
            "password containing '/' must still be detected"
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

    /// Compound env-var keys (a prefix joined by `_` to the keyword, like
    /// `DB_PASSWORD` or `MY_TOKEN`) are the most common real-world secret names;
    /// `\b` does not match across `_`, so the old anchor missed them entirely.
    #[test]
    fn env_secret_matches_compound_keys() {
        assert!(
            detect("DB_PASSWORD=S3cretValue123")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value == "S3cretValue123"),
            "DB_PASSWORD compound key must be detected"
        );
        assert!(
            detect("MY_TOKEN=realtoken456789")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value == "realtoken456789"),
            "MY_TOKEN compound key must be detected"
        );
    }

    #[test]
    fn ignores_plain_prose() {
        assert!(detect("the quick brown fox jumps over the lazy dog").is_empty());
    }

    #[test]
    fn dedup_collapses_overlapping_matches() {
        // env_secret captures the value; anthropic_key matches the same token.
        // dedupe_overlaps must keep exactly one hit, not both.
        let text = "API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx";
        assert_eq!(detect(text).len(), 1);
    }

    /// Helper: does `detect(text)` produce any match of the given kind?
    fn has_kind(text: &str, kind: &str) -> bool {
        detect(text).iter().any(|m| m.kind == kind)
    }

    #[test]
    fn detects_each_provider_token_kind() {
        // Invariant: each provider detector fires on a valid-shaped synthetic token.
        let github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // ghp_ + 36
        assert!(has_kind(github_token, "github_token"), "github_token");

        let github_pat = format!("github_pat_{}", "A".repeat(82)); // github_pat_ + 82
        assert!(has_kind(&github_pat, "github_pat"), "github_pat");

        let gitlab_pat = "glpat-ABCDEFGHIJKLMNOPQRST"; // glpat- + 20
        assert!(has_kind(gitlab_pat, "gitlab_pat"), "gitlab_pat");

        assert!(has_kind("xoxb-1234567890", "slack_token"), "slack_token");
        assert!(has_kind("xapp-1234567890", "slack_app"), "slack_app");

        let google_api = "AIzaSyA1234567890abcdefghijklmnopqrstuv"; // AIza + 35
        assert!(has_kind(google_api, "google_api"), "google_api");

        let sendgrid_key = format!("SG.{}.{}", "A".repeat(22), "B".repeat(43));
        assert!(has_kind(&sendgrid_key, "sendgrid_key"), "sendgrid_key");

        let hf_token = format!("hf_{}", "A".repeat(34));
        assert!(has_kind(&hf_token, "hf_token"), "hf_token");

        let npm_token = format!("npm_{}", "A".repeat(36));
        assert!(has_kind(&npm_token, "npm_token"), "npm_token");

        let stripe_key = format!("sk_live_{}", "A".repeat(24));
        assert!(has_kind(&stripe_key, "stripe_key"), "stripe_key");

        let openai_key = format!("sk-proj-{}", "A".repeat(20));
        assert!(has_kind(&openai_key, "openai_key"), "openai_key");

        let anthropic_key = format!("sk-ant-{}", "a".repeat(20));
        assert!(has_kind(&anthropic_key, "anthropic_key"), "anthropic_key");

        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.ABCDEFGHIJ_signature_pad";
        assert!(has_kind(jwt, "jwt"), "jwt");
    }

    #[test]
    fn ignores_innocuous_text() {
        // Invariant: common log/prose strings never trigger any detector.
        assert!(detect("the build finished in 1.23s").is_empty());
        assert!(detect("GET /api/users?id=42").is_empty());
        assert!(detect("version 1.2.3 released").is_empty());
        assert!(detect("lorem ipsum dolor sit amet").is_empty());
    }

    #[test]
    fn env_value_stops_at_json_escaped_newline() {
        // In a JSON-encoded body a newline is the two chars `\n` (backslash + n),
        // not real whitespace. The env_secret value MUST stop there — otherwise one
        // match swallows every following line (and other secrets) into a single
        // giant sentinel, mangling the prompt the LLM receives.
        let json_body =
            r#"API_KEY=firstsecretvalue123\nDB_PASSWORD=secondsecretvalue456\nNOTE=keepgoing"#;
        let env: Vec<String> = detect(json_body)
            .into_iter()
            .filter(|m| m.kind == "env_secret")
            .map(|m| m.value)
            .collect();
        // Each value is line-bounded; neither swallows the following line.
        assert!(
            env.iter().any(|v| v == "firstsecretvalue123"),
            "first value not line-bounded: {env:?}"
        );
        assert!(
            env.iter().any(|v| v == "secondsecretvalue456"),
            "second value not line-bounded: {env:?}"
        );
        assert!(
            env.iter().all(|v| !v.contains("DB_PASSWORD")),
            "a value swallowed the next line: {env:?}"
        );
    }
}
