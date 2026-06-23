use regex::Regex;
use std::sync::LazyLock;
use zeroize::Zeroizing;

/// A detected secret span. `start..end` are byte offsets into the scanned text;
/// `value` is the exact substring that will be masked.
///
/// `value` is wrapped in [`zeroize::Zeroizing`] so the heap copy of the secret —
/// which outlives the splice in `mask_text` and lingers in the `Vec<Match>` until
/// the vector is dropped — is wiped from memory on drop rather than left for a
/// later allocation to reuse. It derefs to `String`, so reads that need `&str`
/// use `.as_str()` or `&*m.value`; direct `==` comparisons use `.as_str()`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Match {
    pub kind: &'static str,
    pub value: Zeroizing<String>,
    pub start: usize,
    pub end: usize,
}

/// One regex detector. `group` picks which capture is the secret: 0 = the whole
/// match (token-shaped secrets), N = a sub-group (the value in `KEY=value`, the
/// password in a DB URL). `guard_fn` is an optional predicate: when `Some(f)`,
/// matched values where `f(value)` returns `true` are silently dropped as
/// placeholders or code expressions.
struct RegexDetector {
    kind: &'static str,
    re: Regex,
    group: usize,
    guard_fn: Option<fn(&str) -> bool>,
}

impl RegexDetector {
    fn find(&self, text: &str, out: &mut Vec<Match>) {
        for caps in self.re.captures_iter(text) {
            if let Some(m) = caps.get(self.group) {
                let value = m.as_str();
                if self.guard_fn.is_some_and(|f| f(value)) {
                    continue;
                }
                out.push(Match {
                    kind: self.kind,
                    value: Zeroizing::new(value.to_string()),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
}

/// A function-call expression captured in `KEY=value` position, e.g.
/// `getenv("X")` or `os.environ.get("X")` — code that reads a secret, not the
/// secret itself. Matches an identifier (optionally dotted) immediately followed
/// by a parenthesised argument list. Used by the placeholder guard so a real
/// high-entropy credential that merely *contains* a parenthesis is still masked,
/// while genuine call expressions are skipped.
///
/// Anchored to the WHOLE value (`^…$`): the previous unanchored form used
/// `is_match`, so any secret that happened to embed a balanced `ident(...)`
/// substring (e.g. `A9f83(Kd0)more`) was dropped as "code" and LEAKED. Anchoring
/// means the guard fires only when the value *is* a call expression, never when
/// it merely contains one. Truncated calls whose capture stopped at the opening `(`
/// (e.g. `os.environ.get(`) are not matched here; they are handled by the separate
/// `v.ends_with('(')` check in `looks_like_placeholder`.
static CALL_EXPR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)$")
        .expect("BUG: call-expr guard regex failed to compile")
});

/// Reject values that look like config defaults / examples, not real secrets.
fn looks_like_placeholder(v: &str) -> bool {
    if v.len() < 6 {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    // Exact-match deny list. Values that are clearly example / template text and
    // should never be forwarded masked (as that would waste a round-trip and add
    // noise to the audit log). Keep this list narrow: anything ambiguous belongs
    // in a per-detector guard, not here.
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
        "your_password",
        "placeholder",
        "sample",
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
        // Code expression, not a literal secret. Reject a genuine call shape
        // (`getenv("X")`, `os.environ.get(`) — but NOT a high-entropy credential
        // that merely contains a parenthesis. A captured call expression ends in
        // `(` (the quote that opened its argument stopped the capture) or is a
        // complete `ident(...)`; a real secret is neither.
        || v.ends_with('(')
        || CALL_EXPR.is_match(v)
        // Common config-interpolation / env-reference prefixes, including both
        // dot-access (`process.env.SECRET_NAME`) and bracket-access
        // (`process.env['SECRET']`) JavaScript forms.
        || lower.starts_with("process.env")
        || lower.starts_with("os.environ")
        || lower.starts_with("env.")
        || v.chars().all(|c| c == 'x' || c == 'X')
        || v.chars().all(|c| c == '*')
}

/// Reject DB-connection-string password fields that are obviously placeholder
/// defaults. This guard is intentionally narrower than `looks_like_placeholder`:
/// the surrounding `scheme://user:pass@host` URL shape is strong evidence of a
/// real credential, so we skip the length floor and most DENY words. Only the
/// explicit placeholder strings that no production password would ever use are
/// rejected — favouring over-masking for all other values.
fn looks_like_db_placeholder(v: &str) -> bool {
    const DB_DENY: &[&str] = &[
        "changeme",
        "change_me",
        "placeholder",
        "secret",
        "password",
        "example",
        "test",
        "sample",
        "your_password",
    ];
    let lower = v.to_ascii_lowercase();
    DB_DENY.contains(&lower.as_str())
}

static DETECTORS: LazyLock<Vec<RegexDetector>> = LazyLock::new(|| {
    // Patterns are compile-time constants, so a failure here is a developer bug,
    // not a runtime condition. The panic message names the offending detector,
    // its pattern, and the parse error so the fix is obvious from CI output alone.
    fn d(kind: &'static str, pat: &str) -> RegexDetector {
        RegexDetector {
            kind,
            re: Regex::new(pat)
                .unwrap_or_else(|e| panic!("BUG: detector {kind} invalid regex {pat:?}: {e}")),
            group: 0,
            guard_fn: None,
        }
    }
    fn dg(
        kind: &'static str,
        pat: &str,
        group: usize,
        guard_fn: Option<fn(&str) -> bool>,
    ) -> RegexDetector {
        RegexDetector {
            kind,
            re: Regex::new(pat)
                .unwrap_or_else(|e| panic!("BUG: detector {kind} invalid regex {pat:?}: {e}")),
            group,
            guard_fn,
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
            None,
        ),
        // PASSWORD capture excludes only `@` (the userinfo/host separator) and
        // whitespace. A `/` is legal inside a password and must NOT abort the
        // match; the username class keeps `/` excluded so the `user:pass` split is
        // unambiguous. (Passwords containing a literal `@` remain a known gap.)
        //
        // A narrow DB-placeholder guard is applied: obvious template values like
        // `changeme`, `password`, or `placeholder` are dropped. The full
        // `looks_like_placeholder` guard (which includes a length floor and many
        // DENY words that could reject a short real password) stays OFF — only
        // the explicit placeholder words known to appear in DB URLs are filtered.
        // A false negative is a leak, so this guard stays minimal.
        dg(
            "db_password",
            // Guillemets «» excluded for the same sentinel-anti-smuggling reason
            // as env_secret: a partial sentinel must not be absorbed into the match.
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mariadb|mssql)://[^:@/\s]+:([^@\s\\«»]+)@",
            1,
            Some(looks_like_db_placeholder),
        ),
        // `[a-z0-9_]*` allows a compound prefix (e.g. `DB_`, `MY_`) before the
        // keyword: `\b` does not match across `_`, so the old `\b`-anchored form
        // missed `DB_PASSWORD`, `MY_TOKEN`, `APP_SECRET`. The keyword group stays
        // NON-capturing so the value remains capture group 1.
        // The value class also excludes `\` (backslash): in a JSON-encoded body a
        // newline is the two chars `\n`, NOT real whitespace, so without this the
        // value would greedily run across many lines and swallow whole blocks of
        // content (and several other secrets) into one giant sentinel.
        // It further excludes the sentinel guillemets `«`/`»` (U+00AB / U+00BB):
        // model- or user-supplied content could otherwise place one inside a
        // captured span, smuggling a partial sentinel into the masked body and
        // corrupting the round-trip. They are never part of a real secret.
        //
        // KNOWN GAP (unquoted, conservative): this class stops at the first
        // whitespace (`\s`), so a *space-bearing* unquoted secret loses its tail
        // — e.g. `secret = hunter two` captures only `hunter`. An unquoted value
        // has no closing delimiter, so a space is the only safe boundary; greedily
        // crossing it would swallow following prose/JSON (and other secrets) into
        // one giant sentinel, which is worse. Quote the value (the variants below
        // capture spaces verbatim) to mask a secret that contains spaces.
        dg(
            "env_secret",
            r#"(?i)[a-z0-9_]*(?:password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*["']?([^\s"',}\\«»]{8,})"#,
            1,
            Some(looks_like_placeholder),
        ),
        // Quoted-value variants. The unquoted class above stops at `,` and `}` so
        // it does not swallow JSON structure — but that also truncates a *quoted*
        // secret that legitimately contains those bytes (e.g. `"a,b}c..."`), which
        // would forward the tail in cleartext. When the value is delimited by
        // quotes, the closing quote is the unambiguous boundary, so the inner class
        // need only exclude the quote and `\`. Same `env_secret` kind; the closing
        // quote stays OUTSIDE group 1, so masking preserves it and the body stays
        // valid. `dedupe_overlaps` keeps this longer match over the truncated one.
        // Guillemets `«`/`»` are excluded from the quoted classes too, for the same
        // anti-smuggling reason as the unquoted variant above.
        dg(
            "env_secret",
            r#"(?i)[a-z0-9_]*(?:password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*"([^"\\«»]{8,})""#,
            1,
            Some(looks_like_placeholder),
        ),
        dg(
            "env_secret",
            r#"(?i)[a-z0-9_]*(?:password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*'([^'\\«»]{8,})'"#,
            1,
            Some(looks_like_placeholder),
        ),
        // JSON-escaped-quote variant. In a JSON request body, `password = "val"`
        // arrives as `password = \"val\"` (backslash-escaped). The backslash is in
        // the exclusion class of the variants above, so they miss it. This variant
        // uses `\"…\"` as delimiters to catch the JSON-encoded form.
        dg(
            "env_secret",
            r#"(?i)[a-z0-9_]*(?:password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*\\"([^"\\«»]{8,})\\""#,
            1,
            Some(looks_like_placeholder),
        ),
        // ── AI / LLM provider keys (the core use case) ──────────────────────
        // Distinct prefixes catch bare tokens that `env_secret` misses (a key
        // pasted into prose or code without a `KEY=` context). Providers whose
        // keys have no prefix (Mistral, Cohere, Together, DeepSeek) are still
        // caught by `env_secret` in `KEY=value` form.
        d("groq_key", r"\bgsk_[A-Za-z0-9]{40,}\b"),
        d("openrouter_key", r"\bsk-or-v1-[a-f0-9]{32,}\b"),
        d("replicate_key", r"\br8_[A-Za-z0-9]{32,}\b"),
        d("perplexity_key", r"\bpplx-[A-Za-z0-9]{40,}\b"),
        d("fireworks_key", r"\bfw_[A-Za-z0-9]{24,}\b"),
        d("nvidia_key", r"\bnvapi-[A-Za-z0-9_-]{60,}\b"),
        // ── Cloud / infrastructure ──────────────────────────────────────────
        d("digitalocean_token", r"\bdop_v1_[a-f0-9]{64}\b"),
        d("doppler_token", r"\bdp\.pt\.[A-Za-z0-9]{40,}\b"),
        d("vault_token", r"\bhv[sb]\.[A-Za-z0-9]{24,}\b"),
        d(
            "terraform_token",
            r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b",
        ),
        d("databricks_token", r"\bdapi[0-9a-f]{32}\b"),
        d(
            "planetscale_token",
            r"\bpscale_(?:pw|tkn)_[A-Za-z0-9_-]{32,}\b",
        ),
        d("tailscale_key", r"\btskey-(?:auth|api)-[A-Za-z0-9-]{40,}\b"),
        // Azure Storage account key: 88-char base64 after `AccountKey=`.
        dg(
            "azure_storage_key",
            r"(?i)AccountKey=([A-Za-z0-9+/]{86,88}={0,2})",
            1,
            None,
        ),
        // ── Developer tools / platforms ─────────────────────────────────────
        d("pypi_token", r"\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}\b"),
        d("dockerhub_token", r"\bdckr_pat_[A-Za-z0-9_-]{27,}\b"),
        d("shopify_token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
        d("linear_key", r"\blin_api_[A-Za-z0-9]{40,}\b"),
        d("atlassian_token", r"\bATATT3[A-Za-z0-9_.+=/-]{180,}"),
        d("figma_token", r"\bfigd_[A-Za-z0-9_-]{40,}\b"),
        d("notion_token", r"\bntn_[A-Za-z0-9]{40,}\b"),
        d("airtable_pat", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"),
        d("rubygems_key", r"\brubygems_[a-f0-9]{48}\b"),
        d("postman_key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
        d("sonar_token", r"\bsq[ap]_[a-f0-9]{40}\b"),
        d("circleci_token", r"\bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b"),
        // ── SaaS / communication / payment ──────────────────────────────────
        d(
            "slack_webhook",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
        ),
        d(
            "discord_token",
            r"\b[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}\b",
        ),
        d(
            "discord_webhook",
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
        ),
        // Mailgun's `key-<32hex>` shape is indistinguishable from a cache key or
        // MD5 in isolation, so require the word "mailgun" nearby (the bare KEY=value
        // form is already covered by `env_secret`). Twilio's `SK<32hex>` is the
        // public-ish API-key SID (not the secret) and far too false-positive-prone
        // to detect bare; the real auth token is caught by `env_secret`.
        dg(
            "mailgun_key",
            r"(?i)mailgun[^\n]{0,40}\b(key-[0-9a-f]{32})\b",
            1,
            None,
        ),
        d("stripe_webhook", r"\bwhsec_[A-Za-z0-9]{32,}\b"),
        d("square_token", r"\bsq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,}\b"),
        d("razorpay_key", r"\brzp_(?:live|test)_[A-Za-z0-9]{14,}\b"),
        // ── Vector DB / AI-agent infrastructure (AI-native differentiator) ──
        d("pinecone_key", r"\bpcsk_[A-Za-z0-9_]{20,}\b"),
        d(
            "langsmith_key",
            r"\blsv2_[a-z]{2}_[A-Za-z0-9]{16,}_[A-Za-z0-9]{8,}\b",
        ),
        // ── Monitoring / messaging / misc ───────────────────────────────────
        d("sentry_user_token", r"\bsntryu_[A-Za-z0-9]{64}\b"),
        d("sentry_org_token", r"\bsntrys_[A-Za-z0-9_=+/]{60,}\b"),
        // Anchor the DSN host to sentry.io so we don't match any basic-auth URL of
        // the form https://<32hex>@<anyhost>/<digits>.
        d(
            "sentry_dsn",
            r"https://[0-9a-f]{32}@[a-z0-9.-]*sentry\.io/\d+",
        ),
        d("newrelic_key", r"\bNRAK-[A-Z0-9]{27}\b"),
        d(
            "mapbox_token",
            r"\b[ps]k\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
        ),
        d("telegram_bot", r"\b\d{6,16}:[A-Za-z0-9_-]{35}\b"),
        d("google_oauth", r"\bya29\.[A-Za-z0-9_-]{30,}\b"),
        d("gcp_refresh", r"\b1//[A-Za-z0-9_-]{30,}\b"),
        d("fcm_token", r"\bAPA91[A-Za-z0-9_-]{100,}\b"),
        d("grafana_cloud", r"\bglc_[A-Za-z0-9+/]{32,}={0,2}\b"),
        d("grafana_sa", r"\bglsa_[A-Za-z0-9]{32}_[0-9a-f]{8}\b"),
        d("aws_mws", r"\bamzn\.mws\.[0-9a-f-]{36}\b"),
        d("asana_pat", r"\b[0-2]/\d{15,18}:[a-f0-9]{32}\b"),
        d("dropbox_token", r"\bsl\.[A-Za-z0-9_-]{130,}\b"),
        d("gitlab_trigger", r"\bglptt-[0-9a-f]{40}\b"),
        d("age_secret_key", r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"),
        // ── More certificate / key blocks (PEM forms `private_key` misses) ──
        d(
            "pgp_private_key",
            r"(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
        ),
        d(
            "teams_webhook",
            r"https://[a-z0-9.-]+\.webhook\.office\.com/webhookb2/[\w@./-]+",
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
                .any(|m| m.kind == "db_password" && m.value.as_str() == "s3cr3tPass1")
        );
    }

    /// A `/` inside the password must not abort the whole-URL match: the password
    /// capture excludes only `@` and whitespace, so `p4ss/word` is captured intact.
    #[test]
    fn db_password_allows_slash_in_password() {
        let hits = detect("DATABASE_URL=postgres://app:p4ss/word@db:5432/x");
        assert!(
            hits.iter()
                .any(|m| m.kind == "db_password" && m.value.as_str() == "p4ss/word"),
            "password containing '/' must still be detected"
        );
    }

    /// Issue #44 — DB URL placeholder guard.
    /// Common placeholder values inside a DB connection string must be dropped,
    /// but a real non-placeholder password must still be detected.
    #[test]
    fn db_password_drops_placeholder_values() {
        // Each of these is a well-known placeholder that nobody ships in production.
        for placeholder in &[
            "changeme",
            "CHANGEME",
            "placeholder",
            "PLACEHOLDER",
            "secret",
            "SECRET",
            "password",
            "PASSWORD",
            "example",
            "test",
            "sample",
            "your_password",
        ] {
            let url = format!("postgres://user:{placeholder}@db:5432/mydb");
            assert!(
                detect(&url)
                    .iter()
                    .filter(|m| m.kind == "db_password")
                    .count()
                    == 0,
                "db_password must NOT fire on placeholder value {placeholder:?}"
            );
        }
        // A non-placeholder value must still be detected (guard should not over-block).
        let url = "postgres://user:xKj8mQp2rN@db:5432/mydb";
        assert!(
            detect(url).iter().any(|m| m.kind == "db_password"),
            "db_password must fire on a real non-placeholder password"
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

    /// Issue #44 — extended placeholder guard for env_secret.
    /// The DENY list now includes `"your_password"`, `"placeholder"`, and `"sample"`.
    #[test]
    fn env_secret_drops_new_placeholder_words() {
        assert!(
            detect("PASSWORD=placeholder").is_empty(),
            "PASSWORD=placeholder should be dropped"
        );
        assert!(
            detect("PASSWORD=your_password").is_empty(),
            "PASSWORD=your_password should be dropped"
        );
        assert!(
            detect("PASSWORD=sample").is_empty(),
            "PASSWORD=sample should be dropped"
        );
    }

    /// A high-entropy credential that merely *contains* a parenthesis must still
    /// be masked — the old guard rejected any value with `(`/`)`, silently leaking
    /// such secrets. Only genuine call expressions (below) should be skipped.
    #[test]
    fn env_secret_with_paren_is_masked() {
        assert!(
            detect("API_KEY=A9f83(Kd0parealtoken")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "A9f83(Kd0parealtoken"),
            "credential containing '(' must be detected, not treated as code"
        );
    }

    /// Call expressions that *read* a secret are not the secret; they stay guarded.
    #[test]
    fn env_secret_call_expression_is_not_masked() {
        assert!(
            !detect("API_KEY=getenv(SECRET_TOKEN)")
                .iter()
                .any(|m| m.kind == "env_secret"),
            "getenv(...) is code, not a literal secret"
        );
        assert!(
            !detect(r#"API_KEY=os.environ.get("FOO_BAR")"#)
                .iter()
                .any(|m| m.kind == "env_secret"),
            "os.environ.get( is code, not a literal secret"
        );
    }

    /// Issue #43 — `process.env` dot-access and bracket-access forms must not be
    /// treated as literal secrets. Both JS env-access syntaxes produce a code
    /// expression, not a real credential value.
    #[test]
    fn process_env_access_forms_are_not_masked() {
        // Dot-access: `SECRET_KEY=process.env.MY_SECRET`
        assert!(
            !detect("SECRET_KEY=process.env.MY_SECRET")
                .iter()
                .any(|m| m.kind == "env_secret"),
            "process.env.MY_SECRET dot-access must not be masked"
        );
        // Bracket-access: `SECRET_KEY=process.env['MY_SECRET']`
        assert!(
            !detect("SECRET_KEY=process.env['MY_SECRET']")
                .iter()
                .any(|m| m.kind == "env_secret"),
            "process.env['MY_SECRET'] bracket-access must not be masked"
        );
        // Double-quote variant: `SECRET_KEY=process.env["MY_SECRET"]`
        assert!(
            !detect(r#"SECRET_KEY=process.env["MY_SECRET"]"#)
                .iter()
                .any(|m| m.kind == "env_secret"),
            r#"process.env["MY_SECRET"] bracket-access must not be masked"#
        );
    }

    /// Issue #45 — `env_secret` must fire on the unquoted bare form (`KEY=value`)
    /// and space-separated forms (`KEY =value`, `KEY= value`) that the regex
    /// handles via `\s*[:=]\s*`. This test pins the behaviour so a future regex
    /// change cannot silently regress it.
    #[test]
    fn env_secret_unquoted_and_space_forms() {
        // Bare unquoted (already worked; now pinned).
        assert!(
            detect("API_KEY=A9f83Kd0parealtoken")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "A9f83Kd0parealtoken"),
            "bare KEY=value form must be detected"
        );
        // Space before `=`
        assert!(
            detect("API_KEY =A9f83Kd0parealtoken")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "A9f83Kd0parealtoken"),
            "KEY =value (space before =) form must be detected"
        );
        // Space after `=`
        assert!(
            detect("API_KEY= A9f83Kd0parealtoken")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "A9f83Kd0parealtoken"),
            "KEY= value (space after =) form must be detected"
        );
    }

    /// Issue #45 — values that start with guillemet sentinels (`«`) must
    /// NOT be captured, so an already-masked sentinel is never re-masked into a
    /// nested sentinel that would corrupt round-trip restore.
    #[test]
    fn env_secret_excludes_guillemet_values() {
        // A sentinel that sits in the value position of a KEY= expression must not
        // trigger another env_secret match.
        let sentinel_value = "API_KEY=«promtect:aws_key:0001»";
        assert!(
            !detect(sentinel_value)
                .iter()
                .any(|m| m.kind == "env_secret"),
            "a sentinel in value position must not trigger env_secret"
        );
    }

    /// A quoted value containing `,` or `}` must be captured whole — the unquoted
    /// class stops at those bytes and would forward the tail in cleartext. The
    /// closing quote bounds the quoted variant, so the full secret is masked.
    #[test]
    fn quoted_env_secret_with_delimiters_not_truncated() {
        assert!(
            detect(r#"{"api_key":"ab,cd}efghij"}"#)
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "ab,cd}efghij"),
            "quoted secret with ','/'}}' must be captured whole, not truncated"
        );
        assert!(
            detect("token = 'p4ss,w0rd,with,commas'")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "p4ss,w0rd,with,commas"),
            "single-quoted secret with commas must be captured whole"
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
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "S3cretValue123"),
            "DB_PASSWORD compound key must be detected"
        );
        assert!(
            detect("MY_TOKEN=realtoken456789")
                .iter()
                .any(|m| m.kind == "env_secret" && m.value.as_str() == "realtoken456789"),
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

    /// Synthetic (structural, NOT real) tokens for every extended detector, paired
    /// with the kind each must report. Shared by the detection and no-leak tests.
    fn extended_kind_cases() -> Vec<(String, &'static str)> {
        let a = |n: usize| "A".repeat(n); // alphanumeric filler
        let h = |n: usize| "a".repeat(n); // hex-safe filler
        vec![
            (format!("gsk_{}", a(40)), "groq_key"),
            (format!("sk-or-v1-{}", h(40)), "openrouter_key"),
            (format!("r8_{}", a(32)), "replicate_key"),
            (format!("pplx-{}", a(40)), "perplexity_key"),
            (format!("fw_{}", a(24)), "fireworks_key"),
            (format!("nvapi-{}", a(60)), "nvidia_key"),
            (format!("dop_v1_{}", h(64)), "digitalocean_token"),
            (format!("dp.pt.{}", a(40)), "doppler_token"),
            (format!("hvs.{}", a(24)), "vault_token"),
            (format!("{}.atlasv1.{}", a(14), a(60)), "terraform_token"),
            (format!("dapi{}", h(32)), "databricks_token"),
            (format!("pscale_pw_{}", a(32)), "planetscale_token"),
            (format!("tskey-auth-{}", a(40)), "tailscale_key"),
            (format!("AccountKey={}", a(88)), "azure_storage_key"),
            (format!("pypi-AgEIcHlwaS{}", a(50)), "pypi_token"),
            (format!("dckr_pat_{}", a(27)), "dockerhub_token"),
            (format!("shpat_{}", h(32)), "shopify_token"),
            (format!("lin_api_{}", a(40)), "linear_key"),
            (format!("ATATT3{}", a(180)), "atlassian_token"),
            (format!("figd_{}", a(40)), "figma_token"),
            (format!("ntn_{}", a(40)), "notion_token"),
            (format!("pat{}.{}", a(14), h(64)), "airtable_pat"),
            (format!("rubygems_{}", h(48)), "rubygems_key"),
            (format!("PMAK-{}-{}", h(24), h(34)), "postman_key"),
            (format!("sqp_{}", h(40)), "sonar_token"),
            (format!("CCIPAT_{}_{}", a(22), h(40)), "circleci_token"),
            (
                format!("https://hooks.slack.com/services/T00000000/B00000000/{}", a(24)),
                "slack_webhook",
            ),
            (format!("M{}.ABCDEF.{}", a(23), a(27)), "discord_token"),
            (
                "https://discord.com/api/webhooks/123456789012345678/AbCdEf-tok".to_string(),
                "discord_webhook",
            ),
            (format!("mailgun api key-{}", h(32)), "mailgun_key"),
            (format!("whsec_{}", a(32)), "stripe_webhook"),
            (format!("sq0atp-{}", a(22)), "square_token"),
            (format!("rzp_live_{}", a(16)), "razorpay_key"),
            (format!("pcsk_{}", a(40)), "pinecone_key"),
            (format!("lsv2_pt_{}_{}", a(32), a(12)), "langsmith_key"),
            (format!("sntryu_{}", a(64)), "sentry_user_token"),
            (format!("sntrys_{}", a(60)), "sentry_org_token"),
            (
                format!("https://{}@o0.ingest.sentry.io/12345", h(32)),
                "sentry_dsn",
            ),
            (format!("NRAK-{}", a(27)), "newrelic_key"),
            (format!("sk.eyJ{}.{}", a(20), a(20)), "mapbox_token"),
            (format!("1234567890:{}", a(35)), "telegram_bot"),
            (format!("ya29.{}", a(30)), "google_oauth"),
            (format!("1//{}", a(30)), "gcp_refresh"),
            (format!("APA91{}", a(100)), "fcm_token"),
            (format!("glc_{}", a(40)), "grafana_cloud"),
            (format!("glsa_{}_{}", a(32), h(8)), "grafana_sa"),
            (
                "amzn.mws.550e8400-e29b-41d4-a716-446655440000".to_string(),
                "aws_mws",
            ),
            (format!("1/1234567890123456:{}", h(32)), "asana_pat"),
            (format!("sl.{}", a(130)), "dropbox_token"),
            (format!("glptt-{}", h(40)), "gitlab_trigger"),
            (format!("AGE-SECRET-KEY-1{}", a(58)), "age_secret_key"),
            (
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIIabc\n-----END PGP PRIVATE KEY BLOCK-----"
                    .to_string(),
                "pgp_private_key",
            ),
            (
                "https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/xyz/12"
                    .to_string(),
                "teams_webhook",
            ),
        ]
    }

    /// Every extended (Phase 3) detector fires on a synthetic token of its shape.
    #[test]
    fn detects_each_extended_kind() {
        for (token, kind) in &extended_kind_cases() {
            assert!(has_kind(token, kind), "{kind} did not fire on {token}");
        }
    }

    /// NO-LEAK: every extended detector not only *fires* but actually *masks* — the
    /// secret value is absent from the masked output and a sentinel replaces it.
    /// Detection with a wrong span/capture-group would still leak; this proves the
    /// no-leak invariant for every detector, not just the three the property test
    /// exercises.
    #[test]
    fn masking_removes_every_extended_kind() {
        use crate::audit::Audit;
        use crate::mask::mask_text;
        use crate::vault::Vault;
        for (token, kind) in &extended_kind_cases() {
            let vault = Vault::new();
            let masked = mask_text(token, &vault, &Audit::null(), "r");
            assert!(
                !masked.contains(token.as_str()),
                "{kind}: secret survived masking — {masked:?}"
            );
            assert!(
                masked.contains("«promtect:"),
                "{kind}: nothing was masked — {masked:?}"
            );
        }
    }

    /// Overlapping detectors must resolve to the RIGHT kind with the FULL span —
    /// a wrong winner with a shorter/shifted span would leak the uncovered prefix.
    #[test]
    fn detector_precedence_on_overlaps() {
        // A Mapbox secret token embeds a single `eyJ…` segment; it must report
        // `mapbox_token` over `jwt`, covering the `sk.` prefix (not starting at eyJ).
        let mapbox = format!("sk.eyJ{}.{}", "A".repeat(20), "B".repeat(20));
        let hits = detect(&mapbox);
        assert_eq!(hits.len(), 1, "mapbox overlap not deduped: {hits:?}");
        assert_eq!(
            hits[0].kind, "mapbox_token",
            "mapbox lost to {}",
            hits[0].kind
        );
        assert_eq!(
            &mapbox[hits[0].start..hits[0].end],
            mapbox,
            "span must cover the whole token including the sk. prefix"
        );

        // An OpenRouter key shares the `sk-` lead with openai_key but the hyphens
        // mean openai_key cannot match; it must report `openrouter_key` in full.
        let openrouter = format!("sk-or-v1-{}", "a".repeat(40));
        let hits = detect(&openrouter);
        assert_eq!(hits.len(), 1, "openrouter overlap not deduped: {hits:?}");
        assert_eq!(hits[0].kind, "openrouter_key");
        assert_eq!(&openrouter[hits[0].start..hits[0].end], openrouter);
    }

    /// The OSS registry ships broad coverage of known credential formats.
    #[test]
    fn registry_has_expected_breadth() {
        assert!(
            DETECTORS.len() >= 70,
            "expected >= 70 detectors, have {}",
            DETECTORS.len()
        );
    }

    /// Anti-drift: `docs/detectors.md` must mention every detector `kind`, so a new
    /// detector cannot ship undocumented. Adding a row to `DETECTORS` without a row
    /// in the reference fails CI here.
    #[test]
    fn detectors_doc_covers_every_kind() {
        let doc = include_str!("../docs/detectors.md");
        let mut kinds: Vec<&str> = DETECTORS.iter().map(|d| d.kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        for k in &kinds {
            // Match the backtick-delimited code span (`aws_key`), not a bare
            // substring: otherwise a removed `private_key` row would be masked by
            // `pgp_private_key`, which contains it, and the guard would pass blind.
            assert!(
                doc.contains(&format!("`{k}`")),
                "docs/detectors.md is missing detector kind `{k}` — add a row"
            );
        }
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
            .map(|m| m.value.to_string())
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

    /// Issue: `secret_key` (Terraform AWS provider) leaked because the `secret`
    /// keyword matched but `_key` before `=` prevented the `[:=]` anchor from
    /// firing. `secret[_-]?key` must be listed before bare `secret`.
    #[test]
    fn secret_key_hcl_is_detected() {
        let hcl = r#"secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY""#;
        assert!(
            detect(hcl).iter().any(|m| m.kind == "env_secret"),
            "secret_key = \"...\" must be detected as env_secret; got: {:?}",
            detect(hcl)
        );
    }

    /// Issue: in a JSON request body the HCL value `password = "val"` is encoded
    /// as `password = \"val\"` (backslash-escaped quotes). The backslash is in the
    /// exclusion class of the unquoted/quoted variants, so capture failed. A
    /// JSON-escaped-quote variant (`\"…\"`) must catch this.
    #[test]
    fn password_json_encoded_quotes_is_detected() {
        // Simulate how the proxy sees it: double-quotes JSON-escaped to \"
        let json_fragment = r#"password = \"super-secret-db-pass-123!\""#;
        assert!(
            detect(json_fragment).iter().any(|m| m.kind == "env_secret"),
            "password with JSON-escaped quotes must be detected; got: {:?}",
            detect(json_fragment)
        );
    }
}
