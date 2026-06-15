//! Detection benchmark — a small labeled corpus that yields a publishable accuracy
//! number and guards against regressions.
//!
//! Positives are realistic, in-context payloads (JSON values, `.env` lines, URLs)
//! carrying a *synthetic* secret of a known shape — never a real credential. Negatives
//! are prose, code expressions, and placeholders that must NOT be masked. The test is
//! kind-agnostic: it only asks "did detection fire?" (recall) and "did it fire where it
//! must not?" (false positives), which is what a user actually cares about.
//!
//! Asserts 100% recall on the positive corpus and zero false positives on the negative
//! corpus, and prints the headline numbers (run with `--nocapture` to see them).

use promtect::detect::detect;

/// Realistic payloads that each carry exactly one secret and MUST be detected.
fn positives() -> Vec<(&'static str, String)> {
    let a = |n: usize| "A".repeat(n);
    let h = |n: usize| "a".repeat(n);
    vec![
        (
            "aws key (json)",
            r#"{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}"#.into(),
        ),
        (
            "github token (header)",
            "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into(),
        ),
        ("stripe (.env)", format!("STRIPE_KEY=sk_live_{}", a(24))),
        ("openai (.env)", format!("OPENAI_API_KEY=sk-proj-{}", a(20))),
        (
            "anthropic (inline)",
            format!("use key sk-ant-{} please", h(20)),
        ),
        ("slack token", "slack=xoxb-1234567890".into()),
        (
            "google api key",
            "key: AIzaSyA1234567890abcdefghijklmnopqrstuv".into(),
        ),
        (
            "jwt",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.ABCDEFGHIJ_signature_pad".into(),
        ),
        (
            "rsa private key",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkqhki\n-----END RSA PRIVATE KEY-----"
                .into(),
        ),
        (
            "db url password",
            "DATABASE_URL=postgres://app:s3cr3tp4ssword@db.internal:5432/app".into(),
        ),
        ("env_secret", "PASSWORD=hunter2hunter2".into()),
        (
            "env_secret quoted comma",
            r#"{"api_key":"ab,cd}efghij"}"#.into(),
        ),
        ("groq", format!("GROQ_API_KEY=gsk_{}", a(40))),
        ("openrouter", format!("key=sk-or-v1-{}", h(40))),
        ("huggingface", format!("hf_{} is the token", a(34))),
        (
            "npm token",
            format!(".npmrc: //registry/:_authToken=npm_{}", a(36)),
        ),
        ("sendgrid", format!("SG.{}.{}", a(22), a(43))),
        ("doppler", format!("dp.pt.{}", a(40))),
        ("notion", format!("NOTION_TOKEN=ntn_{}", a(40))),
        ("digitalocean", format!("dop_v1_{}", h(64))),
    ]
}

/// Prose, code expressions, and placeholders that MUST NOT be masked.
fn negatives() -> Vec<&'static str> {
    vec![
        "Please rotate the key before you deploy the service to production.",
        r#"api_key = os.environ.get("OPENAI_API_KEY")"#,
        "API_KEY=your_api_key_here",
        "password=changeme",
        "token: ${MY_TOKEN}",
        "secret = process.env.SECRET",
        "Set ANTHROPIC_BASE_URL to point at the proxy.",
        "An AWS access key starts with AKIA followed by sixteen characters.",
        "placeholder = \"<your-token>\"",
        "the commit hash is 9f83a2b and the branch is main",
        "DB_PASSWORD={{ vault_password }}",
        "export API_KEY=REDACTED",
    ]
}

#[test]
fn detection_benchmark() {
    let pos = positives();
    let neg = negatives();

    let mut missed: Vec<&str> = Vec::new();
    for (label, payload) in &pos {
        if detect(payload).is_empty() {
            missed.push(label);
        }
    }

    let mut false_positives: Vec<&str> = Vec::new();
    for payload in &neg {
        if !detect(payload).is_empty() {
            false_positives.push(payload);
        }
    }

    let detected = pos.len() - missed.len();
    let recall = (detected as f64) / (pos.len() as f64) * 100.0;
    println!(
        "detection benchmark: {detected}/{total} positives detected ({recall:.0}% recall), \
         {fp} false positives across {neg_total} negatives",
        total = pos.len(),
        fp = false_positives.len(),
        neg_total = neg.len(),
    );

    assert!(missed.is_empty(), "missed (false negatives): {missed:?}");
    assert!(
        false_positives.is_empty(),
        "false positives (must not be masked): {false_positives:?}"
    );
}
