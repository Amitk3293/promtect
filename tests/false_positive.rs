//! False-positive regression gate.
//!
//! Strings here must NEVER be flagged as secrets. A masked variable name or a
//! masked placeholder makes the LLM produce wrong code, which the developer
//! blames on Promtect — so false positives are a trust bug, not a cosmetic one.
//! Add a case here whenever a real-world false positive is found; it then guards
//! against regressions forever.

use promtect::detect::detect;

/// Assert that `text` produces no detections, with a helpful message if it does.
fn clean(text: &str) {
    let hits = detect(text);
    assert!(
        hits.is_empty(),
        "false positive on {text:?}: {:?}",
        hits.iter().map(|m| m.kind).collect::<Vec<_>>()
    );
}

#[test]
fn placeholders_are_not_secrets() {
    clean("PASSWORD=changeme");
    clean("API_KEY=your_key_here");
    clean("TOKEN=<your-token>");
    clean("password: ${DB_PASSWORD}");
    clean("api_key={{ vault_api_key }}");
    clean("AWS_SECRET_ACCESS_KEY=<your-aws-secret>");
    clean("client_secret=xxxxxxxxxxxxxxxxxxxx");
    clean("auth_token=REDACTED");
}

#[test]
fn code_expressions_are_not_secrets() {
    // A context detector must not capture a code expression as the "value".
    clean("secret = os.environ.get(\"SECRET_KEY\")");
    clean("token := os.Getenv(\"API_TOKEN\")");
    clean("password = process.env.DB_PASSWORD");
    clean("apiKey: config.get('apiKey')");
}

#[test]
fn innocuous_prose_and_code_are_clean() {
    clean("the quick brown fox jumps over the lazy dog");
    clean("GET /api/users?id=42 HTTP/1.1");
    clean("version 1.2.3 released on 2026-06-15");
    clean("function getApiKey() { return config.apiKey; }");
    clean("npm install --save-dev @types/node");
    clean("Authorization: Bearer <token>");
    clean("see the docs at https://example.com/api/keys for details");
}
