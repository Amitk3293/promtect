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
fn new_prefix_detectors_do_not_overmatch() {
    // Supabase's publishable key is non-secret and must not be masked; only
    // `sb_secret_`/`sbp_` are secrets.
    clean("sb_publishable_aBcDeFgHiJkLmNoPqRsTuV");
    // `rnd_` code identifiers carry underscores, so they never reach the 30-char
    // underscore-free run a real Render key needs.
    clean("let rnd_seed_value = make_rng_seed(input_entropy_source);");
    clean("rnd_next_value_from_the_generator_helper_function");
    // `xai-` is followed by an unbroken alphanumeric run; hyphenated identifiers
    // break the run well before the 20-char minimum.
    clean("xai-experimental-feature-toggle-name");
    clean("xai-beta");
    // `fly_token` needs the `fm2_` macaroon lead-in and 20+ following chars, and
    // stops at whitespace — bare `FlyV1` prose and short stubs must not match.
    clean("deploy with FlyV1 over the fm2 transport layer today");
    clean("FlyV1 fm2_short");
}

#[test]
fn extended_prefix_detectors_need_full_form() {
    // The prefix-anchored providers require their full length + charclass; short
    // stubs and `prefix_`-shaped code identifiers must not match.
    clean("y0_value"); // yandex needs 20+ chars
    clean("vcp_short"); // vercel needs 20+ chars
    clean("ops_team_settings_config"); // 1password needs 40+ chars
    clean("pul-request-handler-name"); // pulumi needs 40 hex, not words
    clean("call jina_init() to begin"); // jina_init too short
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
