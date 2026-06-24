// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Per-upstream data-handling risk.
//!
//! Promtect masks known-format secrets before they leave the machine. But *where*
//! a request goes still matters: once anything reaches an upstream it lands in that
//! provider's logs, abuse-review queue, subprocessors, and breach blast radius. The
//! provider's own guidance treats an exposed credential as compromised (OpenAI says
//! rotate a leaked key immediately), and the security consensus is that anything
//! entering an LLM's context should be assumed compromised. So the honest framing is:
//! reaching any provider is a rotate-it event;
//! Promtect's job is to stop the secret from arriving in the first place.
//!
//! This module maps the resolved upstream origin to a short, honest one-line note
//! shown at startup, and backs the optional `PROMTECT_BLOCK_RISKY` fail-closed switch.
//!
//! Profiles reflect public provider documentation as of June 2026 (major Western APIs:
//! short abuse-retention with zero-data-retention available; DeepSeek and the China-based
//! models: data under Chinese jurisdiction). They are operator guidance, not a
//! guarantee: verify against your own contract and tier. Promtect classifies only the
//! *immediate* upstream; a local chain (e.g. LiteLLM) can forward anywhere downstream.

/// How exposed a secret is once it reaches an upstream. [`Risk::High`] is the tier
/// `PROMTECT_BLOCK_RISKY` refuses; loopback / local-chain upstreams are [`Risk::Local`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Stays on the machine (local model or the operator's own local chain).
    Local,
    /// Major Western API with short retention and zero-data-retention available.
    Low,
    /// Passthrough, consumer/free tier that may train, or otherwise unverified.
    Medium,
    /// Trains on input, opaque jurisdiction, or an unknown remote host.
    High,
}

/// A one-line, honest risk note for an upstream: name included, no overclaim.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    pub name: &'static str,
    pub risk: Risk,
    /// Self-contained startup line (already includes the provider name).
    pub note: &'static str,
}

/// Whether `PROMTECT_BLOCK_RISKY` should refuse this profile. Only [`Risk::High`]
/// (high-risk providers like DeepSeek, or an unverified unknown remote) is
/// blocked; local, low, and medium upstreams are allowed through with a warning.
pub fn is_blocked(profile: &Profile, block_risky: bool) -> bool {
    block_risky && profile.risk == Risk::High
}

/// Classify a resolved upstream origin (e.g. `https://api.anthropic.com`) into its
/// data-handling [`Profile`]. Matching is by host substring; an unrecognised remote
/// host is treated as [`Risk::High`] (fail-closed: we cannot vouch for it).
pub fn classify(upstream: &str) -> Profile {
    let u = upstream.to_ascii_lowercase();

    // Loopback / local: nothing is sent to a third party by Promtect itself. A local
    // chain may forward downstream, so the note stays honest about that.
    if u.contains("://127.0.0.1")
        || u.contains("://localhost")
        || u.contains("://[::1]")
        || u.contains("://0.0.0.0")
    {
        return Profile {
            name: "local",
            risk: Risk::Local,
            note: "local upstream: stays on your machine (or your own chain); \
                   nothing is sent to a third party by Promtect.",
        };
    }

    if u.contains("api.anthropic.com") {
        return Profile {
            name: "Anthropic API",
            risk: Risk::Low,
            note: "Anthropic API: an exposed key still means rotate it; \
                   Promtect keeps it from arriving.",
        };
    }
    if u.contains("api.openai.com") {
        return Profile {
            name: "OpenAI API",
            risk: Risk::Low,
            note: "OpenAI API: an exposed key still means rotate it; \
                   Promtect keeps it from arriving.",
        };
    }
    if u.contains("openrouter.ai") {
        return Profile {
            name: "OpenRouter",
            risk: Risk::Medium,
            note: "OpenRouter: forwards to a downstream provider; your exposure depends \
                   on where it routes. Prefer zero-retention routes.",
        };
    }
    if u.contains("googleapis.com") || u.contains("generativelanguage") {
        return Profile {
            name: "Google Gemini",
            risk: Risk::Medium,
            note: "Google Gemini: the free AI Studio tier trains on your input; \
                   verify your tier.",
        };
    }
    if u.contains("openai.azure.com") || u.contains(".azure.com") {
        return Profile {
            name: "Azure OpenAI",
            risk: Risk::Low,
            note: "Azure OpenAI: abuse-monitoring retention unless you have \
                   modified/zero monitoring approved.",
        };
    }
    if u.contains("bedrock") && u.contains("amazonaws.com") {
        return Profile {
            name: "AWS Bedrock",
            risk: Risk::Low,
            note: "AWS Bedrock: log retention is account-configurable.",
        };
    }
    if u.contains("mistral.ai") {
        return Profile {
            name: "Mistral",
            risk: Risk::Low,
            note: "Mistral: EU-based; zero-retention available.",
        };
    }
    if u.contains("cohere.") || u.contains("api.cohere") {
        return Profile {
            name: "Cohere",
            risk: Risk::Medium,
            note: "Cohere: trains by default unless you opt out / enable zero-retention.",
        };
    }
    if u.contains("deepseek") {
        return Profile {
            name: "DeepSeek",
            risk: Risk::High,
            note: "DeepSeek: HIGH RISK: trains on your input, China jurisdiction \
                   (National Intelligence Law can compel access), no zero-retention.",
        };
    }
    if u.contains("moonshot") {
        return Profile {
            name: "Kimi (Moonshot)",
            risk: Risk::High,
            note: "Kimi (Moonshot AI): HIGH RISK: data processed in China; the \
                   National Intelligence Law can compel access regardless of server.",
        };
    }
    if u.contains("bigmodel") || u.contains("zhipu") || u.contains("z.ai") {
        return Profile {
            name: "GLM (Zhipu)",
            risk: Risk::High,
            note: "GLM (Zhipu AI): HIGH RISK: data processed in China; the National \
                   Intelligence Law can compel access regardless of server.",
        };
    }

    // Unknown remote: fail closed. We cannot confirm what it does with the request.
    Profile {
        name: "unknown",
        risk: Risk::High,
        note: "unknown upstream: its data handling is unverified; treat it as untrusted.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_apis_are_low_risk() {
        assert_eq!(classify("https://api.anthropic.com").risk, Risk::Low);
        assert_eq!(classify("https://api.openai.com").risk, Risk::Low);
        // Path and casing must not change the classification.
        assert_eq!(classify("https://API.OpenAI.com/v1").risk, Risk::Low);
    }

    #[test]
    fn deepseek_is_high_risk() {
        let p = classify("https://api.deepseek.com");
        assert_eq!(p.risk, Risk::High);
        assert!(p.note.contains("HIGH"));
    }

    #[test]
    fn chinese_coding_models_are_high_risk() {
        for url in [
            "https://api.moonshot.ai/v1",           // Kimi global
            "https://api.moonshot.cn/v1",           // Kimi China
            "https://open.bigmodel.cn/api/paas/v4", // GLM / Zhipu
            "https://api.z.ai/v1",                  // GLM / Z.ai
        ] {
            let p = classify(url);
            assert_eq!(p.risk, Risk::High, "{url} should be high-risk");
            assert!(p.note.contains("China"), "{url} note should name China");
        }
    }

    #[test]
    fn loopback_is_local() {
        assert_eq!(classify("http://127.0.0.1:11434").risk, Risk::Local);
        assert_eq!(classify("http://localhost:4000").risk, Risk::Local);
    }

    #[test]
    fn passthrough_and_consumer_are_medium() {
        assert_eq!(classify("https://openrouter.ai").risk, Risk::Medium);
        assert_eq!(
            classify("https://generativelanguage.googleapis.com").risk,
            Risk::Medium
        );
    }

    #[test]
    fn unknown_remote_fails_closed_to_high() {
        assert_eq!(classify("https://weird.example.com").risk, Risk::High);
    }

    #[test]
    fn block_risky_only_blocks_high() {
        let deepseek = classify("https://api.deepseek.com");
        let anthropic = classify("https://api.anthropic.com");
        let local = classify("http://127.0.0.1:11434");
        // Flag off: nothing is blocked.
        assert!(!is_blocked(&deepseek, false));
        // Flag on: only High is blocked.
        assert!(is_blocked(&deepseek, true));
        assert!(!is_blocked(&anthropic, true));
        assert!(!is_blocked(&local, true));
    }
}
