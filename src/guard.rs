//! `promtect guard <tool>` — run an AI coding tool inside a one-command protected
//! session.
//!
//! Instead of manually starting the proxy, exporting the right base-URL env var
//! for your tool, and remembering the `/v1` path quirks, `guard` does it all:
//! it starts an ephemeral proxy on a free port, points the tool at it, runs the
//! tool with your args, and tears the proxy down on exit.
//!
//! The parsing/wiring lives in the pure [`plan_guard`] (fully unit-tested); the
//! I/O — binding the proxy, spawning the child — lives in [`guard`].

use crate::audit::Audit;
use crate::proxy::{self, Ctx, resolve_upstream};
use std::sync::Arc;

/// A fully-resolved launch plan: which binary to run, the env var that points it
/// at the proxy, the proxy's upstream, and the masking mode.
#[derive(Debug, PartialEq, Eq)]
pub struct GuardPlan {
    /// Tool binary to execute (`claude`, `codex`, `ollama`, `aider`, or an `--exec` command).
    pub bin: String,
    /// Arguments passed through to the tool verbatim.
    pub tool_args: Vec<String>,
    /// Env var the tool reads for its API base URL
    /// (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `OLLAMA_HOST`).
    pub base_var: String,
    /// Path suffix appended to the proxy URL the tool is pointed at
    /// (`""` for Claude/Ollama, `/v1` for Codex, `/api/v1` for OpenRouter).
    pub base_path: String,
    /// Resolved upstream origin the proxy forwards masked traffic to.
    pub upstream: String,
    /// Whether to restore secrets in the response (false = strict mode).
    pub restore: bool,
    /// Pinned proxy port, or `None` for an ephemeral free port.
    pub port: Option<u16>,
    /// Advisory notes to print to the user (e.g. Codex+OpenRouter wire-api caveat).
    pub notes: Vec<String>,
}

/// Default Headroom URL — Headroom binds `127.0.0.1:8787` by default.
/// Use `--headroom=<url>` to override (e.g. `--headroom=http://127.0.0.1:9000`).
const HEADROOM_DEFAULT: &str = "http://127.0.0.1:8787";

fn next_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i + 1)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Parse `guard` arguments (everything after `guard`) into a [`GuardPlan`]. Pure:
/// no I/O, so the whole wiring is unit-testable.
pub fn plan_guard(args: &[String]) -> Result<GuardPlan, String> {
    if args.is_empty() {
        return Err("expected a tool (claude|codex|ollama|aider) or --exec CMD".to_string());
    }

    // ── tool / --exec ───────────────────────────────────────────────────────
    let mut tool: Option<&str> = None;
    let bin: String;
    let mut i;
    if args[0] == "--exec" {
        bin = args
            .get(1)
            .cloned()
            .ok_or_else(|| "--exec requires a command".to_string())?;
        i = 2;
    } else {
        let t = args[0].as_str();
        if !matches!(t, "claude" | "codex" | "ollama" | "aider") {
            return Err(format!(
                "unknown tool '{t}' (expected claude|codex|ollama|aider, or --exec CMD)"
            ));
        }
        tool = Some(t);
        bin = t.to_string();
        i = 1;
    }

    // ── flags (must precede tool args; `--` forces the boundary) ─────────────
    let mut headroom: Option<String> = None;
    let mut openrouter = false;
    let mut upstream_override: Option<String> = None;
    let mut strict = false;
    let mut port: Option<u16> = None;
    let mut exec_base_var: Option<String> = None;
    let mut exec_base_path: Option<String> = None;
    let mut exec_mode: Option<String> = None;
    let mut tool_args: Vec<String> = Vec::new();

    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                tool_args.extend_from_slice(&args[i + 1..]);
                break;
            }
            "--strict" => strict = true,
            "--openrouter" => openrouter = true,
            "--headroom" => headroom = Some(HEADROOM_DEFAULT.to_string()),
            "--upstream" => {
                upstream_override = Some(next_value(args, i, "--upstream")?.to_string());
                i += 2;
                continue;
            }
            "--port" => {
                let p = next_value(args, i, "--port")?;
                port = Some(
                    p.parse::<u16>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| format!("--port must be an integer 1-65535 (got {p:?})"))?,
                );
                i += 2;
                continue;
            }
            "--base-var" => {
                exec_base_var = Some(next_value(args, i, "--base-var")?.to_string());
                i += 2;
                continue;
            }
            "--base-path" => {
                exec_base_path = Some(next_value(args, i, "--base-path")?.to_string());
                i += 2;
                continue;
            }
            "--mode" => {
                exec_mode = Some(next_value(args, i, "--mode")?.to_string());
                i += 2;
                continue;
            }
            _ if a.starts_with("--headroom=") => {
                headroom = Some(a.trim_start_matches("--headroom=").to_string());
            }
            // First token that isn't a guard flag: it and the rest are the tool's.
            _ => {
                tool_args.extend_from_slice(&args[i..]);
                break;
            }
        }
        i += 1;
    }

    // Reject empty override values — they would otherwise collapse to the
    // provider default in resolve_upstream and silently NOT chain Headroom / the
    // intended upstream.
    if upstream_override
        .as_deref()
        .is_some_and(|u| u.trim().is_empty())
    {
        return Err("--upstream requires a non-empty URL".to_string());
    }
    if headroom.as_deref().is_some_and(|h| h.trim().is_empty()) {
        return Err("--headroom= requires a URL (omit the '=' to use the default)".to_string());
    }
    // --exec-only flags with a named tool would be silently ignored.
    if tool.is_some()
        && (exec_base_var.is_some() || exec_base_path.is_some() || exec_mode.is_some())
    {
        return Err("--base-var/--base-path/--mode are only valid with --exec".to_string());
    }

    // ── per-tool wiring (verified against each tool's docs) ──────────────────
    let (base_var, base_path, mode): (String, String, String) = match tool {
        Some("claude") => {
            if openrouter {
                return Err("--openrouter is not valid with claude (Anthropic only)".to_string());
            }
            (
                "ANTHROPIC_BASE_URL".into(),
                String::new(),
                "anthropic".into(),
            )
        }
        Some("codex") if openrouter => (
            "OPENAI_BASE_URL".into(),
            "/api/v1".into(),
            "openrouter".into(),
        ),
        Some("codex") => ("OPENAI_BASE_URL".into(), "/v1".into(), "openai".into()),
        Some("ollama") => {
            if openrouter {
                return Err("--openrouter is not valid with ollama".to_string());
            }
            ("OLLAMA_HOST".into(), String::new(), "ollama".into())
        }
        // Aider reads OPENAI_API_BASE for its OpenAI-compatible endpoint (LiteLLM
        // under the hood). For OpenRouter just chain via --upstream or --exec.
        Some("aider") if openrouter => {
            return Err(
                "--openrouter is not wired for aider; use --upstream https://openrouter.ai \
                 or guard --exec aider --base-var OPENAI_API_BASE --base-path /api/v1"
                    .to_string(),
            );
        }
        Some("aider") => ("OPENAI_API_BASE".into(), "/v1".into(), "openai".into()),
        // --exec
        None => {
            let bv =
                exec_base_var.ok_or_else(|| "--exec requires --base-var <ENV_VAR>".to_string())?;
            let bp = exec_base_path.unwrap_or_default();
            let md = if openrouter {
                "openrouter".to_string()
            } else {
                exec_mode.unwrap_or_else(|| "openai".to_string())
            };
            (bv, bp, md)
        }
        // `tool` is validated against the known set above, so this is unreachable
        // today. Return an error rather than panic, so a future refactor that adds
        // a tool without updating this match fails cleanly instead of aborting.
        Some(other) => return Err(format!("unvalidated tool '{other}'")),
    };

    // ── upstream: explicit --upstream wins, then --headroom, then the mode ───
    let upstream = if let Some(u) = upstream_override {
        resolve_upstream(None, Some(&u))?
    } else if let Some(h) = &headroom {
        resolve_upstream(None, Some(h))?
    } else {
        resolve_upstream(Some(&mode), None)?
    };

    // ── advisory notes ──────────────────────────────────────────────────────
    let mut notes = Vec::new();
    if tool == Some("codex") && openrouter {
        notes.push(
            "Codex speaks the OpenAI Responses API but OpenRouter exposes Chat \
             Completions — set wire_api=\"chat\" with a custom provider in \
             ~/.codex/config.toml for this to work."
                .to_string(),
        );
    }
    if tool == Some("ollama") && headroom.is_some() {
        notes.push(
            "Headroom does not compress native Ollama (/api/chat) traffic — \
             it benefits claude/codex."
                .to_string(),
        );
    }
    // Aider is multi-provider: guard covers only OpenAI-compatible traffic.
    // Anthropic/Gemini/other models bypass the proxy entirely — warn so a
    // non-openai model isn't a silent leak (worst failure mode for a masking tool).
    if tool == Some("aider") {
        notes.push(
            "guard aider masks OpenAI-compatible traffic (via OPENAI_API_BASE + OPENAI_BASE_URL). \
             Use an `openai/<model>` model; Anthropic/Gemini/other models in aider \
             bypass the proxy and are NOT masked."
                .to_string(),
        );
    }
    // Warn if a guard flag was typed AFTER the tool name — it was passed to the
    // tool, not honored by guard (e.g. `guard claude --strict` runs in transparent
    // mode). Guard flags must precede the tool, or come after `--` for the tool.
    const GUARD_FLAGS: &[&str] = &[
        "--strict",
        "--openrouter",
        "--headroom",
        "--upstream",
        "--port",
        "--mode",
        "--base-var",
        "--base-path",
    ];
    let stray: Vec<&str> = tool_args
        .iter()
        .map(String::as_str)
        .filter(|a| GUARD_FLAGS.contains(a) || a.starts_with("--headroom="))
        .collect();
    if !stray.is_empty() {
        notes.push(format!(
            "{} look like guard flag(s) but were passed to the tool and NOT honored \
             by guard — put guard flags before the tool name.",
            stray.join(" ")
        ));
    }

    Ok(GuardPlan {
        bin,
        tool_args,
        base_var,
        base_path,
        upstream,
        restore: !strict,
        port,
        notes,
    })
}

/// Run a [`GuardPlan`]: start an ephemeral proxy, point the tool at it via its
/// base-URL env var, run the tool, and return its exit code. The proxy task is
/// dropped when the process exits.
pub async fn guard(plan: GuardPlan) -> i32 {
    // Classify the upstream for the banner, and fail closed on a high-risk one when
    // PROMTECT_BLOCK_RISKY is set — before binding or spawning the tool.
    let risk = crate::provider::classify(&plan.upstream);
    let block_risky = proxy::parse_truthy(std::env::var("PROMTECT_BLOCK_RISKY").ok().as_deref());
    if crate::provider::is_blocked(&risk, block_risky) {
        eprintln!(
            "promtect guard: refusing a high-risk upstream — {}\n  \
             Unset PROMTECT_BLOCK_RISKY to allow it.",
            risk.note
        );
        return 1;
    }

    let bind_addr = format!("127.0.0.1:{}", plan.port.unwrap_or(0));
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("promtect guard: cannot bind {bind_addr} ({e})");
            return 1;
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            eprintln!("promtect guard: {e}");
            return 1;
        }
    };
    let base_url = format!("http://127.0.0.1:{port}{}", plan.base_path);

    // Same audit log as the standalone server, so the dashboard sees guard traffic.
    let audit_path =
        std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());
    let audit_path_for_dash = audit_path.clone();
    let requests = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ctx = Ctx {
        upstream: plan.upstream.clone(),
        audit: Arc::new(Audit::to_file(audit_path)),
        client: crate::net::http_client(),
        max_body_bytes: proxy::DEFAULT_MAX_BODY_BYTES,
        restore: plan.restore,
        requests: requests.clone(),
    };

    // Banner + notes go to STDERR so they never pollute the tool's stdout (some
    // tools have their output parsed by scripts).
    eprintln!(
        "promtect guard: {} → [mask] → {}  (proxy 127.0.0.1:{port}, {})",
        plan.bin,
        plan.upstream,
        if plan.restore {
            "restore on"
        } else {
            "strict: restore off"
        }
    );
    eprintln!("  upstream risk: {}", risk.note);
    for note in &plan.notes {
        eprintln!("  note: {note}");
    }

    // Detect a stale base-URL var left by a previous test or crashed session.
    // Guard overrides it for the child process, but the shell still holds the old
    // value — direct tool invocations in this terminal will fail until it's cleared.
    // Warn only when the value looks like an ephemeral stub (loopback, non-standard
    // port), not when it's a valid Headroom (8787) or Promtect (8790) URL or a remote host.
    if let Ok(stale) = std::env::var(&plan.base_var)
        && is_stale_stub(&stale)
    {
        eprintln!(
            "promtect guard: WARNING — {} is set to a dead stub ({stale}).\n  \
             This session is fine; direct '{}' calls in this terminal will fail.\n  \
             Fix: if no proxy is serving this URL, run: unset {}",
            plan.base_var, plan.bin, plan.base_var
        );
    }

    let app = proxy::app(ctx);
    tokio::spawn(async move {
        // Drain in-flight proxy requests on SIGINT / SIGTERM so secrets masked
        // in a partially-buffered response are fully restored before the socket
        // closes.  An error from with_graceful_shutdown still surfaces so a
        // premature stop is never silently swallowed.
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(crate::proxy::shutdown_signal())
            .await
        {
            eprintln!("promtect guard: proxy stopped serving ({e}) — tool is no longer masked");
        }
    });

    // Auto-start the dashboard so guard sessions get the same metrics UI as the
    // standalone proxy. Uses the same audit log, so guard traffic appears there.
    // Non-fatal: if the port is taken (e.g. another guard session), skip silently.
    if let Ok(dash_port) = proxy::parse_port(
        "PROMTECT_DASHBOARD_PORT",
        std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
        8799,
    ) {
        let dash_addr = format!("127.0.0.1:{dash_port}");
        if let Ok(dash_listener) = tokio::net::TcpListener::bind(&dash_addr).await {
            let dash_app = crate::dashboard::app(crate::dashboard::DashCtx {
                audit_path: Arc::new(audit_path_for_dash.as_str().into()),
            });
            tokio::spawn(async move {
                // Drain in-flight dashboard requests on signal so metrics
                // pages aren't truncated when guard exits.
                if let Err(e) = axum::serve(dash_listener, dash_app)
                    .with_graceful_shutdown(crate::proxy::shutdown_signal())
                    .await
                {
                    eprintln!("promtect guard: dashboard error: {e}");
                }
            });
            eprintln!("  dashboard: http://127.0.0.1:{dash_port}");
        }
    }

    // Inherit the full parent env (so the user's API keys flow through, forwarded
    // untouched), then override the tool's base-URL var to point at the proxy.
    // kill_on_drop ensures the child can't be orphaned if this future is dropped.
    let mut cmd = tokio::process::Command::new(&plan.bin);
    cmd.args(&plan.tool_args)
        .env(&plan.base_var, &base_url)
        .kill_on_drop(true);
    // Belt-and-suspenders for aider: LiteLLM reads OPENAI_API_BASE, but the modern
    // OpenAI SDK (used directly by newer aider for openai/ prefix models) reads
    // OPENAI_BASE_URL only. Override both so the proxy intercepts regardless of
    // which var the installed aider version prefers. A stale OPENAI_BASE_URL in the
    // parent shell would otherwise leak straight past plan.base_var override.
    if plan.base_var == "OPENAI_API_BASE" {
        cmd.env("OPENAI_BASE_URL", &base_url);
    }
    let status = cmd.status().await;

    // Tripwire: if the proxy never saw a request, the tool bypassed it entirely
    // (e.g. it ignored the base-URL var) — secrets may have gone out unmasked.
    // Skip for invocations that intentionally make no API calls.
    let is_dry_run = plan.tool_args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--help" | "-h" | "--version" | "version" | "help"
        )
    });
    if !is_dry_run && requests.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        eprintln!(
            "promtect guard: WARNING the proxy saw 0 requests — did '{}' use {}? \
             secrets may have gone direct (unmasked).",
            plan.bin, plan.base_var
        );
    }

    match status {
        Ok(s) => exit_code(&s, &plan.bin),
        Err(e) => {
            eprintln!(
                "promtect guard: failed to run '{}' ({e}). Is it installed and on your PATH?",
                plan.bin
            );
            127
        }
    }
}

/// Returns `true` if `url` looks like an ephemeral stub — a loopback address on a
/// non-standard port. Known-good loopback ports (8787 = Headroom default, 8790 =
/// Promtect default) are excluded so legitimate proxy URLs don't trigger the
/// stale-stub warning.
fn is_stale_stub(url: &str) -> bool {
    let host_port = url
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| url.strip_prefix("http://localhost:"));
    let Some(rest) = host_port else {
        return false; // remote host — not a stub
    };
    let port: u16 = rest
        .split('/')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    !matches!(port, 8787 | 8788 | 8790)
}

/// Map a child `ExitStatus` to a process exit code. A child killed by a signal has
/// no exit code — map it to the shell convention `128 + signal` and warn, so an
/// OOM-killed or Ctrl-C'd run is NEVER reported as success (0).
fn exit_code(status: &std::process::ExitStatus, bin: &str) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            eprintln!("promtect guard: '{bin}' was killed by signal {sig}");
            return 128 + sig;
        }
    }
    let _ = bin;
    1 // no code and no signal: never report success
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(args: &[&str]) -> Result<GuardPlan, String> {
        plan_guard(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn stale_stub_detection() {
        // ephemeral ports → stale
        assert!(is_stale_stub("http://127.0.0.1:56524"));
        assert!(is_stale_stub("http://localhost:12345"));
        // known-good loopback ports → not stale
        assert!(!is_stale_stub("http://127.0.0.1:8787"));
        assert!(!is_stale_stub("http://127.0.0.1:8790"));
        // remote host → never a stub
        assert!(!is_stale_stub("https://api.anthropic.com"));
        assert!(!is_stale_stub("https://openrouter.ai/api/v1"));
    }

    #[test]
    fn claude_default_wiring() {
        let p = plan(&["claude"]).unwrap();
        assert_eq!(p.bin, "claude");
        assert_eq!(p.base_var, "ANTHROPIC_BASE_URL");
        assert_eq!(p.base_path, "");
        assert_eq!(p.upstream, "https://api.anthropic.com");
        assert!(p.restore);
        assert!(p.tool_args.is_empty());
        assert!(p.notes.is_empty());
    }

    #[test]
    fn codex_default_wiring() {
        let p = plan(&["codex"]).unwrap();
        assert_eq!(p.bin, "codex");
        assert_eq!(p.base_var, "OPENAI_BASE_URL");
        assert_eq!(p.base_path, "/v1");
        assert_eq!(p.upstream, "https://api.openai.com");
    }

    #[test]
    fn ollama_default_wiring_points_at_local_server() {
        let p = plan(&["ollama", "run", "deepseek-r1"]).unwrap();
        assert_eq!(p.bin, "ollama");
        assert_eq!(p.base_var, "OLLAMA_HOST");
        assert_eq!(p.base_path, "");
        assert_eq!(p.upstream, "http://localhost:11434");
        assert_eq!(p.tool_args, vec!["run", "deepseek-r1"]);
    }

    #[test]
    fn aider_default_wiring() {
        let p = plan(&["aider", "--model", "openai/gpt-5.5"]).unwrap();
        assert_eq!(p.bin, "aider");
        assert_eq!(p.base_var, "OPENAI_API_BASE");
        assert_eq!(p.base_path, "/v1");
        assert_eq!(p.upstream, "https://api.openai.com");
        assert_eq!(p.tool_args, vec!["--model", "openai/gpt-5.5"]);
        // Multi-provider footgun must be surfaced: only OpenAI-compatible traffic is masked.
        assert!(
            p.notes.iter().any(|n| n.contains("NOT masked")),
            "expected aider bypass warning in notes, got {:?}",
            p.notes
        );
    }

    #[test]
    fn aider_openrouter_is_rejected_with_hint() {
        // Aider+OpenRouter isn't wired as a preset; the error points at the escape hatch.
        let e = plan(&["aider", "--openrouter"]).unwrap_err();
        assert!(e.contains("--upstream") || e.contains("--exec"), "{e}");
    }

    #[test]
    fn codex_openrouter_sets_path_and_warns() {
        let p = plan(&["codex", "--openrouter"]).unwrap();
        assert_eq!(p.base_path, "/api/v1");
        assert_eq!(p.upstream, "https://openrouter.ai");
        assert!(p.notes.iter().any(|n| n.contains("wire_api")));
    }

    #[test]
    fn headroom_default_and_override() {
        assert_eq!(
            plan(&["claude", "--headroom"]).unwrap().upstream,
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            plan(&["claude", "--headroom=http://127.0.0.1:8790"])
                .unwrap()
                .upstream,
            "http://127.0.0.1:8790"
        );
    }

    #[test]
    fn ollama_headroom_warns_no_compression() {
        let p = plan(&["ollama", "--headroom"]).unwrap();
        assert!(p.notes.iter().any(|n| n.contains("does not compress")));
    }

    #[test]
    fn bare_args_pass_through_to_tool() {
        let p = plan(&["codex", "fix the s3 upload"]).unwrap();
        assert_eq!(p.tool_args, vec!["fix the s3 upload"]);
    }

    #[test]
    fn double_dash_separates_tool_flags() {
        let p = plan(&["claude", "--strict", "--", "--model", "opus"]).unwrap();
        assert!(!p.restore);
        assert_eq!(p.tool_args, vec!["--model", "opus"]);
    }

    #[test]
    fn explicit_upstream_wins() {
        let p = plan(&["claude", "--upstream", "http://127.0.0.1:8790/"]).unwrap();
        assert_eq!(p.upstream, "http://127.0.0.1:8790");
    }

    #[test]
    fn strict_and_port() {
        let p = plan(&["claude", "--strict", "--port", "18787"]).unwrap();
        assert!(!p.restore);
        assert_eq!(p.port, Some(18787));
    }

    #[test]
    fn exec_requires_base_var() {
        assert!(
            plan(&["--exec", "aider"])
                .unwrap_err()
                .contains("--base-var")
        );
        let p = plan(&[
            "--exec",
            "aider",
            "--base-var",
            "OPENAI_BASE_URL",
            "--base-path",
            "/v1",
        ])
        .unwrap();
        assert_eq!(p.bin, "aider");
        assert_eq!(p.base_var, "OPENAI_BASE_URL");
        assert_eq!(p.base_path, "/v1");
        assert_eq!(p.upstream, "https://api.openai.com");
    }

    #[test]
    fn rejects_unknown_tool_and_bad_openrouter() {
        assert!(plan(&["notatool"]).unwrap_err().contains("unknown tool"));
        assert!(
            plan(&["claude", "--openrouter"])
                .unwrap_err()
                .contains("not valid with claude")
        );
        assert!(
            plan(&["ollama", "--openrouter"])
                .unwrap_err()
                .contains("not valid with ollama")
        );
        assert!(plan(&[]).unwrap_err().contains("expected a tool"));
        assert!(
            plan(&["claude", "--port", "0"])
                .unwrap_err()
                .contains("--port")
        );
    }

    #[test]
    fn rejects_empty_override_values() {
        // Empty values would silently collapse to the provider default upstream.
        assert!(
            plan(&["claude", "--headroom="])
                .unwrap_err()
                .contains("--headroom")
        );
        assert!(
            plan(&["claude", "--upstream", ""])
                .unwrap_err()
                .contains("--upstream")
        );
    }

    #[test]
    fn rejects_exec_only_flags_with_named_tool() {
        for flag in [
            ["--base-var", "X"],
            ["--base-path", "/v1"],
            ["--mode", "openai"],
        ] {
            let args = ["claude", flag[0], flag[1]];
            assert!(
                plan(&args).unwrap_err().contains("only valid with --exec"),
                "{flag:?} should be rejected with a named tool"
            );
        }
    }

    #[test]
    fn rejects_non_http_upstream() {
        assert!(
            plan(&["claude", "--upstream", "ftp://evil"])
                .unwrap_err()
                .contains("http(s)")
        );
    }

    #[test]
    fn value_flag_without_value_errors() {
        assert!(
            plan(&["claude", "--upstream"])
                .unwrap_err()
                .contains("requires a value")
        );
    }

    #[test]
    fn explicit_upstream_beats_headroom() {
        let p = plan(&[
            "claude",
            "--headroom",
            "--upstream",
            "http://127.0.0.1:9000",
        ])
        .unwrap();
        assert_eq!(p.upstream, "http://127.0.0.1:9000");
    }

    #[test]
    fn guard_flag_after_tool_warns() {
        // `--strict` after the tool is passed to the tool, NOT honored — must warn,
        // and restore stays ON (the silent-downgrade footgun).
        let p = plan(&["claude", "task", "--strict"]).unwrap();
        assert!(
            p.restore,
            "strict after tool must NOT silently disable restore"
        );
        assert_eq!(p.tool_args, vec!["task", "--strict"]);
        assert!(
            p.notes.iter().any(|n| n.contains("guard flag")),
            "should warn about the stray guard flag: {:?}",
            p.notes
        );
    }
}
