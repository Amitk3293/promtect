// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

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
use std::time::Duration;

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
    /// Advisory notes to print to the user (for example, tool-specific scope limits).
    pub notes: Vec<String>,
    /// Whether this is the named Codex preset, which requires additional
    /// authentication, routing, and compression checks before launch.
    pub codex_fail_closed: bool,
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
    // `--cloud` targets Ollama Cloud (ollama.com) instead of the local daemon.
    let mut cloud = false;
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
            "--cloud" => cloud = true,
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
    // --cloud only changes the Ollama upstream; on any other tool it would do nothing.
    if cloud && tool != Some("ollama") {
        return Err("--cloud is only valid with ollama".to_string());
    }
    if tool == Some("codex") && openrouter {
        return Err(
            "--openrouter is not supported by guard codex: Codex requires a custom chat provider, which can bypass Promtect's fail-closed routing"
                .to_string(),
        );
    }
    if tool == Some("codex")
        && let Some(key) = conflicting_codex_override(&tool_args)
    {
        return Err(format!(
            "Codex argument {key:?} can bypass Promtect routing or compression safety; remove it"
        ));
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
        Some("codex") => ("OPENAI_BASE_URL".into(), "/v1".into(), "openai".into()),
        Some("ollama") => {
            if openrouter {
                return Err("--openrouter is not valid with ollama".to_string());
            }
            // `--cloud` swaps the upstream to ollama.com; explicit --upstream/--headroom
            // still win below, since mode is the lowest-priority upstream source.
            let m = if cloud { "ollama-cloud" } else { "ollama" };
            ("OLLAMA_HOST".into(), String::new(), m.into())
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
    if tool == Some("codex") && is_openrouter_upstream(&upstream) {
        return Err(
            "OpenRouter is not supported by guard codex: Codex can select routing that bypasses Promtect"
                .to_string(),
        );
    }

    // ── advisory notes ──────────────────────────────────────────────────────
    let mut notes = Vec::new();
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
        "--cloud",
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
        codex_fail_closed: tool == Some("codex"),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodexInvocation {
    Interactive,
    Exec,
    Review,
    DryRun,
}

/// Classify the root Codex invocation while rejecting routing overrides and
/// unsupported root commands. Options with values must be consumed before a
/// token can be treated as a subcommand.
fn inspect_codex_args(args: &[String]) -> Result<CodexInvocation, &str> {
    const VALUE_OPTIONS: &[&str] = &[
        "-m",
        "--model",
        "-p",
        "--profile",
        "-s",
        "--sandbox",
        "-C",
        "--cd",
        "--add-dir",
        "-a",
        "--ask-for-approval",
    ];
    const VALUE_PREFIXES: &[&str] = &[
        "--model=",
        "--profile=",
        "--sandbox=",
        "--cd=",
        "--add-dir=",
        "--ask-for-approval=",
    ];
    const ATTACHED_SHORT_VALUE_PREFIXES: &[&str] = &["-m", "-p", "-s", "-C", "-a"];
    const FLAG_OPTIONS: &[&str] = &[
        "--strict-config",
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "--search",
        "--no-alt-screen",
    ];

    if let Some(arg) = routing_codex_override(args) {
        return Err(arg);
    }

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if VALUE_OPTIONS.contains(&arg) {
            if args.get(i + 1).is_none() {
                return Err(arg);
            }
            i += 2;
            continue;
        }
        if VALUE_PREFIXES.iter().any(|prefix| arg.starts_with(prefix))
            || ATTACHED_SHORT_VALUE_PREFIXES
                .iter()
                .any(|prefix| arg.starts_with(prefix) && arg.len() > prefix.len())
            || FLAG_OPTIONS.contains(&arg)
        {
            i += 1;
            continue;
        }
        if matches!(arg, "--help" | "-h" | "--version" | "-V" | "help") {
            return Ok(CodexInvocation::DryRun);
        }
        if matches!(arg, "exec" | "e") {
            return Ok(if codex_subcommand_is_dry_run(&args[i + 1..]) {
                CodexInvocation::DryRun
            } else {
                CodexInvocation::Exec
            });
        }
        if arg == "review" {
            return Ok(if codex_subcommand_is_dry_run(&args[i + 1..]) {
                CodexInvocation::DryRun
            } else {
                CodexInvocation::Review
            });
        }
        if !arg.starts_with('-') && arg.chars().any(char::is_whitespace) {
            return Ok(CodexInvocation::Interactive);
        }

        // `--image` is variadic, so parsing it without Codex's own Clap model is
        // ambiguous. Unknown flags and positional root tokens are denied rather
        // than risking a newly-added transport command.
        return Err(arg);
    }
    Ok(CodexInvocation::Interactive)
}

fn codex_subcommand_is_dry_run(args: &[String]) -> bool {
    args.iter()
        .map(String::as_str)
        .take_while(|arg| *arg != "--")
        .any(|arg| matches!(arg, "--help" | "-h" | "--version" | "-V"))
}

/// Find any Codex option that can change routing, regardless of whether Clap
/// accepts it before or after the root subcommand. A literal `--` ends option
/// parsing, so later values are prompt data rather than global overrides.
fn routing_codex_override(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .take_while(|arg| *arg != "--")
        .find(|arg| {
            // Codex/Clap accepts separated, equals, and attached short forms.
            // Reject every runtime TOML override instead of trying to keep a
            // denylist in sync with Codex's evolving configuration schema.
            matches!(*arg, "-c" | "--config")
                || arg.starts_with("--config=")
                || (arg.starts_with("-c") && arg.len() > 2)
                || matches!(*arg, "--oss" | "--local-provider")
                || arg.starts_with("--local-provider=")
                || matches!(*arg, "--enable" | "--disable")
                || arg.starts_with("--enable=")
                || arg.starts_with("--disable=")
                || matches!(
                    *arg,
                    "--remote" | "--remote-auth-token-env" | "--remote-control"
                )
                || arg.starts_with("--remote=")
                || arg.starts_with("--remote-auth-token-env=")
        })
}

/// Return the first Codex argument that can select a transport outside the
/// guard-owned provider.
fn conflicting_codex_override(args: &[String]) -> Option<&str> {
    inspect_codex_args(args).err()
}

fn is_openrouter_upstream(upstream: &str) -> bool {
    reqwest::Url::parse(upstream)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| {
            host.eq_ignore_ascii_case("openrouter.ai")
                || host.to_ascii_lowercase().ends_with(".openrouter.ai")
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodexAuthSource {
    OpenAiEnvironment,
    CodexEnvironment,
    StoredApiKey,
}

#[derive(Debug)]
enum CodexPreflightError {
    NotFound,
    Rejected(String),
}

fn codex_process_error(action: &str, error: std::io::Error) -> CodexPreflightError {
    if error.kind() == std::io::ErrorKind::NotFound {
        CodexPreflightError::NotFound
    } else {
        CodexPreflightError::Rejected(format!("cannot {action} ({error})"))
    }
}

fn codex_config_args(base_url: &str, auth: CodexAuthSource) -> Vec<String> {
    let provider_name = format!("promtect_guard_{}", uuid::Uuid::new_v4().simple());
    codex_config_args_for_provider(base_url, auth, &provider_name)
}

fn codex_config_args_for_provider(
    base_url: &str,
    auth: CodexAuthSource,
    provider_name: &str,
) -> Vec<String> {
    // Keep the documented built-in override for current Codex compatibility,
    // but select a guard-owned provider whose complete definition cannot inherit
    // user routing. WebSockets and retries are disabled so one model call produces
    // one observable HTTP request through Promtect.
    let auth_fields = match auth {
        CodexAuthSource::StoredApiKey => "requires_openai_auth=true".to_string(),
        CodexAuthSource::OpenAiEnvironment | CodexAuthSource::CodexEnvironment => {
            "env_key=\"OPENAI_API_KEY\",requires_openai_auth=false".to_string()
        }
    };
    let provider = format!(
        "model_providers.{provider_name}={{name=\"Promtect guard\",base_url=\"{base_url}\",wire_api=\"responses\",{auth_fields},supports_websockets=false,request_max_retries=0,stream_max_retries=0}}"
    );
    vec![
        "-c".to_string(),
        format!("model_provider=\"{provider_name}\""),
        "-c".to_string(),
        format!("openai_base_url=\"{base_url}\""),
        "-c".to_string(),
        provider,
        "--disable".to_string(),
        "enable_request_compression".to_string(),
    ]
}

fn has_nonblank_env(key: &str) -> bool {
    std::env::var(key).is_ok_and(|value| !value.trim().is_empty())
}

fn classify_stored_codex_auth(status: &str) -> Result<CodexAuthSource, &'static str> {
    if status.contains("Logged in using ChatGPT") {
        return Err(
            "ChatGPT subscription authentication is unsupported because Codex can bypass the OpenAI API routing contract",
        );
    }
    if status.contains("Logged in using an API key") {
        return Ok(CodexAuthSource::StoredApiKey);
    }
    Err("Codex guard requires API-key authentication")
}

async fn verify_codex_auth(bin: &str) -> Result<CodexAuthSource, CodexPreflightError> {
    // An explicit environment key selects the guard-owned environment-auth
    // provider. A separate stored ChatGPT session cannot power or reroute it.
    if has_nonblank_env("OPENAI_API_KEY") {
        return Ok(CodexAuthSource::OpenAiEnvironment);
    }
    if has_nonblank_env("CODEX_API_KEY") {
        return Ok(CodexAuthSource::CodexEnvironment);
    }

    let mut cmd = tokio::process::Command::new(bin);
    configure_codex_network_env(&mut cmd);
    cmd.args(["login", "status"]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(5), cmd.output())
        .await
        .map_err(|_| CodexPreflightError::Rejected("Codex login status timed out".to_string()))?
        .map_err(|error| codex_process_error("check Codex login status", error))?;
    if !output.status.success() {
        return Err(CodexPreflightError::Rejected(
            "Codex login status check failed".to_string(),
        ));
    }
    // Codex versions have emitted this value-free status on both stdout and
    // stderr. Inspect both, but never relay either stream: future versions may
    // add authentication details that must not reach Promtect's own logs.
    let mut status = String::from_utf8_lossy(&output.stdout).into_owned();
    status.push_str(&String::from_utf8_lossy(&output.stderr));
    classify_stored_codex_auth(&status)
        .map_err(|error| CodexPreflightError::Rejected(error.to_string()))
}

fn configure_codex_network_env(cmd: &mut tokio::process::Command) {
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "WS_PROXY",
        "WSS_PROXY",
        "ws_proxy",
        "wss_proxy",
    ] {
        cmd.env_remove(key);
    }
    cmd.env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
}

fn configure_codex_command(cmd: &mut tokio::process::Command, auth: CodexAuthSource) {
    configure_codex_network_env(cmd);
    if auth == CodexAuthSource::CodexEnvironment
        && let Some(api_key) = std::env::var_os("CODEX_API_KEY")
    {
        // Codex custom providers consume their configured env_key. Alias the
        // documented CODEX_API_KEY only inside the child process; never log it.
        cmd.env("OPENAI_API_KEY", api_key);
    }
}

async fn verify_codex_config(
    bin: &str,
    base_url: &str,
    auth: CodexAuthSource,
) -> Result<(), CodexPreflightError> {
    let mut args = codex_config_args(base_url, auth);
    args.extend(["debug".to_string(), "models".to_string()]);
    let mut cmd = tokio::process::Command::new(bin);
    configure_codex_command(&mut cmd, auth);
    cmd.args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(10), cmd.status())
        .await
        .map_err(|_| CodexPreflightError::Rejected("Codex config check timed out".to_string()))?
        .map_err(|error| codex_process_error("run Codex config check", error))?;
    if status.success() {
        Ok(())
    } else {
        Err(CodexPreflightError::Rejected(
            "Codex rejected the fail-closed routing configuration".to_string(),
        ))
    }
}

async fn run_codex_dry_run(plan: &GuardPlan) -> i32 {
    let mut cmd = tokio::process::Command::new(&plan.bin);
    configure_codex_network_env(&mut cmd);
    match cmd.args(&plan.tool_args).kill_on_drop(true).status().await {
        Ok(status) => exit_code(&status, &plan.bin),
        Err(error) => {
            eprintln!(
                "promtect guard: failed to run '{}' ({error}). Is it installed and on your PATH?",
                plan.bin
            );
            127
        }
    }
}

/// Run a [`GuardPlan`]: start an ephemeral proxy, point the tool at it via its
/// base-URL env var, run the tool, and return its exit code. The proxy task is
/// dropped when the process exits.
pub async fn guard(plan: GuardPlan) -> i32 {
    if plan.codex_fail_closed
        && matches!(
            inspect_codex_args(&plan.tool_args),
            Ok(CodexInvocation::DryRun)
        )
    {
        return run_codex_dry_run(&plan).await;
    }

    let codex_auth = if plan.codex_fail_closed {
        match verify_codex_auth(&plan.bin).await {
            Ok(source) => Some(source),
            Err(CodexPreflightError::NotFound) => {
                eprintln!(
                    "promtect guard: failed to run '{}' (command not found). Is it installed and on your PATH?",
                    plan.bin
                );
                return 127;
            }
            Err(CodexPreflightError::Rejected(error)) => {
                eprintln!(
                    "promtect guard: refusing to start Codex: {error}.\n  \
                     Use an OpenAI API key or choose another supported guard; no provider request was sent."
                );
                return 1;
            }
        }
    } else {
        None
    };

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
        extra_detect: None,
        output_scan: None,
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
    let proxy_task = tokio::spawn(async move {
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

    if let Some(auth) = codex_auth {
        if let Err(error) = verify_codex_config(&plan.bin, &base_url, auth).await {
            proxy_task.abort();
            match error {
                CodexPreflightError::NotFound => {
                    eprintln!(
                        "promtect guard: failed to run '{}' (command not found). Is it installed and on your PATH?",
                        plan.bin
                    );
                    return 127;
                }
                CodexPreflightError::Rejected(error) => {
                    eprintln!(
                        "promtect guard: refusing to start Codex: {error}.\n  \
                         Upgrade Codex or remove conflicting configuration; no prompt was sent."
                    );
                    return 1;
                }
            }
        }
        eprintln!(
            "  Codex config check: protected Responses route accepted, WebSockets and request compression disabled"
        );
    }

    // Auto-start the dashboard so guard sessions get the same metrics UI as the
    // standalone proxy. Uses the same audit log, so guard traffic appears there.
    // Non-fatal: if the port is taken (e.g. another guard session), skip silently.
    let mut dashboard_task = None;
    if let Ok(dash_port) = proxy::parse_port(
        "PROMTECT_DASHBOARD_PORT",
        std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
        8799,
    ) {
        let dash_addr = format!("127.0.0.1:{dash_port}");
        if let Ok(dash_listener) = tokio::net::TcpListener::bind(&dash_addr).await {
            let dash_app = crate::dashboard::app(crate::dashboard::DashCtx {
                audit_path: Arc::new(audit_path_for_dash.as_str().into()),
                restore_enabled: plan.restore,
            });
            dashboard_task = Some(tokio::spawn(async move {
                // Drain in-flight dashboard requests on signal so metrics
                // pages aren't truncated when guard exits.
                if let Err(e) = axum::serve(dash_listener, dash_app)
                    .with_graceful_shutdown(crate::proxy::shutdown_signal())
                    .await
                {
                    eprintln!("promtect guard: dashboard error: {e}");
                }
            }));
            eprintln!("  dashboard: http://127.0.0.1:{dash_port}");
        }
    }

    // Inherit the full parent env (so the user's API keys flow through, forwarded
    // untouched), then override the tool's base-URL var to point at the proxy.
    // kill_on_drop ensures the child can't be orphaned if this future is dropped.
    let mut cmd = tokio::process::Command::new(&plan.bin);
    if let Some(auth) = codex_auth {
        configure_codex_command(&mut cmd, auth);
        cmd.args(codex_config_args(&base_url, auth));
    }
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
    // Wrapping a full-screen TUI (Claude Code, Codex, …): stay quiet during the
    // session so per-request notifications do not corrupt the tool's terminal.
    // The audit log + dashboard still capture everything; the summary prints below.
    crate::proxy::set_quiet(true);
    // Snapshot the audit so the exit summary reflects THIS session, not the whole
    // append-only log.
    let baseline = crate::metrics::aggregate(std::path::Path::new(&audit_path_for_dash));

    let status = cmd.status().await;
    proxy_task.abort();
    if let Some(task) = dashboard_task {
        task.abort();
    }

    // Tripwire: if the proxy never saw a request, the tool bypassed it entirely
    // (e.g. it ignored the base-URL var) — secrets may have gone out unmasked.
    // Skip for invocations that intentionally make no API calls.
    let is_dry_run = if plan.codex_fail_closed {
        matches!(
            inspect_codex_args(&plan.tool_args),
            Ok(CodexInvocation::DryRun)
        )
    } else {
        plan.tool_args.iter().any(|a| {
            matches!(
                a.as_str(),
                "--help" | "-h" | "--version" | "version" | "help"
            )
        })
    };
    if !is_dry_run {
        let req_count = requests.load(std::sync::atomic::Ordering::Relaxed);
        if req_count == 0 {
            eprintln!(
                "promtect guard: WARNING the proxy saw 0 requests — did '{}' use {}? \
                 secrets may have gone direct (unmasked).",
                plan.bin, plan.base_var
            );
        } else {
            // Value-free end-of-session summary, now that the TUI has released the
            // terminal: the useful Promtect signal without disturbing the session.
            let after = crate::metrics::aggregate(std::path::Path::new(&audit_path_for_dash));
            print_guard_summary(&baseline, &after);
        }
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

/// Print a value-free end-of-session summary for a guard run: how many secrets it
/// masked outbound, and how many the Pro output scan caught in the model's replies.
/// Counts are the difference between an audit snapshot taken before the tool
/// launched and one taken now, so they reflect this session only.
fn print_guard_summary(before: &crate::metrics::Metrics, after: &crate::metrics::Metrics) {
    let masked = after
        .secrets_masked_total
        .saturating_sub(before.secrets_masked_total);
    let echoed = after
        .output_secrets_total
        .saturating_sub(before.output_secrets_total);

    if masked == 0 {
        eprintln!("promtect guard: this session masked 0 secrets — nothing sensitive was sent.");
    } else {
        let kinds = kinds_delta(&before.by_detector, &after.by_detector);
        eprintln!(
            "promtect guard: this session masked {masked} secret{} ({}). Rotate anything \
             that already leaked; Promtect kept these from arriving.",
            if masked == 1 { "" } else { "s" },
            kinds.join(", "),
        );
    }
    if echoed > 0 {
        eprintln!(
            "promtect guard: the output scan flagged {echoed} secret{} in the model's replies.",
            if echoed == 1 { "" } else { "s" },
        );
    }
}

/// Detector kinds whose masked count increased between two audit snapshots, sorted.
fn kinds_delta(
    before: &std::collections::BTreeMap<String, u64>,
    after: &std::collections::BTreeMap<String, u64>,
) -> Vec<String> {
    let mut kinds: Vec<String> = after
        .iter()
        .filter(|(k, c)| **c > before.get(k.as_str()).copied().unwrap_or(0))
        .map(|(k, _)| k.clone())
        .collect();
    kinds.sort();
    kinds
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

    #[test]
    fn kinds_delta_reports_only_increased_kinds() {
        use std::collections::BTreeMap;
        let before = BTreeMap::from([("aws_key".to_string(), 1u64), ("jwt".to_string(), 2)]);
        let after = BTreeMap::from([
            ("aws_key".to_string(), 3u64),   // increased
            ("jwt".to_string(), 2),          // unchanged → excluded
            ("github_token".to_string(), 1), // new → included
        ]);
        assert_eq!(
            kinds_delta(&before, &after),
            vec!["aws_key".to_string(), "github_token".to_string()]
        );
    }

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
        assert!(p.codex_fail_closed);
    }

    #[test]
    fn codex_config_args_force_routing_and_disable_compression() {
        assert_eq!(
            codex_config_args_for_provider(
                "http://127.0.0.1:12345/v1",
                CodexAuthSource::OpenAiEnvironment,
                "promtect_guard",
            ),
            vec![
                "-c",
                "model_provider=\"promtect_guard\"",
                "-c",
                "openai_base_url=\"http://127.0.0.1:12345/v1\"",
                "-c",
                "model_providers.promtect_guard={name=\"Promtect guard\",base_url=\"http://127.0.0.1:12345/v1\",wire_api=\"responses\",env_key=\"OPENAI_API_KEY\",requires_openai_auth=false,supports_websockets=false,request_max_retries=0,stream_max_retries=0}",
                "--disable",
                "enable_request_compression",
            ]
        );
    }

    #[test]
    fn codex_stored_auth_uses_managed_auth_without_env_key() {
        let args = codex_config_args("http://127.0.0.1:12345/v1", CodexAuthSource::StoredApiKey);

        assert!(
            args.iter()
                .any(|arg| arg.contains("requires_openai_auth=true"))
        );
        assert!(!args.iter().any(|arg| arg.contains("env_key")));
    }

    #[test]
    fn codex_provider_identity_is_fresh_for_each_child() {
        let first = codex_config_args(
            "http://127.0.0.1:12345/v1",
            CodexAuthSource::OpenAiEnvironment,
        );
        let second = codex_config_args(
            "http://127.0.0.1:12345/v1",
            CodexAuthSource::OpenAiEnvironment,
        );

        assert!(first[1].starts_with("model_provider=\"promtect_guard_"));
        assert!(second[1].starts_with("model_provider=\"promtect_guard_"));
        assert_ne!(first[1], second[1]);
    }

    #[test]
    fn codex_rejects_routing_and_compression_overrides() {
        for args in [
            vec!["codex", "-c", "openai_base_url=\"https://example.test\""],
            vec!["codex", "-cmodel_provider=\"other\""],
            vec!["codex", "-c=model_provider=\"other\""],
            vec!["codex", "--config", "model=\"other\""],
            vec!["codex", "--config=model_provider=\"other\""],
            vec![
                "codex",
                "-c",
                "model_providers={promtect_guard={base_url=\"https://example.test\"}}",
            ],
            vec!["codex", "--enable", "enable_request_compression"],
            vec!["codex", "--disable=responses_websockets"],
            vec!["codex", "--oss"],
            vec!["codex", "--local-provider=ollama"],
            vec!["codex", "--remote", "environment-id"],
            vec!["codex", "--remote-auth-token-env=TOKEN"],
            vec!["codex", "remote-control"],
            vec!["codex", "cloud"],
            vec!["codex", "app-server"],
            vec!["codex", "mcp-server"],
            vec!["codex", "exec-server"],
        ] {
            let error = plan(&args).unwrap_err();
            assert!(
                error.contains("bypass Promtect"),
                "expected fail-closed override error for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn codex_stored_auth_rejects_chatgpt() {
        let error = classify_stored_codex_auth("Logged in using ChatGPT").unwrap_err();
        assert!(error.contains("ChatGPT subscription"), "{error}");
    }

    #[test]
    fn codex_stored_auth_accepts_only_api_key_login() {
        assert_eq!(
            classify_stored_codex_auth("Logged in using an API key"),
            Ok(CodexAuthSource::StoredApiKey)
        );
        assert!(classify_stored_codex_auth("Not logged in").is_err());
        assert!(classify_stored_codex_auth("unexpected authentication error").is_err());
    }

    #[test]
    fn codex_normal_model_flag_remains_supported() {
        let plan = plan(&["codex", "--model", "synthetic-model", "exec", "safe prompt"]).unwrap();

        assert_eq!(
            plan.tool_args,
            ["--model", "synthetic-model", "exec", "safe prompt"]
        );
    }

    #[test]
    fn codex_option_values_cannot_hide_an_unsafe_root_command() {
        for args in [
            vec!["codex", "--model", "exec", "cloud"],
            vec!["codex", "--profile", "exec", "remote-control"],
            vec!["codex", "--cd", "exec", "app-server"],
        ] {
            let error = plan(&args).unwrap_err();
            assert!(
                error.contains("bypass Promtect"),
                "expected fail-closed root-command error for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn codex_global_routing_overrides_fail_closed_after_subcommands() {
        for args in [
            vec![
                "codex",
                "exec",
                "safe prompt",
                "-c",
                "model_provider=\"openai\"",
            ],
            vec!["codex", "exec", "--oss", "safe prompt"],
            vec!["codex", "review", "--enable", "web_search"],
            vec!["codex", "review", "--local-provider=ollama"],
        ] {
            let error = plan(&args).unwrap_err();
            assert!(
                error.contains("bypass Promtect"),
                "expected post-subcommand override rejection for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn codex_unknown_root_commands_fail_closed() {
        let error = plan(&["codex", "future-network-command"]).unwrap_err();

        assert!(error.contains("bypass Promtect"), "{error}");

        for args in [
            vec!["codex", "version"],
            vec!["codex", "--profile", "safe", "version"],
        ] {
            let error = plan(&args).unwrap_err();
            assert!(
                error.contains("bypass Promtect"),
                "expected bare version prompt to fail closed for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn codex_dry_runs_are_classified_without_provider_preflight() {
        let args = vec![
            "--model".to_string(),
            "exec".to_string(),
            "--help".to_string(),
        ];

        assert_eq!(inspect_codex_args(&args), Ok(CodexInvocation::DryRun));

        for args in [
            vec!["exec", "--help"],
            vec!["exec", "--version"],
            vec!["review", "--help"],
        ] {
            let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert_eq!(inspect_codex_args(&args), Ok(CodexInvocation::DryRun));
        }

        let prompt_help = ["exec", "--", "--help"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(inspect_codex_args(&prompt_help), Ok(CodexInvocation::Exec));
    }

    #[test]
    fn codex_rejects_openrouter_even_as_an_explicit_upstream() {
        let error = plan(&[
            "codex",
            "--upstream",
            "https://openrouter.ai/api/v1",
            "exec",
            "safe prompt",
        ])
        .unwrap_err();

        assert!(error.contains("OpenRouter is not supported"), "{error}");
    }

    #[test]
    fn codex_child_clears_parent_proxies_and_forces_loopback_no_proxy() {
        let mut command = tokio::process::Command::new("codex");
        configure_codex_command(&mut command, CodexAuthSource::OpenAiEnvironment);
        let env = command.as_std().get_envs().collect::<Vec<_>>();

        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "WS_PROXY",
            "WSS_PROXY",
            "ws_proxy",
            "wss_proxy",
        ] {
            assert!(
                env.iter()
                    .any(|(name, value)| *name == key && value.is_none()),
                "expected {key} to be removed from the Codex child"
            );
        }
        for key in ["NO_PROXY", "no_proxy"] {
            assert!(env.iter().any(|(name, value)| {
                *name == key && value.is_some_and(|value| value == "127.0.0.1,localhost")
            }));
        }
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
    fn ollama_cloud_points_at_ollama_dot_com() {
        let p = plan(&["ollama", "--cloud", "run", "gpt-oss:120b-cloud"]).unwrap();
        assert_eq!(p.bin, "ollama");
        assert_eq!(p.base_var, "OLLAMA_HOST");
        assert_eq!(p.base_path, "");
        assert_eq!(p.upstream, "https://ollama.com");
        // --cloud must not be swallowed into the tool's args.
        assert_eq!(p.tool_args, vec!["run", "gpt-oss:120b-cloud"]);
    }

    #[test]
    fn cloud_flag_rejected_on_non_ollama_tool() {
        let err = plan(&["codex", "--cloud"]).unwrap_err();
        assert!(
            err.contains("only valid with ollama"),
            "expected ollama-only error, got {err:?}"
        );
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
    fn codex_openrouter_fails_closed() {
        let error = plan(&["codex", "--openrouter"]).unwrap_err();
        assert!(error.contains("not supported"), "{error}");
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
