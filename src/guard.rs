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
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Seek};
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
    /// Whether this is the named Claude preset, which supports only a verified
    /// unmanaged profile and owns routing plus the user-only notice for the session.
    pub claude_fail_closed: bool,
}

/// Default Headroom URL — Headroom binds `127.0.0.1:8787` by default.
/// Use `--headroom=<url>` to override (e.g. `--headroom=http://127.0.0.1:9000`).
const HEADROOM_DEFAULT: &str = "http://127.0.0.1:8787";
const CLAUDE_BASE_VAR: &str = "ANTHROPIC_BASE_URL";
const CLAUDE_PROVIDER_SELECTORS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_MANTLE",
    "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "CLAUDE_CODE_USE_GATEWAY",
];
const CLAUDE_AUTH_OVERRIDE_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_BEDROCK_MANTLE_API_KEY",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "CLAUDE_CODE_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
];
const CLAUDE_RUNTIME_OVERRIDE_VARS: &[&str] = &[
    "CLAUDE_CODE_SAFE_MODE",
    "CLAUDE_CODE_SIMPLE",
    "CLAUDE_CODE_MANAGED_SETTINGS_PATH",
    "CLAUDE_CODE_REMOTE_SETTINGS_PATH",
    "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "CLAUDE_CODE_HOST_AUTH_ENV_VAR",
    "CLAUDE_CODE_HOST_CREDS_FILE",
    "CLAUDE_CODE_PROCESS_WRAPPER",
];
const CLAUDE_SUPPORTED_VERSION: &str = "2.1.209 (Claude Code)";
const CLAUDE_UNSUPPORTED_ROOT_COMMANDS: &[&str] = &[
    "agents",
    "auth",
    "auto-mode",
    "doctor",
    "gateway",
    "install",
    "mcp",
    "plugin",
    "plugins",
    "project",
    "setup-token",
    "ultrareview",
    "update",
    "upgrade",
];
const CLAUDE_NOTICE_ROUTE: &str = "/_promtect/hooks/{token}";
const CLAUDE_NOTICE_MAX_DELTA_BYTES: u64 = 1024 * 1024;
const CLAUDE_NOTICE_MAX_RECORD_BYTES: u64 = 16 * 1024;
const CLAUDE_NOTICE_MAX_RECORDS: usize = 4096;
const CLAUDE_NOTICE_MAX_REQUEST_ID_BYTES: usize = 256;
const CLAUDE_NOTICE_MAX_DETECTOR_BYTES: usize = 64;
const CLAUDE_NOTICE_MAX_DETECTORS: usize = 128;
const CLAUDE_NOTICE_DEGRADED_MESSAGE: &str = "🛡 Promtect could not safely summarize this turn’s protection metadata. No sensitive values are included; check the local dashboard and guard summary.";

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
    if tool == Some("claude")
        && let Some(key) = conflicting_claude_override(&tool_args)
    {
        return Err(format!(
            "Claude argument {key:?} conflicts with Promtect's protected routing or automatic notice; remove it (guard injects protected settings automatically)"
        ));
    }

    // ── per-tool wiring (verified against each tool's docs) ──────────────────
    let (base_var, base_path, mode): (String, String, String) = match tool {
        Some("claude") => {
            if openrouter {
                return Err("--openrouter is not valid with claude (Anthropic only)".to_string());
            }
            (CLAUDE_BASE_VAR.into(), String::new(), "anthropic".into())
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
        claude_fail_closed: tool == Some("claude"),
    })
}

/// Return the first Claude argument that conflicts with guard-owned routing or
/// disables the automatic, Promtect-owned in-session notice.
fn conflicting_claude_override(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|arg| {
            *arg == "--settings"
                || arg.starts_with("--settings=")
                || *arg == "--managed-settings"
                || arg.starts_with("--managed-settings=")
                || [
                    "--safe-mode=",
                    "--bare=",
                    "--background=",
                    "--bg=",
                    "--remote-control=",
                    "--tmux=",
                    "--worktree=",
                ]
                .iter()
                .any(|prefix| arg.starts_with(prefix))
                || arg.starts_with("-w")
                || matches!(
                    *arg,
                    "--safe-mode"
                        | "--bare"
                        | "--background"
                        | "--bg"
                        | "--remote-control"
                        | "--tmux"
                        | "--worktree"
                )
        })
        .or_else(|| first_claude_root_command(args))
}

/// Return the root command selected by Claude's pinned CLI grammar, if it is
/// one of the commands whose independent network/lifecycle behavior guard has
/// not reviewed. Option values must not be mistaken for commands: for example,
/// `claude --name doctor` names an interactive session and does not run
/// `claude doctor`.
fn first_claude_root_command(args: &[String]) -> Option<&str> {
    const VALUE_OPTIONS: &[&str] = &[
        "--agent",
        "--agents",
        "--append-system-prompt",
        "--debug-file",
        "--effort",
        "--fallback-model",
        "--input-format",
        "--json-schema",
        "--max-budget-usd",
        "--model",
        "--name",
        "-n",
        "--output-format",
        "--permission-mode",
        "--plugin-dir",
        "--plugin-url",
        "--remote-control-session-name-prefix",
        "--session-id",
        "--setting-sources",
        "--settings",
        "--system-prompt",
    ];
    const OPTIONAL_VALUE_OPTIONS: &[&str] = &[
        "--debug",
        "-d",
        "--from-pr",
        "--prompt-suggestions",
        "--remote-control",
        "--resume",
        "-r",
        "--worktree",
        "-w",
    ];
    const VARIADIC_VALUE_OPTIONS: &[&str] = &[
        "--add-dir",
        "--allowedTools",
        "--allowed-tools",
        "--betas",
        "--disallowedTools",
        "--disallowed-tools",
        "--file",
        "--mcp-config",
        "--tools",
    ];

    let mut index = 0usize;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if arg == "--" {
            // Commander treats everything after `--` as prompt text, not as a
            // root command. Conflicting routing flags are still rejected by the
            // independent scan above.
            return None;
        }
        if !arg.starts_with('-') {
            return CLAUDE_UNSUPPORTED_ROOT_COMMANDS
                .contains(&arg)
                .then_some(arg);
        }
        if arg.contains('=') || (arg.starts_with("-n") && arg != "-n") {
            index += 1;
            continue;
        }
        if VALUE_OPTIONS.contains(&arg) {
            index = index.saturating_add(2);
            continue;
        }
        if OPTIONAL_VALUE_OPTIONS.contains(&arg) {
            index += 1;
            if args.get(index).is_some_and(|value| !value.starts_with('-')) {
                index += 1;
            }
            continue;
        }
        if VARIADIC_VALUE_OPTIONS.contains(&arg) {
            index += 1;
            while args.get(index).is_some_and(|value| !value.starts_with('-')) {
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    None
}

fn claude_settings_json(base_url: &str, notice_url: &str) -> String {
    let mut env = serde_json::Map::new();
    env.insert(CLAUDE_BASE_VAR.to_string(), serde_json::json!(base_url));
    for selector in CLAUDE_PROVIDER_SELECTORS {
        // Current Claude transports recognize these selectors as enabled by `1`.
        // An explicit `0` overrides hostile persisted settings without relying on
        // inherited environment state; the pinned real-CLI harness verifies this.
        env.insert((*selector).to_string(), serde_json::json!("0"));
    }
    for variable in CLAUDE_AUTH_OVERRIDE_VARS
        .iter()
        .chain(CLAUDE_RUNTIME_OVERRIDE_VARS)
    {
        // Inline settings outrank ordinary user/project settings. Clearing the
        // complete reviewed set prevents a persisted API-key/runtime selector
        // from reappearing after the stored-profile preflight.
        env.insert((*variable).to_string(), serde_json::json!(""));
    }
    env.insert("ANTHROPIC_UNIX_SOCKET".to_string(), serde_json::json!(""));
    for proxy in [
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
        env.insert(proxy.to_string(), serde_json::json!(""));
    }
    env.insert(
        "NO_PROXY".to_string(),
        serde_json::json!("127.0.0.1,localhost"),
    );
    env.insert(
        "no_proxy".to_string(),
        serde_json::json!("127.0.0.1,localhost"),
    );
    serde_json::json!({
        "env": env,
        "disableAllHooks": false,
        "hooks": {
            "Stop": [{
                "hooks": [{
                    "type": "http",
                    "url": notice_url,
                    "timeout": 5
                }]
            }]
        }
    })
    .to_string()
}

struct ClaudeSettingsFile {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl ClaudeSettingsFile {
    fn create(base_url: &str, notice_url: &str) -> std::io::Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("promtect-claude-{}", uuid::Uuid::new_v4().simple()));
        let mut directory_builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory_builder.mode(0o700);
        }
        directory_builder.create(&directory)?;

        let path = directory.join("settings.json");
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            use std::io::Write;
            file.write_all(claude_settings_json(base_url, notice_url).as_bytes())?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            std::fs::remove_file(&path).ok();
            std::fs::remove_dir(&directory).ok();
            return Err(error);
        }

        Ok(Self { directory, path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ClaudeSettingsFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
        std::fs::remove_dir(&self.directory).ok();
    }
}

#[derive(Clone)]
struct ClaudeNoticeState {
    audit_path: Arc<std::path::PathBuf>,
    audit: Option<Arc<Audit>>,
    cursor: Arc<std::sync::Mutex<u64>>,
    reading: Arc<std::sync::atomic::AtomicBool>,
    token: Arc<str>,
    request_prefix: Arc<str>,
    strict: bool,
}

impl ClaudeNoticeState {
    fn new(
        audit_path: impl Into<std::path::PathBuf>,
        token: String,
        request_scope: &str,
        strict: bool,
    ) -> Self {
        let audit_path = audit_path.into();
        let cursor = std::fs::metadata(&audit_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Self {
            audit_path: Arc::new(audit_path),
            audit: None,
            cursor: Arc::new(std::sync::Mutex::new(cursor)),
            reading: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            request_prefix: format!("{request_scope}:").into(),
            token: token.into(),
            strict,
        }
    }

    fn with_audit(mut self, audit: Arc<Audit>) -> Self {
        self.audit = Some(audit);
        self
    }
}

struct ClaudeNoticeReadPermit(Arc<std::sync::atomic::AtomicBool>);

impl Drop for ClaudeNoticeReadPermit {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ClaudeNotice {
    masked: u64,
    detectors: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ClaudeNoticeRead {
    Empty,
    Notice(ClaudeNotice),
    Degraded,
}

#[derive(Debug, Default)]
struct RequestNotice {
    masked: u64,
    detectors: BTreeSet<String>,
}

fn valid_detector_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= CLAUDE_NOTICE_MAX_DETECTOR_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Read only complete audit records written since the previous Claude Stop hook.
/// The result contains counts and detector kinds, never request bodies or values.
fn take_claude_notice(state: &ClaudeNoticeState) -> ClaudeNoticeRead {
    let mut cursor = state
        .cursor
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut file = match Audit::open_read(state.audit_path.as_path()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ClaudeNoticeRead::Degraded;
        }
        Err(_) => return ClaudeNoticeRead::Degraded,
    };
    let len = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(_) => return ClaudeNoticeRead::Degraded,
    };
    if *cursor > len {
        // A same-inode copy-truncate invalidates the saved generation. Never
        // silently turn that loss of evidence into a false zero-event result.
        *cursor = len;
        return ClaudeNoticeRead::Degraded;
    }
    let delta = len - *cursor;
    if delta == 0 {
        return ClaudeNoticeRead::Empty;
    }
    if delta > CLAUDE_NOTICE_MAX_DELTA_BYTES {
        *cursor = len;
        return ClaudeNoticeRead::Degraded;
    }
    if file.seek(std::io::SeekFrom::Start(*cursor)).is_err() {
        return ClaudeNoticeRead::Degraded;
    }

    // Read only the snapshotted delta. Concurrent appends belong to the next hook,
    // so a busy audit can never make this invocation chase a moving EOF.
    let mut reader = std::io::BufReader::new(file.take(delta));
    let mut line = Vec::new();
    let mut requests: BTreeMap<String, RequestNotice> = BTreeMap::new();
    let mut unsuccessful = BTreeSet::new();
    let mut next_cursor = *cursor;
    let mut records = 0usize;

    loop {
        line.clear();
        let bytes = match reader
            .by_ref()
            .take(CLAUDE_NOTICE_MAX_RECORD_BYTES + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(bytes) => bytes,
            Err(_) => {
                *cursor = len;
                return ClaudeNoticeRead::Degraded;
            }
        };
        if bytes == 0 {
            break;
        }
        if bytes as u64 > CLAUDE_NOTICE_MAX_RECORD_BYTES {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        }
        if !line.ends_with(b"\n") {
            // A writer may still be completing this record. Leave it pending for
            // the next hook instead of accepting a partial JSON object.
            break;
        }
        records += 1;
        if records > CLAUDE_NOTICE_MAX_RECORDS {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        }
        next_cursor = next_cursor.saturating_add(bytes as u64);

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&line) else {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        };
        let Some(action) = value.get("action").and_then(|field| field.as_str()) else {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        };
        let Some(request_id) = value
            .get("request_id")
            .and_then(|field| field.as_str())
            .filter(|request_id| !request_id.is_empty())
        else {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        };
        if request_id.len() > CLAUDE_NOTICE_MAX_REQUEST_ID_BYTES {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        }
        if !request_id.starts_with(state.request_prefix.as_ref()) {
            continue;
        }

        match action {
            "request" => {
                let Some(masked) = value.get("masked").and_then(|field| field.as_u64()) else {
                    *cursor = len;
                    return ClaudeNoticeRead::Degraded;
                };
                let Some(blocked) = value.get("blocked").and_then(|field| field.as_bool()) else {
                    *cursor = len;
                    return ClaudeNoticeRead::Degraded;
                };
                let Some(detectors) = value.get("detectors").and_then(|field| field.as_array())
                else {
                    *cursor = len;
                    return ClaudeNoticeRead::Degraded;
                };
                let mut validated_detectors = BTreeSet::new();
                for detector in detectors {
                    let Some(detector) = detector.as_str() else {
                        *cursor = len;
                        return ClaudeNoticeRead::Degraded;
                    };
                    if !valid_detector_name(detector) {
                        *cursor = len;
                        return ClaudeNoticeRead::Degraded;
                    }
                    validated_detectors.insert(detector.to_string());
                    if validated_detectors.len() > CLAUDE_NOTICE_MAX_DETECTORS {
                        *cursor = len;
                        return ClaudeNoticeRead::Degraded;
                    }
                }
                if masked > 0 && validated_detectors.is_empty() {
                    *cursor = len;
                    return ClaudeNoticeRead::Degraded;
                }
                if blocked {
                    unsuccessful.insert(request_id.to_string());
                    continue;
                }
                if masked == 0 {
                    continue;
                }
                let entry = requests.entry(request_id.to_string()).or_default();
                entry.masked = entry.masked.saturating_add(masked);
                entry.detectors.extend(validated_detectors);
            }
            "request_blocked" | "request_rejected" | "request_failed" | "stream_interrupted" => {
                unsuccessful.insert(request_id.to_string());
            }
            _ => {}
        }
    }
    *cursor = next_cursor;

    let mut notice = ClaudeNotice::default();
    for (request_id, request) in requests {
        if unsuccessful.contains(&request_id) {
            continue;
        }
        notice.masked = notice.masked.saturating_add(request.masked);
        notice.detectors.extend(request.detectors);
        if notice.detectors.len() > CLAUDE_NOTICE_MAX_DETECTORS {
            *cursor = len;
            return ClaudeNoticeRead::Degraded;
        }
    }
    if notice.masked > 0 {
        ClaudeNoticeRead::Notice(notice)
    } else {
        ClaudeNoticeRead::Empty
    }
}

fn detector_display_name(kind: &str) -> String {
    match kind {
        "aws_key" => "AWS access key".to_string(),
        "anthropic_key" => "Anthropic API key".to_string(),
        "github_token" => "GitHub token".to_string(),
        "stripe_key" => "Stripe API key".to_string(),
        _ => kind.replace('_', " "),
    }
}

fn claude_managed_settings_root() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(std::path::PathBuf::from(
            "/Library/Application Support/ClaudeCode",
        ))
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Some(std::path::PathBuf::from("/etc/claude-code"))
    }
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var_os("ProgramFiles")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files"));
        Some(root.join("ClaudeCode"))
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        None
    }
}

fn claude_managed_settings_paths(
    root: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut paths = vec![root.join("managed-settings.json")];
    let drop_ins = root.join("managed-settings.d");
    let entries = match std::fs::read_dir(&drop_ins) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(error) => {
            return Err(format!(
                "cannot verify Claude managed-settings drop-ins at {} ({error})",
                drop_ins.display()
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot verify Claude managed-settings drop-ins at {} ({error})",
                drop_ins.display()
            )
        })?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with('.')
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn json_has_settings(contents: &str) -> Result<bool, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(contents)?;
    Ok(match value {
        serde_json::Value::Object(object) => !object.is_empty(),
        serde_json::Value::Null => false,
        _ => true,
    })
}

#[cfg(unix)]
fn open_claude_settings_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = std::fs::File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "settings source is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_claude_settings_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "settings source is not a regular file",
        ));
    }
    Ok(file)
}

fn read_claude_settings_file(
    path: &std::path::Path,
    source: &str,
) -> Result<Option<String>, String> {
    const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
    let file = match open_claude_settings_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot verify Claude {source} at {} ({error})",
                path.display()
            ));
        }
    };
    let mut contents = String::new();
    file.take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| {
            format!(
                "cannot verify Claude {source} at {} ({error})",
                path.display()
            )
        })?;
    if contents.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(format!(
            "cannot verify Claude {source} at {} because it exceeds the safety limit",
            path.display()
        ));
    }
    Ok(Some(contents))
}

fn validate_claude_unmanaged_files(paths: &[std::path::PathBuf]) -> Result<(), String> {
    for path in paths {
        let Some(contents) = read_claude_settings_file(path, "managed settings")? else {
            continue;
        };
        let has_settings = json_has_settings(&contents).map_err(|error| {
            format!(
                "cannot verify malformed Claude managed settings at {} ({error})",
                path.display()
            )
        })?;
        if has_settings {
            return Err(format!(
                "endpoint-managed Claude settings are active at {}; managed profiles can override protected routing and the automatic notice",
                path.display()
            ));
        }
    }
    Ok(())
}

fn claude_config_dir() -> Result<std::path::PathBuf, String> {
    if let Some(path) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok(path.into());
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| "cannot locate Claude's configuration directory".to_string())?;
    Ok(std::path::PathBuf::from(home).join(".claude"))
}

fn validate_claude_remote_settings(config_dir: &std::path::Path) -> Result<(), String> {
    let path = config_dir.join("remote-settings.json");
    let Some(contents) = read_claude_settings_file(&path, "remote settings")? else {
        return Ok(());
    };
    let has_settings = json_has_settings(&contents).map_err(|error| {
        format!(
            "cannot verify malformed Claude remote settings at {} ({error})",
            path.display()
        )
    })?;
    if has_settings {
        return Err(
            "server-managed Claude settings are active; Team, Enterprise, and gateway-managed profiles are not supported by guard claude"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_claude_os_policy() -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/defaults")
        .args(["read", "com.anthropic.claudecode"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|error| format!("cannot verify Claude macOS managed preferences ({error})"))?;
    if output.status.success() {
        return Err(
            "macOS-managed Claude settings are active; managed profiles are not supported by guard claude"
                .to_string(),
        );
    }
    let stderr = bounded_policy_probe_text(&output.stderr)?;
    if output.status.code() == Some(1)
        && stderr.contains("Domain com.anthropic.claudecode does not exist")
    {
        Ok(())
    } else {
        Err("cannot verify whether Claude macOS managed preferences are active".to_string())
    }
}

#[cfg(target_os = "windows")]
fn validate_claude_os_policy() -> Result<(), String> {
    Err(
        "guard claude is not supported on Windows because Promtect cannot yet verify Windows policy and descendant cleanup"
            .to_string(),
    )
}

#[cfg(target_os = "macos")]
fn bounded_policy_probe_text(bytes: &[u8]) -> Result<String, String> {
    const MAX_POLICY_PROBE_BYTES: usize = 4096;
    if bytes.len() > MAX_POLICY_PROBE_BYTES {
        return Err("Claude managed-policy probe output exceeded its safety limit".to_string());
    }
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| "Claude managed-policy probe returned invalid text".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn validate_claude_os_policy() -> Result<(), String> {
    Ok(())
}

fn validate_claude_auth_status(bytes: &[u8]) -> Result<(), String> {
    let status: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "Claude auth status did not return valid JSON".to_string())?;
    if status.get("loggedIn").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("Claude is not authenticated".to_string());
    }
    if status
        .get("apiProvider")
        .and_then(serde_json::Value::as_str)
        != Some("firstParty")
    {
        return Err(
            "gateway and third-party Claude authentication profiles are not supported".to_string(),
        );
    }
    match status.get("authMethod").and_then(serde_json::Value::as_str) {
        Some("claude.ai") => match status
            .get("subscriptionType")
            .and_then(serde_json::Value::as_str)
        {
            Some("max")
                if status
                    .get("organizationType")
                    .is_none_or(serde_json::Value::is_null) =>
            {
                Ok(())
            }
            _ => Err(
                "Team, Enterprise, and unknown Claude subscription profiles are not supported"
                    .to_string(),
            ),
        },
        _ => Err("unknown Claude authentication profile is not supported".to_string()),
    }
}

fn validate_claude_version(bytes: &[u8]) -> Result<(), String> {
    let version = std::str::from_utf8(bytes)
        .map_err(|_| "Claude version check returned invalid text".to_string())?
        .trim();
    if version == CLAUDE_SUPPORTED_VERSION {
        Ok(())
    } else {
        Err(format!(
            "Claude version is unsupported; guard claude currently requires {CLAUDE_SUPPORTED_VERSION}"
        ))
    }
}

async fn verify_claude_version(bin: &str) -> Result<(), String> {
    let mut command = tokio::process::Command::new(bin);
    configure_guard_child_network_env(&mut command);
    command
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not run Claude version preflight ({error})"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not read Claude version preflight".to_string())?;
    let output = tokio::time::timeout(Duration::from_secs(5), async {
        use tokio::io::AsyncReadExt;

        const MAX_VERSION_BYTES: u64 = 256;
        let mut bytes = Vec::new();
        stdout
            .take(MAX_VERSION_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "could not read Claude version preflight".to_string())?;
        if bytes.len() as u64 > MAX_VERSION_BYTES {
            child.kill().await.ok();
            return Err("Claude version preflight output exceeded its safety limit".to_string());
        }
        let status = child
            .wait()
            .await
            .map_err(|_| "Claude version preflight failed".to_string())?;
        Ok((status, bytes))
    })
    .await
    .map_err(|_| "Claude version preflight timed out".to_string())??;
    if !output.0.success() {
        return Err("Claude version preflight failed".to_string());
    }
    validate_claude_version(&output.1)
}

fn first_claude_auth_override(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    CLAUDE_AUTH_OVERRIDE_VARS
        .iter()
        .copied()
        .find(|variable| is_set(variable))
}

fn first_claude_runtime_override(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    CLAUDE_RUNTIME_OVERRIDE_VARS
        .iter()
        .copied()
        .find(|variable| is_set(variable))
}

async fn verify_claude_unmanaged_profile(bin: &str) -> Result<(), String> {
    if let Some(variable) =
        first_claude_runtime_override(|variable| std::env::var_os(variable).is_some())
    {
        return Err(format!(
            "Claude runtime override {variable} is set; guard claude cannot verify protected routing and the automatic notice"
        ));
    }
    if let Some(variable) =
        first_claude_auth_override(|variable| std::env::var_os(variable).is_some())
    {
        return Err(format!(
            "Claude authentication override {variable} is set; guard claude requires the verified stored individual Max credential"
        ));
    }
    tokio::task::spawn_blocking(|| {
        if let Some(root) = claude_managed_settings_root() {
            let paths = claude_managed_settings_paths(&root)?;
            validate_claude_unmanaged_files(&paths)?;
        }
        validate_claude_os_policy()?;
        validate_claude_remote_settings(&claude_config_dir()?)
    })
    .await
    .map_err(|_| "Claude managed-profile preflight failed".to_string())??;

    verify_claude_version(bin).await?;

    let mut command = tokio::process::Command::new(bin);
    configure_guard_child_network_env(&mut command);
    command
        .args(["auth", "status", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not run Claude auth preflight ({error})"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not read Claude auth preflight".to_string())?;
    let output = tokio::time::timeout(Duration::from_secs(5), async {
        use tokio::io::AsyncReadExt;

        const MAX_AUTH_STATUS_BYTES: u64 = 64 * 1024;
        let mut bytes = Vec::new();
        stdout
            .take(MAX_AUTH_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "could not read Claude auth preflight".to_string())?;
        if bytes.len() as u64 > MAX_AUTH_STATUS_BYTES {
            child.kill().await.ok();
            return Err("Claude auth preflight output exceeded its safety limit".to_string());
        }
        let status = child
            .wait()
            .await
            .map_err(|_| "Claude auth preflight failed".to_string())?;
        Ok((status, bytes))
    })
    .await
    .map_err(|_| "Claude auth preflight timed out".to_string())??;
    if !output.0.success() {
        return Err("Claude auth preflight failed".to_string());
    }
    validate_claude_auth_status(&output.1)
}

fn format_claude_notice(notice: &ClaudeNotice, strict: bool) -> String {
    let detector_label = if notice.detectors.len() == 1 {
        "Detector"
    } else {
        "Detectors"
    };
    let detectors = notice
        .detectors
        .iter()
        .map(|kind| format!("{} (`{kind}`)", detector_display_name(kind)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut message = format!(
        "🛡 Promtect prevented an exposure — masked {} sensitive value{} before {} left your machine. {detector_label}: {detectors}.",
        notice.masked,
        if notice.masked == 1 { "" } else { "s" },
        if notice.masked == 1 { "it" } else { "they" },
    );
    if strict {
        message.push_str(" Strict mode: plaintext restoration off.");
    }
    message
}

async fn claude_notice_hook(
    State(state): State<ClaudeNoticeState>,
    Path(token): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !constant_time_token_eq(token.as_bytes(), state.token.as_bytes()) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({})));
    }
    if state
        .audit
        .as_ref()
        .is_some_and(|audit| !audit.is_healthy())
    {
        if let Some(audit) = state.audit.as_ref() {
            audit.mark_unhealthy();
        }
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "systemMessage": CLAUDE_NOTICE_DEGRADED_MESSAGE
            })),
        );
    }
    if state
        .reading
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "systemMessage": CLAUDE_NOTICE_DEGRADED_MESSAGE
            })),
        );
    }
    let strict = state.strict;
    let reading = state.reading.clone();
    let read_state = state.clone();
    let read = tokio::task::spawn_blocking(move || {
        let _permit = ClaudeNoticeReadPermit(reading);
        let unhealthy = || {
            read_state
                .audit
                .as_ref()
                .is_some_and(|audit| !audit.is_healthy() || !audit.path_matches_handle())
        };
        if unhealthy() {
            if let Some(audit) = read_state.audit.as_ref() {
                audit.mark_unhealthy();
            }
            return ClaudeNoticeRead::Degraded;
        }
        let read = if let Some(audit) = read_state.audit.as_ref() {
            let notice = audit.take_turn_notice();
            if notice.masked == 0 {
                ClaudeNoticeRead::Empty
            } else {
                ClaudeNoticeRead::Notice(ClaudeNotice {
                    masked: notice.masked,
                    detectors: notice.detectors,
                })
            }
        } else {
            take_claude_notice(&read_state)
        };
        if unhealthy() {
            if let Some(audit) = read_state.audit.as_ref() {
                audit.mark_unhealthy();
            }
            ClaudeNoticeRead::Degraded
        } else {
            read
        }
    })
    .await
    .unwrap_or(ClaudeNoticeRead::Degraded);
    let body = match read {
        ClaudeNoticeRead::Empty => serde_json::json!({}),
        ClaudeNoticeRead::Notice(notice) => {
            serde_json::json!({
                "systemMessage": format_claude_notice(&notice, strict)
            })
        }
        ClaudeNoticeRead::Degraded => serde_json::json!({
            "systemMessage": CLAUDE_NOTICE_DEGRADED_MESSAGE
        }),
    };
    (StatusCode::OK, Json(body))
}

fn constant_time_token_eq(provided: &[u8], expected: &[u8]) -> bool {
    let mut difference = provided.len() ^ expected.len();
    for (index, expected_byte) in expected.iter().enumerate() {
        difference |= usize::from(provided.get(index).copied().unwrap_or(0) ^ expected_byte);
    }
    difference == 0
}

async fn bind_guard_dashboard(preferred_port: u16) -> Option<(tokio::net::TcpListener, u16)> {
    let preferred_addr = format!("127.0.0.1:{preferred_port}");
    match tokio::net::TcpListener::bind(&preferred_addr).await {
        Ok(listener) => Some((listener, preferred_port)),
        Err(preferred_error) => match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => match listener.local_addr() {
                Ok(address) => {
                    eprintln!(
                        "promtect guard: dashboard port {preferred_port} is unavailable ({preferred_error}); using {} for this session.\n  Do not use an existing page on port {preferred_port}; it is not this guard session.",
                        address.port()
                    );
                    Some((listener, address.port()))
                }
                Err(error) => {
                    eprintln!(
                        "promtect guard: dashboard unavailable (could not read fallback address: {error})"
                    );
                    None
                }
            },
            Err(fallback_error) => {
                eprintln!(
                    "promtect guard: dashboard unavailable: {preferred_addr} is occupied ({preferred_error}) and fallback bind failed ({fallback_error})"
                );
                None
            }
        },
    }
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
    configure_guard_child_network_env(&mut cmd);
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

fn configure_guard_child_network_env(cmd: &mut tokio::process::Command) {
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
    configure_guard_child_network_env(cmd);
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
    configure_guard_child_network_env(&mut cmd);
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

async fn terminate_guarded_child(
    child: &mut tokio::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        if let Ok(raw) = i32::try_from(pid) {
            let pgrp = Pid::from_raw(raw);
            let _ = killpg(pgrp, Signal::SIGTERM);
            if let Ok(status) = tokio::time::timeout(Duration::from_millis(750), child.wait()).await
            {
                return status;
            }
            let _ = killpg(pgrp, Signal::SIGKILL);
        }
    }

    child.start_kill().ok();

    child.wait().await
}

#[cfg(unix)]
fn configure_guard_process_group(command: &mut tokio::process::Command) {
    use std::os::unix::process::CommandExt;

    // Give the guarded tool an owned process group. Background helpers inherit
    // this boundary even after their direct parent exits or they are reparented,
    // so cleanup never has to guess from a stale PPID snapshot.
    command.as_std_mut().process_group(0);
}

#[cfg(not(unix))]
fn configure_guard_process_group(_command: &mut tokio::process::Command) {}

#[cfg(unix)]
fn set_foreground_process_group(pgrp: nix::unistd::Pid) -> nix::Result<()> {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};

    // Restoring the parent's foreground group necessarily happens while the
    // parent is temporarily a background group. Block SIGTTOU only on this
    // calling thread around tcsetpgrp, then restore the exact prior mask.
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))?;
    let changed = nix::unistd::tcsetpgrp(std::io::stdin(), pgrp);
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
    changed.and(restored)
}

#[cfg(unix)]
fn set_guard_termios(termios: &nix::sys::termios::Termios) -> nix::Result<()> {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};

    // tcsetattr can also raise SIGTTOU when the guard is temporarily behind
    // the child process group. Block it only for this call, just like tcsetpgrp.
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))?;
    let changed = nix::sys::termios::tcsetattr(
        std::io::stdin(),
        nix::sys::termios::SetArg::TCSANOW,
        termios,
    );
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
    changed.and(restored)
}

#[cfg(unix)]
struct GuardTerminalLease {
    original_pgrp: nix::unistd::Pid,
    original_termios: nix::sys::termios::Termios,
}

#[cfg(unix)]
fn require_foreground_guard(
    foreground_pgrp: nix::unistd::Pid,
    guard_pgrp: nix::unistd::Pid,
) -> Result<(), String> {
    if foreground_pgrp == guard_pgrp {
        Ok(())
    } else {
        Err(
            "guard was started as a background job and cannot take terminal ownership; run it in the foreground"
                .to_string(),
        )
    }
}

#[cfg(unix)]
fn preflight_guard_terminal() -> Result<(), String> {
    use nix::errno::Errno;

    match nix::unistd::tcgetpgrp(std::io::stdin()) {
        Ok(foreground_pgrp) => require_foreground_guard(foreground_pgrp, nix::unistd::getpgrp()),
        Err(Errno::ENOTTY) => Ok(()),
        Err(error) => Err(format!("cannot inspect terminal job control ({error})")),
    }
}

#[cfg(not(unix))]
fn preflight_guard_terminal() -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
impl GuardTerminalLease {
    fn acquire(child_pid: u32) -> Result<Option<Self>, String> {
        use nix::errno::Errno;
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let original_pgrp = match nix::unistd::tcgetpgrp(std::io::stdin()) {
            Ok(pgrp) => pgrp,
            Err(Errno::ENOTTY) => return Ok(None),
            Err(error) => return Err(format!("cannot inspect terminal job control ({error})")),
        };
        require_foreground_guard(original_pgrp, nix::unistd::getpgrp())?;
        let child_pgrp = Pid::from_raw(i32::try_from(child_pid).map_err(|_| {
            "guarded tool process identifier exceeded the platform limit".to_string()
        })?);
        let original_termios = nix::sys::termios::tcgetattr(std::io::stdin())
            .map_err(|error| format!("cannot inspect terminal controls ({error})"))?;
        let mut guarded_termios = original_termios.clone();
        guarded_termios.control_chars[nix::sys::termios::SpecialCharacterIndices::VSUSP as usize] =
            nix::libc::_POSIX_VDISABLE;
        set_guard_termios(&guarded_termios)
            .map_err(|error| format!("cannot disable terminal suspension ({error})"))?;
        if let Err(error) = set_foreground_process_group(child_pgrp) {
            let _ = set_guard_termios(&original_termios);
            return Err(format!(
                "cannot give the terminal to the guarded tool ({error})"
            ));
        }
        // The child can attempt a terminal read in the short spawn-to-transfer
        // window and receive SIGTTIN. Resume the whole owned group after transfer.
        let _ = killpg(child_pgrp, Signal::SIGCONT);
        Ok(Some(Self {
            original_pgrp,
            original_termios,
        }))
    }
}

#[cfg(unix)]
impl Drop for GuardTerminalLease {
    fn drop(&mut self) {
        if let Err(error) = set_foreground_process_group(self.original_pgrp) {
            eprintln!(
                "promtect guard: warning: could not restore terminal foreground ownership ({error})"
            );
        }
        if let Err(error) = set_guard_termios(&self.original_termios) {
            eprintln!("promtect guard: warning: could not restore terminal controls ({error})");
        }
    }
}

#[cfg(not(unix))]
struct GuardTerminalLease;

#[cfg(not(unix))]
impl GuardTerminalLease {
    fn acquire(_child_pid: u32) -> Result<Option<Self>, String> {
        Ok(None)
    }
}

#[cfg(unix)]
fn process_group_exists(pgid: u32) -> bool {
    use nix::sys::signal::killpg;
    use nix::unistd::Pid;

    i32::try_from(pgid)
        .ok()
        .is_some_and(|raw| killpg(Pid::from_raw(raw), None).is_ok())
}

#[cfg(unix)]
async fn cleanup_guard_process_group(pgid: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let Ok(raw) = i32::try_from(pgid) else {
        return;
    };
    let pgrp = Pid::from_raw(raw);
    let _ = killpg(pgrp, Signal::SIGTERM);
    for _ in 0..20 {
        if !process_group_exists(pgid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = killpg(pgrp, Signal::SIGKILL);
    for _ in 0..20 {
        if !process_group_exists(pgid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    eprintln!("promtect guard: warning: the guarded process group did not disappear cleanly");
}

#[cfg(not(unix))]
async fn cleanup_guard_process_group(_pgid: u32) {}

async fn wait_for_guard_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn drain_guard_service(mut task: tokio::task::JoinHandle<()>, name: &str) {
    if tokio::time::timeout(Duration::from_secs(10), &mut task)
        .await
        .is_err()
    {
        eprintln!("promtect guard: warning: {name} did not drain within 10 seconds; forcing stop");
        task.abort();
        let _ = task.await;
    }
}

async fn shutdown_guard_services(
    shutdown: &tokio::sync::watch::Sender<bool>,
    signal_task: tokio::task::JoinHandle<()>,
    proxy_task: tokio::task::JoinHandle<()>,
    dashboard_task: Option<tokio::task::JoinHandle<()>>,
) {
    shutdown.send_replace(true);
    signal_task.abort();
    drain_guard_service(proxy_task, "proxy").await;
    if let Some(task) = dashboard_task {
        drain_guard_service(task, "dashboard").await;
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

    if let Err(error) = preflight_guard_terminal() {
        eprintln!("promtect guard: refusing to continue: {error}");
        return 1;
    }

    if plan.claude_fail_closed {
        if let Err(error) = verify_claude_unmanaged_profile(&plan.bin).await {
            eprintln!(
                "promtect guard: refusing to start Claude: {error}.\n  \
                 Use an unmanaged individual Claude Max profile; no provider request was sent."
            );
            return 1;
        }
        eprintln!("  Claude profile check: unmanaged individual Max profile verified");
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
    let claude_notice_token = plan
        .claude_fail_closed
        .then(|| uuid::Uuid::new_v4().simple().to_string());
    let claude_audit_scope = plan
        .claude_fail_closed
        .then(|| uuid::Uuid::new_v4().simple().to_string());
    let audit = claude_audit_scope.as_ref().map_or_else(
        || Audit::to_file(&audit_path),
        |scope| Audit::to_file_scoped(&audit_path, scope.clone()),
    );
    let audit = Arc::new(audit);
    if claude_notice_token.is_some() {
        let audit_to_prepare = audit.clone();
        match tokio::task::spawn_blocking(move || audit_to_prepare.prepare()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                eprintln!(
                    "promtect guard: refusing to start Claude because the audit path is unsafe or unavailable"
                );
                return 1;
            }
        }
    }
    let requests = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ctx = Ctx {
        upstream: plan.upstream.clone(),
        audit: audit.clone(),
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

    let (app, claude_notice_url) = if plan.claude_fail_closed {
        let token = claude_notice_token.expect("Claude notice token must exist");
        let notice_path = CLAUDE_NOTICE_ROUTE.replace("{token}", &token);
        let notice_url = format!("{base_url}{notice_path}");
        let notice_state = ClaudeNoticeState::new(
            std::path::PathBuf::from(&audit_path_for_dash),
            token,
            claude_audit_scope
                .as_deref()
                .expect("Claude audit scope must exist"),
            !plan.restore,
        )
        .with_audit(audit.clone());
        let notice_router = Router::new()
            .route(CLAUDE_NOTICE_ROUTE, post(claude_notice_hook))
            .with_state(notice_state);
        (notice_router.merge(proxy::app(ctx)), Some(notice_url))
    } else {
        (proxy::app(ctx), None)
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let signal_shutdown_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        crate::proxy::shutdown_signal().await;
        signal_shutdown_tx.send_replace(true);
    });
    let proxy_task = tokio::spawn(async move {
        // One guard-owned shutdown signal drains both services on normal tool
        // exit and on SIGINT/SIGTERM. This keeps partially restored responses
        // alive until Axum finishes their in-flight connection.
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_guard_shutdown(shutdown_rx))
            .await
        {
            eprintln!("promtect guard: proxy stopped serving ({e}) — tool is no longer masked");
        }
    });

    if let Some(auth) = codex_auth {
        if let Err(error) = verify_codex_config(&plan.bin, &base_url, auth).await {
            shutdown_guard_services(&shutdown_tx, signal_task, proxy_task, None).await;
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
    // If the preferred port is occupied, bind an ephemeral loopback port and print
    // the actual URL. Silently skipping here can leave a stale, unrelated dashboard
    // on the preferred port looking authoritative for this session.
    let mut dashboard_task = None;
    if let Ok(preferred_port) = proxy::parse_port(
        "PROMTECT_DASHBOARD_PORT",
        std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
        8799,
    ) && let Some((dash_listener, dash_port)) = bind_guard_dashboard(preferred_port).await
    {
        let dash_app = crate::dashboard::app(crate::dashboard::DashCtx {
            audit_path: Arc::new(audit_path_for_dash.as_str().into()),
            restore_enabled: plan.restore,
        });
        let dashboard_shutdown = shutdown_tx.subscribe();
        dashboard_task = Some(tokio::spawn(async move {
            // Drain in-flight dashboard requests on signal so metrics
            // pages aren't truncated when guard exits.
            if let Err(e) = axum::serve(dash_listener, dash_app)
                .with_graceful_shutdown(wait_for_guard_shutdown(dashboard_shutdown))
                .await
            {
                eprintln!("promtect guard: dashboard error: {e}");
            }
        }));
        eprintln!("  dashboard: http://127.0.0.1:{dash_port}");
    }

    // Inherit the parent environment, then override the tool's base-URL variable
    // to point at the proxy. Named Claude guard has already rejected environment
    // authentication overrides and uses the verified stored Max credential.
    // kill_on_drop is a direct-child fallback; explicit shutdown owns descendants.
    let claude_settings_file = if plan.claude_fail_closed {
        let Some(notice_url) = claude_notice_url.as_deref() else {
            shutdown_guard_services(&shutdown_tx, signal_task, proxy_task, dashboard_task).await;
            eprintln!("promtect guard: could not create Claude protection settings");
            return 1;
        };
        match ClaudeSettingsFile::create(&base_url, notice_url) {
            Ok(file) => Some(file),
            Err(_) => {
                shutdown_guard_services(&shutdown_tx, signal_task, proxy_task, dashboard_task)
                    .await;
                eprintln!("promtect guard: could not create owner-only Claude protection settings");
                return 1;
            }
        }
    } else {
        None
    };

    let mut cmd = tokio::process::Command::new(&plan.bin);
    if let Some(auth) = codex_auth {
        configure_codex_command(&mut cmd, auth);
        cmd.args(codex_config_args(&base_url, auth));
    }
    if plan.claude_fail_closed {
        // Claude honors HTTP_PROXY/HTTPS_PROXY even for loopback URLs. Remove
        // inherited proxy routes so the guard-owned base URL cannot be sent to a
        // different proxy before reaching Promtect.
        configure_guard_child_network_env(&mut cmd);
        cmd.env_remove("ANTHROPIC_UNIX_SOCKET")
            .env_remove("CLAUDE_CODE_USE_GATEWAY");
        for variable in CLAUDE_RUNTIME_OVERRIDE_VARS {
            cmd.env_remove(variable);
        }
        // Claude settings.json `env` values override the child process
        // environment. Inline settings win over user/project settings. The
        // preflight above separately rejects higher-precedence managed profiles.
        if let Some(settings_file) = claude_settings_file.as_ref() {
            cmd.arg("--settings").arg(settings_file.path());
        }
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
    configure_guard_process_group(&mut cmd);
    // Wrapping a full-screen TUI (Claude Code, Codex, …): stay quiet during the
    // session so per-request notifications do not corrupt the tool's terminal.
    // The audit log + dashboard still capture everything; the summary prints below.
    crate::proxy::set_quiet(true);
    let mut guarded_pgid = None;
    let mut terminal_lease = None;
    let mut launch_refused = false;
    let child_shutdown = shutdown_tx.subscribe();
    let status = match cmd.spawn() {
        Ok(mut child) => {
            if let Some(pid) = child.id() {
                guarded_pgid = Some(pid);
                match GuardTerminalLease::acquire(pid) {
                    Ok(lease) => terminal_lease = lease,
                    Err(error) => {
                        eprintln!("promtect guard: refusing to continue: {error}");
                        launch_refused = true;
                    }
                }
            }
            if launch_refused {
                terminate_guarded_child(&mut child).await
            } else {
                tokio::select! {
                    status = child.wait() => status,
                        _ = wait_for_guard_shutdown(child_shutdown) => {
                        eprintln!("promtect guard: shutdown requested; stopping the guarded tool");
                        terminate_guarded_child(&mut child).await
                    }
                }
            }
        }
        Err(error) => Err(error),
    };
    if let Some(pgid) = guarded_pgid {
        cleanup_guard_process_group(pgid).await;
    }
    drop(terminal_lease);
    shutdown_guard_services(&shutdown_tx, signal_task, proxy_task, dashboard_task).await;

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
            if plan.claude_fail_closed && !audit.is_healthy() {
                audit.mark_unhealthy();
                eprintln!(
                    "promtect guard: this session's protection metadata is incomplete because the audit log became unavailable; masking continued, but no zero-event claim is possible"
                );
            }
            print_guard_summary(&audit.session_stats());
        }
    }

    if launch_refused {
        return 1;
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
/// Counts come from this guard's process-local audit instance, so concurrent
/// guards sharing a JSONL path cannot contaminate one another's summaries.
fn print_guard_summary(stats: &crate::audit::AuditSessionStats) {
    let masked = stats.masked;
    let echoed = stats.output_secrets;

    if masked == 0 {
        eprintln!("promtect guard: this session recorded 0 masked sensitive values.");
    } else {
        let kinds = stats.by_detector.keys().cloned().collect::<Vec<_>>();
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

    #[cfg(unix)]
    #[test]
    fn background_guard_cannot_claim_foreground_terminal() {
        use nix::unistd::Pid;

        let error = require_foreground_guard(Pid::from_raw(1200), Pid::from_raw(1300))
            .expect_err("different process groups must be rejected");
        assert!(error.contains("background job"));
        assert!(require_foreground_guard(Pid::from_raw(1200), Pid::from_raw(1200)).is_ok());
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
        assert!(p.claude_fail_closed);
        assert!(!p.codex_fail_closed);
    }

    #[test]
    fn claude_private_settings_force_guard_owned_routing() {
        let settings_json = claude_settings_json(
            "http://127.0.0.1:12345",
            "http://127.0.0.1:12345/_promtect/hooks/test-token",
        );
        let settings: serde_json::Value =
            serde_json::from_str(&settings_json).expect("Claude settings must be JSON");
        assert_eq!(
            settings["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:12345"
        );
        for selector in CLAUDE_PROVIDER_SELECTORS {
            assert_eq!(settings["env"][*selector], "0");
        }
        for variable in super::CLAUDE_AUTH_OVERRIDE_VARS
            .iter()
            .chain(super::CLAUDE_RUNTIME_OVERRIDE_VARS)
        {
            assert_eq!(settings["env"][*variable], "");
        }
        for proxy in [
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
            assert_eq!(settings["env"][proxy], "");
        }
        assert_eq!(settings["env"]["NO_PROXY"], "127.0.0.1,localhost");
        assert_eq!(settings["env"]["no_proxy"], "127.0.0.1,localhost");
        assert_eq!(settings["disableAllHooks"], false);
        assert_eq!(settings["hooks"]["Stop"][0]["hooks"][0]["type"], "http");
        assert_eq!(
            settings["hooks"]["Stop"][0]["hooks"][0]["url"],
            "http://127.0.0.1:12345/_promtect/hooks/test-token"
        );
        assert!(
            !settings_json.contains("additionalContext") && !settings_json.contains("prompt"),
            "the user-only notice must never become model context or a prompt"
        );
    }

    #[test]
    fn claude_settings_file_is_owner_only_and_removed_on_drop() {
        let settings = ClaudeSettingsFile::create(
            "http://127.0.0.1:12345",
            "http://127.0.0.1:12345/_promtect/hooks/test-token",
        )
        .expect("create private Claude settings");
        let directory = settings.directory.clone();
        let path = settings.path().to_path_buf();
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory)
                    .expect("settings directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("settings file metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(settings);
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn claude_rejects_user_settings_overrides() {
        for args in [
            vec!["claude", "--settings", "/tmp/settings.json"],
            vec![
                "claude",
                "--settings={\"env\":{\"ANTHROPIC_BASE_URL\":\"https://example.test\"}}",
            ],
            vec!["claude", "--", "--settings", "/tmp/settings.json"],
            vec!["claude", "--managed-settings", "{}"],
            vec!["claude", "--managed-settings={}"],
        ] {
            let error = plan(&args).unwrap_err();
            assert!(
                error.contains("conflicts with Promtect's protected routing"),
                "expected fail-closed settings error for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn claude_rejects_non_session_root_commands() {
        for command in super::CLAUDE_UNSUPPORTED_ROOT_COMMANDS {
            let error = plan(&["claude", command]).expect_err("root command must fail closed");
            assert!(error.contains("protected routing or automatic notice"));
        }

        let error = plan(&["claude", "--name", "demo", "doctor"])
            .expect_err("a root command after an option value must fail closed");
        assert!(error.contains("protected routing or automatic notice"));
    }

    #[test]
    fn claude_option_values_are_not_mistaken_for_root_commands() {
        for args in [
            &["claude", "--name", "doctor"][..],
            &["claude", "-n", "doctor"][..],
            &["claude", "--name=doctor"][..],
            &["claude", "--model", "doctor"][..],
            &["claude", "--resume", "doctor"][..],
        ] {
            plan(args).unwrap_or_else(|error| {
                panic!("Claude option/prompt value was rejected for {args:?}: {error}")
            });
        }
    }

    #[test]
    fn claude_rejects_modes_that_disable_the_automatic_notice() {
        for arg in [
            "--safe-mode",
            "--safe-mode=true",
            "--bare",
            "--background",
            "--bg",
            "--remote-control",
            "--remote-control=demo",
            "--tmux",
            "--tmux=classic",
            "--worktree",
            "--worktree=demo",
            "-w",
            "-wdemo",
        ] {
            let error = plan(&["claude", arg]).unwrap_err();
            assert!(
                error.contains("automatic notice"),
                "expected notice conflict for {arg:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn claude_notice_is_value_free_and_consumed_once() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", true);
        let other_guard =
            crate::audit::Audit::to_file_scoped(path.clone(), "other-guard".to_string());
        other_guard.record_request("request-other", 9, &["jwt"], 100, 120);
        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.record_request(
            "request-1",
            4,
            &["aws_key", "anthropic_key", "github_token", "stripe_key"],
            100,
            120,
        );

        let super::ClaudeNoticeRead::Notice(notice) = super::take_claude_notice(&state) else {
            panic!("expected pending notice");
        };
        assert_eq!(notice.masked, 4);
        assert_eq!(
            notice.detectors,
            BTreeSet::from([
                "anthropic_key".to_string(),
                "aws_key".to_string(),
                "github_token".to_string(),
                "stripe_key".to_string(),
            ])
        );
        let message = super::format_claude_notice(&notice, true);
        assert!(message.contains("masked 4 sensitive values"));
        assert!(message.contains("AWS access key (`aws_key`)"));
        assert!(message.contains("Strict mode: plaintext restoration off."));
        assert!(!message.contains("AKIA"));
        assert!(
            super::take_claude_notice(&state) == super::ClaudeNoticeRead::Empty,
            "a Stop hook must consume each notice exactly once"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_token_comparison_checks_complete_value() {
        assert!(super::constant_time_token_eq(
            b"fixed-hook-token",
            b"fixed-hook-token"
        ));
        for candidate in [
            b"fixed-hook-toke".as_slice(),
            b"fixed-hook-token-extra".as_slice(),
            b"xixed-hook-token".as_slice(),
            b"fixed-hook-tokex".as_slice(),
        ] {
            assert!(!super::constant_time_token_eq(
                candidate,
                b"fixed-hook-token"
            ));
        }
    }

    #[test]
    fn claude_notice_ignores_blocked_or_failed_requests() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-failed-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.record_request("request-blocked", 1, &["aws_key"], 100, 120);
        audit.record(
            "request_blocked",
            "residual_secret",
            "«residual-secret»",
            "request-blocked",
        );
        audit.record_request("request-failed", 1, &["github_token"], 100, 120);
        audit.record(
            "request_failed",
            "upstream",
            "«upstream-request-failed»",
            "request-failed",
        );
        audit.record_request("request-interrupted", 1, &["stripe_key"], 100, 120);
        audit.record(
            "stream_interrupted",
            "upstream",
            "«upstream-stream-interrupted»",
            "request-interrupted",
        );

        assert_eq!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Empty
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_degrades_on_malformed_or_invalid_current_records_then_recovers() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-corrupt-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let invalid_lines = [
            "{not-json}".to_string(),
            serde_json::json!({"request_id":"test-token:missing-action"}).to_string(),
            serde_json::json!({"action":"request","masked":1}).to_string(),
            serde_json::json!({
                "action":"request",
                "request_id":"test-token:wrong-masked",
                "masked":"1",
                "blocked":false,
                "detectors":["aws_key"]
            })
            .to_string(),
            serde_json::json!({
                "action":"request",
                "request_id":"test-token:zero-invalid-detector",
                "masked":0,
                "blocked":false,
                "detectors":[42]
            })
            .to_string(),
            serde_json::json!({
                "action":"request",
                "request_id":"test-token:blocked-invalid-detector",
                "masked":1,
                "blocked":true,
                "detectors":[42]
            })
            .to_string(),
        ];

        for (index, invalid) in invalid_lines.into_iter().enumerate() {
            let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
            audit.record_request(&format!("valid-before-{index}"), 1, &["aws_key"], 100, 90);
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open audit corruption fixture");
            writeln!(file, "{invalid}").expect("append corrupt audit record");
            drop(file);

            assert_eq!(
                super::take_claude_notice(&state),
                super::ClaudeNoticeRead::Degraded
            );
            let recovery =
                crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
            recovery.record_request(&format!("recovery-{index}"), 1, &["github_token"], 100, 90);
            let super::ClaudeNoticeRead::Notice(notice) = super::take_claude_notice(&state) else {
                panic!("expected notice recovery after corruption case {index}");
            };
            assert_eq!(notice.masked, 1);
            assert_eq!(
                notice.detectors,
                BTreeSet::from(["github_token".to_string()])
            );
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_starts_after_repairing_a_truncated_prior_tail() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-truncated-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, br#"{"incomplete":true"#).expect("write truncated audit tail");
        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.prepare().expect("prepare truncated audit tail");
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        audit.record_request("request-new", 1, &["aws_key"], 100, 120);

        let super::ClaudeNoticeRead::Notice(notice) = super::take_claude_notice(&state) else {
            panic!("expected new repaired-session notice");
        };
        assert_eq!(notice.masked, 1);
        assert_eq!(notice.detectors, BTreeSet::from(["aws_key".to_string()]));
        std::fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn claude_notice_survives_same_inode_truncate_and_regrow() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-regrow-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let historical = format!(
            "{}\n",
            serde_json::json!({
                "action": "request",
                "request_id": "historical:request",
                "masked": 0,
                "blocked": false,
                "detectors": []
            })
        )
        .repeat(64);
        std::fs::write(&path, historical).expect("write historical audit");
        let audit = Arc::new(crate::audit::Audit::to_file_scoped(
            path.clone(),
            "test-token".to_string(),
        ));
        audit.prepare().expect("prepare audit fixture");
        let original_len = std::fs::metadata(&path).expect("audit metadata").len();
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false)
                .with_audit(audit.clone());

        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("truncate same audit inode");
        audit.record_request("request-new", 1, &["aws_key"], 100, 120);
        let regrown_len = std::fs::metadata(&path).expect("regrown metadata").len();
        assert!(regrown_len < original_len);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open audit padding");
        file.write_all(&vec![b' '; (original_len - regrown_len) as usize])
            .expect("regrow audit to old cursor");
        drop(file);
        assert_eq!(
            std::fs::metadata(&path).expect("audit metadata").len(),
            original_len
        );

        let (status, Json(body)) =
            super::claude_notice_hook(State(state), Path("hook-token".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        let message = body["systemMessage"]
            .as_str()
            .expect("truncate-regrow turn must still produce a notice");
        assert!(message.contains("masked 1 sensitive value"));
        assert!(message.contains("AWS access key (`aws_key`)"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_large_delta_degrades_then_recovers() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-large-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let mut oversized = vec![b'x'; (super::CLAUDE_NOTICE_MAX_DELTA_BYTES + 1) as usize];
        *oversized.last_mut().expect("non-empty oversized delta") = b'\n';
        std::fs::write(&path, oversized).expect("write oversized audit delta");

        assert_eq!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Degraded
        );
        assert_eq!(
            *state.cursor.lock().expect("notice cursor"),
            super::CLAUDE_NOTICE_MAX_DELTA_BYTES + 1
        );

        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.record_request("request-recovery", 1, &["aws_key"], 100, 120);
        let super::ClaudeNoticeRead::Notice(notice) = super::take_claude_notice(&state) else {
            panic!("expected notice recovery after capped delta");
        };
        assert_eq!(notice.masked, 1);
        assert_eq!(notice.detectors, BTreeSet::from(["aws_key".to_string()]));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_oversized_record_degrades_then_recovers() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-record-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let mut record = vec![b'x'; (super::CLAUDE_NOTICE_MAX_RECORD_BYTES + 1) as usize];
        record.push(b'\n');
        std::fs::write(&path, record).expect("write oversized audit record");

        assert_eq!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Degraded
        );
        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.record_request("request-recovery", 1, &["github_token"], 100, 120);
        assert!(matches!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Notice(_)
        ));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_record_limit_degrades_then_recovers() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-records-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let record = serde_json::json!({
            "action": "ignored",
            "request_id": "different-session:request"
        })
        .to_string()
            + "\n";
        let records = record.repeat(super::CLAUDE_NOTICE_MAX_RECORDS + 1);
        std::fs::write(&path, records).expect("write excessive audit records");

        assert_eq!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Degraded
        );
        let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
        audit.record_request("request-recovery", 1, &["stripe_key"], 100, 120);
        assert!(matches!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Notice(_)
        ));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_copy_truncate_degrades_instead_of_claiming_empty() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-copy-truncate-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            b"{\"action\":\"ignored\",\"request_id\":\"prior:request\"}\n",
        )
        .expect("seed audit");
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        std::fs::write(&path, b"").expect("copy truncate audit");

        assert_eq!(
            super::take_claude_notice(&state),
            super::ClaudeNoticeRead::Degraded
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_notice_field_bounds_degrade_value_free_then_recover() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-fields-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let too_many_detectors = (0..=super::CLAUDE_NOTICE_MAX_DETECTORS)
            .map(|index| format!("detector_{index}"))
            .collect::<Vec<_>>();
        let invalid_records = [
            serde_json::json!({
                "action": "request",
                "request_id": format!(
                    "test-token:{}",
                    "a".repeat(super::CLAUDE_NOTICE_MAX_REQUEST_ID_BYTES)
                ),
                "masked": 1,
                "detectors": ["aws_key"],
                "blocked": false
            }),
            serde_json::json!({
                "action": "request",
                "request_id": "test-token:invalid-character",
                "masked": 1,
                "detectors": ["aws-key"],
                "blocked": false
            }),
            serde_json::json!({
                "action": "request",
                "request_id": "test-token:oversized-detector",
                "masked": 1,
                "detectors": ["a".repeat(super::CLAUDE_NOTICE_MAX_DETECTOR_BYTES + 1)],
                "blocked": false
            }),
            serde_json::json!({
                "action": "request",
                "request_id": "test-token:too-many-detectors",
                "masked": 1,
                "detectors": too_many_detectors,
                "blocked": false
            }),
            serde_json::json!({
                "action": "request",
                "request_id": "test-token:non-string-detector",
                "masked": 1,
                "detectors": [42],
                "blocked": false
            }),
        ];

        for (index, record) in invalid_records.into_iter().enumerate() {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open hostile audit fixture");
            writeln!(file, "{record}").expect("append hostile audit fixture");
            drop(file);
            assert_eq!(
                super::take_claude_notice(&state),
                super::ClaudeNoticeRead::Degraded
            );

            let audit = crate::audit::Audit::to_file_scoped(path.clone(), "test-token".to_string());
            audit.record_request(&format!("recovery-{index}"), 1, &["aws_key"], 100, 120);
            let super::ClaudeNoticeRead::Notice(notice) = super::take_claude_notice(&state) else {
                panic!("expected recovery after hostile audit field {index}");
            };
            assert_eq!(notice.masked, 1);
            assert_eq!(notice.detectors, BTreeSet::from(["aws_key".to_string()]));
        }
        std::fs::remove_file(path).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn claude_notice_hook_allows_only_one_blocking_reader() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-notice-responsive-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let state =
            super::ClaudeNoticeState::new(&path, "hook-token".to_string(), "test-token", false);
        let cursor = state.cursor.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = cursor.lock().expect("hold notice cursor");
            locked_tx.send(()).expect("signal held cursor");
            release_rx.recv().expect("release notice cursor");
        });
        locked_rx.recv().expect("wait for held cursor");

        let hook = tokio::spawn(super::claude_notice_hook(
            State(state.clone()),
            Path("hook-token".to_string()),
        ));
        while !state.reading.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        let (status, Json(body)) =
            super::claude_notice_hook(State(state), Path("hook-token".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["systemMessage"], super::CLAUDE_NOTICE_DEGRADED_MESSAGE);

        release_tx.send(()).expect("release notice cursor");
        holder.join().expect("release notice cursor");
        let (status, _) = hook.await.expect("notice hook task");
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn claude_rejects_any_nonempty_managed_settings_source() {
        let path = std::env::temp_dir().join(format!(
            "promtect-claude-managed-settings-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, r#"{"env":{"EDITOR":"vim"}}"#)
            .expect("write unrelated managed settings fixture");
        let error = super::validate_claude_unmanaged_files(std::slice::from_ref(&path))
            .expect_err("any active managed tier must fail closed");
        assert!(error.contains("endpoint-managed Claude settings are active"));
        assert!(!error.contains("EDITOR") && !error.contains("vim"));

        std::fs::write(&path, "{}").expect("replace empty managed settings fixture");
        super::validate_claude_unmanaged_files(std::slice::from_ref(&path))
            .expect("an empty managed file does not activate the managed tier");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn claude_discovers_managed_settings_drop_ins() {
        let root = std::env::temp_dir().join(format!(
            "promtect-claude-managed-root-{}",
            uuid::Uuid::new_v4()
        ));
        let drop_ins = root.join("managed-settings.d");
        std::fs::create_dir_all(&drop_ins).expect("create managed drop-in fixture");
        std::fs::write(
            drop_ins.join("10-policy.json"),
            r#"{"env":{"EDITOR":"vim"}}"#,
        )
        .expect("write managed drop-in fixture");
        std::fs::write(
            drop_ins.join(".ignored.json"),
            r#"{"env":{"EDITOR":"vim"}}"#,
        )
        .expect("write hidden managed fixture");

        let paths = super::claude_managed_settings_paths(&root).expect("discover drop-ins");
        assert!(paths.iter().any(|path| path.ends_with("10-policy.json")));
        assert!(!paths.iter().any(|path| path.ends_with(".ignored.json")));
        super::validate_claude_unmanaged_files(&paths)
            .expect_err("drop-in-only managed policy must fail closed");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn claude_rejects_nonempty_remote_settings_without_exposing_them() {
        let root = std::env::temp_dir().join(format!(
            "promtect-claude-remote-settings-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create remote-settings fixture");
        let canary = "synthetic-user@example.invalid";
        std::fs::write(
            root.join("remote-settings.json"),
            format!(r#"{{"env":{{"SYNTHETIC_EMAIL":"{canary}"}}}}"#),
        )
        .expect("write remote-settings fixture");

        let error = super::validate_claude_remote_settings(&root)
            .expect_err("remote managed settings must fail closed");
        assert!(error.contains("server-managed Claude settings are active"));
        assert!(!error.contains(canary));

        std::fs::write(root.join("remote-settings.json"), "{}")
            .expect("replace empty remote-settings fixture");
        super::validate_claude_remote_settings(&root)
            .expect("empty remote settings must not activate managed policy");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn claude_auth_gate_allows_only_unmanaged_first_party_max() {
        let max = br#"{
            "loggedIn": true,
            "authMethod": "claude.ai",
            "subscriptionType": "max",
            "apiProvider": "firstParty",
            "organizationType": null
        }"#;
        super::validate_claude_auth_status(max).expect("individual Max must be supported");
        let current_max = br#"{
            "loggedIn": true,
            "authMethod": "claude.ai",
            "subscriptionType": "max",
            "apiProvider": "firstParty"
        }"#;
        super::validate_claude_auth_status(current_max)
            .expect("Claude 2.1.209 individual Max omits organizationType");

        for unsupported in [
            br#"{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"team","apiProvider":"firstParty"}"#.as_slice(),
            br#"{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"enterprise","apiProvider":"firstParty"}"#.as_slice(),
            br#"{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","apiProvider":"firstParty","organizationType":"team"}"#.as_slice(),
            br#"{"loggedIn":true,"authMethod":"api_key","subscriptionType":null,"apiProvider":"firstParty"}"#.as_slice(),
            br#"{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","apiProvider":"gateway"}"#.as_slice(),
            br#"{"loggedIn":false,"authMethod":"none","apiProvider":"firstParty"}"#.as_slice(),
            b"not-json".as_slice(),
        ] {
            super::validate_claude_auth_status(unsupported)
                .expect_err("unsupported Claude profile must fail closed");
        }
    }

    #[test]
    fn claude_version_gate_is_exact_and_value_free() {
        super::validate_claude_version(super::CLAUDE_SUPPORTED_VERSION.as_bytes())
            .expect("pinned Claude version must pass");
        let error = super::validate_claude_version(b"2.1.208 (Claude Code)")
            .expect_err("unreviewed Claude version must fail closed");
        assert!(error.contains(super::CLAUDE_SUPPORTED_VERSION));
        assert!(!error.contains("2.1.208"));
    }

    #[test]
    fn claude_auth_environment_overrides_fail_closed() {
        for expected in super::CLAUDE_AUTH_OVERRIDE_VARS {
            assert_eq!(
                super::first_claude_auth_override(|variable| variable == *expected),
                Some(*expected)
            );
        }
        assert_eq!(super::first_claude_auth_override(|_| false), None);
    }

    #[test]
    fn claude_runtime_environment_overrides_fail_closed() {
        for expected in super::CLAUDE_RUNTIME_OVERRIDE_VARS {
            assert_eq!(
                super::first_claude_runtime_override(|variable| variable == *expected),
                Some(*expected)
            );
        }
        assert_eq!(super::first_claude_runtime_override(|_| false), None);
    }

    #[test]
    fn claude_auth_errors_are_value_free() {
        let canary = "synthetic-user@example.invalid";
        let status = format!(
            r#"{{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"team","apiProvider":"firstParty","email":"{canary}"}}"#
        );
        let error = super::validate_claude_auth_status(status.as_bytes())
            .expect_err("Team profile must fail closed");
        assert!(!error.contains(canary));
    }

    #[tokio::test]
    async fn dashboard_uses_a_visible_fallback_when_default_port_is_occupied() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind occupied dashboard fixture");
        let preferred_port = occupied
            .local_addr()
            .expect("read occupied dashboard fixture address")
            .port();

        let (fallback, fallback_port) = super::bind_guard_dashboard(preferred_port)
            .await
            .expect("dashboard fallback listener");

        assert_ne!(fallback_port, preferred_port);
        assert_eq!(
            fallback
                .local_addr()
                .expect("read dashboard fallback address")
                .port(),
            fallback_port
        );
    }

    #[test]
    fn codex_default_wiring() {
        let p = plan(&["codex"]).unwrap();
        assert_eq!(p.bin, "codex");
        assert_eq!(p.base_var, "OPENAI_BASE_URL");
        assert_eq!(p.base_path, "/v1");
        assert_eq!(p.upstream, "https://api.openai.com");
        assert!(p.codex_fail_closed);
        assert!(!p.claude_fail_closed);
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
