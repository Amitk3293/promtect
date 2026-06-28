// `promtect --version` / `-V` / `version` must print the version and exit,
// NOT start the proxy. Regression guard for the bug where these spellings fell
// through to `run_proxy` and bound the listener instead of reporting a version.

use std::process::{Command, Stdio};

/// Run the built binary with a single argument to completion and capture output.
/// `.output()` waits for exit, so a regression that starts the proxy would either
/// hang here (caught by the test timeout) or print the listening banner (asserted
/// against below).
fn run(arg: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_promtect"))
        .arg(arg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run promtect")
}

fn assert_reports_version(arg: &str) {
    let out = run(arg);
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");

    assert!(out.status.success(), "`promtect {arg}` should exit 0");
    assert_eq!(
        stdout.trim_end(),
        concat!("promtect ", env!("CARGO_PKG_VERSION")),
        "`promtect {arg}` should print the crate version",
    );
    assert!(
        !stdout.contains("listening"),
        "`promtect {arg}` must NOT start the proxy: {stdout}",
    );
}

#[test]
fn version_long_flag_reports_version_without_starting_proxy() {
    assert_reports_version("--version");
}

#[test]
fn version_short_flag_reports_version_without_starting_proxy() {
    assert_reports_version("-V");
}

#[test]
fn version_subcommand_reports_version_without_starting_proxy() {
    assert_reports_version("version");
}

#[test]
fn help_flag_exits_without_starting_proxy() {
    let out = run("--help");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");

    assert!(out.status.success(), "`promtect --help` should exit 0");
    assert!(
        !stdout.contains("listening"),
        "`promtect --help` must NOT start the proxy: {stdout}",
    );
}
