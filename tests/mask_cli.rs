// `promtect mask` reads stdin, replaces detected secrets with sentinels, and
// writes the masked text to stdout. This drives the real built binary end to end.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn mask_cli_masks_stdin_secret_and_preserves_surrounding_text() {
    let bin = env!("CARGO_BIN_EXE_promtect");
    let mut child = Command::new(bin)
        .arg("mask")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn promtect mask");

    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"deploy with AKIAIOSFODNN7EXAMPLE here")
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "mask should exit 0");
    let masked = String::from_utf8(out.stdout).expect("utf8 stdout");

    assert!(
        !masked.contains("AKIAIOSFODNN7EXAMPLE"),
        "the real key must not survive masking: {masked}"
    );
    assert!(
        masked.contains("«promtect:aws_key:"),
        "a sentinel should replace the key: {masked}"
    );
    assert!(
        masked.contains("deploy with ") && masked.contains(" here"),
        "non-secret text must be preserved verbatim: {masked}"
    );
}
