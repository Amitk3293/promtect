#[cfg(unix)]
#[test]
fn guard_exec_accepts_closed_stdin() {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut command = Command::new(env!("CARGO_BIN_EXE_promtect"));
    command.args([
        "guard",
        "--exec",
        "/bin/true",
        "--base-var",
        "PROMTECT_TEST_BASE_URL",
        "--",
        "--version",
    ]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if nix::libc::close(nix::libc::STDIN_FILENO) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = command.output().expect("run guard with closed stdin");
    assert!(
        output.status.success(),
        "guard rejected closed stdin: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
