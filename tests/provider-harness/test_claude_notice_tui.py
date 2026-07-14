#!/usr/bin/env python3
"""Exact-version Claude TUI rehearsal for Promtect's user-only Stop notice."""

import errno
import fcntl
import os
import pty
import re
import signal
import struct
import termios
import time


DEADLINE_SECONDS = 45
PROMPT = """Treat these as fixed synthetic canaries and reply with a short acknowledgement:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ANTHROPIC_API_KEY=sk-ant-demo0000000000000000000000000000
GITHUB_TOKEN=ghp_000000000000000000000000000000000000
STRIPE_SECRET_KEY=sk_test_000000000000000000000000"""
NOTICE = b"Promtect prevented an exposure"
INPUT_PROMPT = "❯".encode()
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def visible_text(output: bytearray) -> bytes:
    return ANSI.sub(b"", bytes(output)).replace(b"\r", b"")


def read_available(fd: int, output: bytearray, timeout: float = 0.1) -> bool:
    import select

    if not select.select([fd], [], [], timeout)[0]:
        return False
    try:
        output.extend(os.read(fd, 65536))
    except OSError as error:
        if error.errno != errno.EIO:
            raise
        return False
    return True


def wait_for_notice(pid: int, master: int, output: bytearray) -> None:
    deadline = time.monotonic() + DEADLINE_SECONDS
    while time.monotonic() < deadline:
        read_available(master, output)
        if NOTICE in visible_text(output):
            return
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            raise AssertionError(
                f"Claude TUI exited before the notice (status={os.waitstatus_to_exitcode(status)}): "
                f"{visible_text(output)[-4000:]!r}"
            )
    raise AssertionError(f"timed out waiting for visible notice: {visible_text(output)[-4000:]!r}")


def stop_session(pid: int, master: int, output: bytearray) -> int:
    os.write(master, b"/exit\r")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        read_available(master, output)
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return os.waitstatus_to_exitcode(status)
    os.kill(pid, signal.SIGINT)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        read_available(master, output)
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return os.waitstatus_to_exitcode(status)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def main() -> None:
    pid, master = pty.fork()
    if pid == 0:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": "/tmp/claude-guard",
                "CLAUDE_CONFIG_DIR": "/tmp/claude-guard",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_UPDATES": "1",
                "PROMTECT_AUDIT": "/tmp/claude-tui-audit.jsonl",
                "PROMTECT_DASHBOARD_PORT": "18996",
            }
        )
        os.execvpe(
            "promtect",
            [
                "promtect",
                "guard",
                "claude",
                "--upstream",
                "http://mock-provider:9000/guard-claude",
            ],
            environment,
        )

    output = bytearray()
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        startup_deadline = time.monotonic() + 20
        while time.monotonic() < startup_deadline:
            read_available(master, output)
            text = visible_text(output)
            if b"Claude Code" in text and INPUT_PROMPT in text:
                break
        else:
            raise AssertionError(
                f"Claude TUI did not reach its input prompt: {visible_text(output)[-4000:]!r}"
            )
        os.write(master, PROMPT.encode() + b"\r")
        wait_for_notice(pid, master, output)
        text = visible_text(output)
        assert text.count(NOTICE) == 1, text[-4000:]
        exit_code = stop_session(pid, master, output)
        if exit_code not in {0, 130}:
            raise AssertionError(
                f"Claude TUI rehearsal exited {exit_code}: {visible_text(output)[-4000:]!r}"
            )
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(master)

    print("PASS Claude guard: exact 2.1.209 interactive TUI rendered one user-only Promtect notice")


if __name__ == "__main__":
    main()
