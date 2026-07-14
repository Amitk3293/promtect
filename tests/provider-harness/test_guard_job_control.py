#!/usr/bin/env python3
"""Real-PTY regressions for guard terminal ownership and cleanup."""

import errno
import os
import pty
import select
import signal
import sys
import termios
import time
import uuid


DEADLINE_SECONDS = 8
UPSTREAM = "http://mock-provider:9000"
FIXTURE = r"""
import os
import sys
print(f"READY pid={os.getpid()} pgid={os.getpgrp()}", flush=True)
for line in sys.stdin:
    command = line.replace(chr(26), "").strip()
    if command == "PING":
        print("ALIVE", flush=True)
    elif command == "EXIT":
        break
"""


def guard_argv(fixture: str) -> list[str]:
    return [
        "promtect",
        "guard",
        "--exec",
        "python3",
        "--base-var",
        "PROMTECT_TEST_BASE",
        "--upstream",
        UPSTREAM,
        "--",
        "-u",
        "-c",
        fixture,
    ]


def read_available(fd: int, output: bytearray, timeout: float = 0.05) -> bool:
    if not select.select([fd], [], [], timeout)[0]:
        return False
    try:
        output.extend(os.read(fd, 65536))
    except OSError as error:
        if error.errno != errno.EIO:
            raise
        return False
    return True


def wait_for_text(fd: int, output: bytearray, needle: bytes, deadline: float) -> None:
    while needle not in output:
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {needle!r}: {output[-2000:]!r}")
        read_available(fd, output)


def wait_for_child(pid: int, fd: int, output: bytearray, deadline: float) -> int:
    while time.monotonic() < deadline:
        read_available(fd, output)
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            while read_available(fd, output, 0):
                pass
            return os.waitstatus_to_exitcode(status)
    raise AssertionError(f"guard did not exit: {output[-2000:]!r}")


def proc_state(pid: int) -> str | None:
    try:
        stat = open(f"/proc/{pid}/stat", encoding="utf-8").read()
    except FileNotFoundError:
        return None
    close = stat.rfind(")")
    return stat[close + 2 :].split()[0]


def kill_session(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def test_foreground_ctrl_z() -> None:
    pid, master = pty.fork()
    if pid == 0:
        os.execvp("promtect", guard_argv(FIXTURE))

    output = bytearray()
    deadline = time.monotonic() + DEADLINE_SECONDS
    original_vsusp = termios.tcgetattr(master)[6][termios.VSUSP]
    try:
        wait_for_text(master, output, b"READY pid=", deadline)
        ready = next(line for line in output.decode(errors="replace").splitlines() if "READY pid=" in line)
        tool_pid = int(ready.split("READY pid=", 1)[1].split()[0])

        os.write(master, b"\x1a")
        for _ in range(20):
            state = proc_state(tool_pid)
            assert state not in {"T", "t"}, f"guarded tool was suspended: state={state}"
            time.sleep(0.025)

        os.write(master, b"PING\n")
        wait_for_text(master, output, b"ALIVE", deadline)
        os.write(master, b"EXIT\n")
        exit_code = wait_for_child(pid, master, output, deadline)
        assert exit_code == 0, output.decode(errors="replace")
        assert termios.tcgetattr(master)[6][termios.VSUSP] == original_vsusp
        try:
            os.killpg(tool_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(f"guarded process group {tool_pid} survived exit")
    except BaseException:
        kill_session(pid)
        raise
    finally:
        os.close(master)


def test_background_refusal() -> None:
    marker = f"/tmp/promtect-background-{uuid.uuid4().hex}"
    background_fixture = f"import pathlib; pathlib.Path({marker!r}).write_text('ran')"
    pid, master = pty.fork()
    if pid == 0:
        controller_pgrp = os.getpgrp()
        guard_pid = os.fork()
        if guard_pid == 0:
            os.setpgid(0, 0)
            os.execvp("promtect", guard_argv(background_fixture))
        _, status = os.waitpid(guard_pid, 0)
        foreground_preserved = os.tcgetpgrp(0) == controller_pgrp
        print(f"BACKGROUND_STATUS={os.waitstatus_to_exitcode(status)}", flush=True)
        print(f"BACKGROUND_FOREGROUND_PRESERVED={foreground_preserved}", flush=True)
        os._exit(0)

    output = bytearray()
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        exit_code = wait_for_child(pid, master, output, deadline)
        text = output.decode(errors="replace")
        assert exit_code == 0, text
        assert "BACKGROUND_STATUS=1" in text, text
        assert "BACKGROUND_FOREGROUND_PRESERVED=True" in text, text
        assert "started as a background job" in text, text
        assert not os.path.exists(marker), "background guard spawned the tool before refusal"
    except BaseException:
        kill_session(pid)
        raise
    finally:
        try:
            os.unlink(marker)
        except FileNotFoundError:
            pass
        os.close(master)


if __name__ == "__main__":
    test_foreground_ctrl_z()
    print("PASS guard job control: Ctrl-Z disabled, terminal restored, process group cleaned")
    test_background_refusal()
    print("PASS guard job control: background launch refused before tool execution")
