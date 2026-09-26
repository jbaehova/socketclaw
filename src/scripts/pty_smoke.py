"""Run the installed or frozen CLI in a real POSIX PTY with private localhost data."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time
import tomllib
from pathlib import Path


def _resize(fd: int, columns: int, rows: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def _read(fd: int, duration: float) -> bytes:
    end = time.monotonic() + duration
    output = bytearray()
    while time.monotonic() < end:
        readable, _, _ = select.select([fd], [], [], max(0.0, min(0.1, end - time.monotonic())))
        if readable:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            output.extend(data)
            if b"\x1b[6n" in data:
                os.write(fd, b"\x1b[1;1R")
    return bytes(output)


def _plain(output: bytes | bytearray) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output.decode(errors="replace"))


def _complete_onboarding(master: int, output: bytearray) -> None:
    def press(keys: bytes, expected: str | None = None) -> bytes:
        os.write(master, keys)
        frame = _read(master, 0.5)
        deadline = time.monotonic() + 5
        while expected and expected not in _plain(frame) and time.monotonic() < deadline:
            frame += _read(master, 0.25)
        output.extend(frame)
        if expected and expected not in _plain(frame):
            raise RuntimeError(f"Onboarding did not reach {expected!r}: {_plain(frame)[-3000:]}")
        return frame

    press(b"\r", "Connect OpenAI")
    press(b"\t")  # API key input to Back.
    press(b"\t")  # Back to Skip for now.
    press(b"\r", "Watch targets")
    # Replace the default remote target before submitting or starting collection.
    press(b"\x05")  # End.
    press(b"\x15")  # Delete to beginning before sending printable input.
    frame = press(b"127.0.0.1")
    if "127.0.0.1" not in _plain(frame):
        raise RuntimeError("Loopback target was not rendered before onboarding submission")
    summary = press(b"\r", "Local monitoring only")
    if "1 network target(s)" not in _plain(summary):
        raise RuntimeError("Onboarding must confirm exactly one target before collection starts")
    press(b"\r")


def _first_observation(directory: Path) -> dict[str, object] | None:
    configuration = directory / "config.toml"
    if not configuration.exists():
        return None
    config = tomllib.loads(configuration.read_text())
    if config.get("targets") != ["127.0.0.1"] or config.get("log_paths") or config.get("services"):
        raise RuntimeError(
            f"PTY setup must save only the selected loopback target: "
            f"targets={config.get('targets')!r}, logs={config.get('log_paths')!r}, "
            f"services={config.get('services')!r}"
        )
    if (directory / ".env").exists():
        raise RuntimeError("Offline onboarding unexpectedly created credentials")
    database = directory / "socketclaw.db"
    if not database.exists():
        return None
    try:
        with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True, timeout=0.25) as connection:
            external = connection.execute(
                "SELECT count(*) FROM events WHERE source IN ('ping', 'port_scan') "
                "AND target != '127.0.0.1'"
            ).fetchone()[0]
            if external:
                raise RuntimeError("PTY setup collected an unselected network target")
            row = connection.execute(
                "SELECT id, event_type, target, outcome FROM events "
                "WHERE target = '127.0.0.1' AND source IN ('ping', 'port_scan') "
                "AND outcome = 'ok' ORDER BY ingest_seq LIMIT 1"
            ).fetchone()
            investigations = connection.execute("SELECT count(*) FROM investigations").fetchone()[0]
            if investigations:
                raise RuntimeError("Offline PTY run unexpectedly created an investigation")
    except sqlite3.OperationalError:
        return None
    return dict(zip(("id", "event_type", "target", "outcome"), row, strict=True)) if row else None


def run(
    command: list[str], columns: int, rows: int, *, onboarding: bool, cancel: bool = False
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="socketclaw-pty-") as directory:
        if not onboarding:
            configuration = Path(directory) / "config.toml"
            configuration.write_text('targets = ["127.0.0.1"]\nports = [65534]\n')
            configuration.chmod(0o600)
        master, slave = pty.openpty()
        _resize(slave, columns, rows)
        env = {
            **os.environ,
            "SOCKETCLAW_HOME": directory,
            "TERM": "xterm-256color",
            "NO_COLOR": "1",
        }
        env.pop("OPENAI_API_KEY", None)
        process = subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True
        )
        os.close(slave)
        output = bytearray()
        first_observation: dict[str, object] | None = None
        try:
            output.extend(_read(master, 2.0))
            # A cold frozen executable can take longer than the source interpreter.
            deadline = time.monotonic() + 30
            ready = "Let's set up your watch." if onboarding else "Your watch"
            while ready not in _plain(output) and time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                output.extend(_read(master, 0.25))
            if process.poll() is not None:
                raise RuntimeError(f"TUI exited during startup: {output[-6000:]!r}")
            if ready not in _plain(output):
                raise RuntimeError(f"TUI startup never reached {ready!r}: {_plain(output)[-3000:]}")
            if onboarding and not cancel:
                _complete_onboarding(master, output)
            if not cancel:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    first_observation = _first_observation(Path(directory))
                    if first_observation:
                        break
                    output.extend(_read(master, 0.25))
                    if process.poll() is not None:
                        break
                if first_observation is None:
                    raise RuntimeError(f"No first loopback observation: {_plain(output)[-4000:]}")
                for key in (b"2", b"\x1b", b"3", b"\x1b", b"4", b"5", b"\x1b", b"1"):
                    os.write(master, key)
                    output.extend(_read(master, 0.25))
            for width, height in ((60, 18), (120, 36), (80, 24)):
                _resize(master, width, height)
                process.send_signal(signal.SIGWINCH)
                output.extend(_read(master, 0.4))
            os.write(master, b"\x03")
            output.extend(_read(master, 2.0))
            process.wait(timeout=10)
            if process.returncode != 0:
                raise RuntimeError(f"PTY exit {process.returncode}: {output[-6000:]!r}")
            for failure in (b"Traceback (most recent call last)", b"WorkerFailed", b"NoMatches"):
                if failure in output:
                    raise RuntimeError(f"PTY emitted {failure!r}: {output[-6000:]!r}")
            if b"socketclaw" not in output.lower():
                raise RuntimeError(f"TUI did not render: {output[-1000:]!r}")
            # Inline mode must preserve the caller's scrollback, including after resize.
            if b"\x1b[3J" in output:
                raise RuntimeError("TUI erased terminal scrollback")
            if cancel and (Path(directory) / "config.toml").exists():
                raise RuntimeError("Canceling onboarding unexpectedly saved configuration")
            return {
                "columns": columns,
                "rows": rows,
                "onboarding": onboarding,
                "mode": "cancel" if cancel else "onboarding" if onboarding else "configured",
                "first_observation": first_observation,
                "resize": [[60, 18], [120, 36], [80, 24]],
                "exit": process.returncode,
                "output_bytes": len(output),
            }
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    executable: Path | None = args.executable
    command = (
        [str(executable.resolve())]
        if executable
        else [sys.executable, "-c", "from socketclaw.entrypoint import main; main()"]
    )
    for columns, rows in ((80, 24), (120, 36)):
        for onboarding, cancel in ((True, False), (True, True), (False, False)):
            print(
                json.dumps(run(command, columns, rows, onboarding=onboarding, cancel=cancel)),
                flush=True,
            )


if __name__ == "__main__":
    main()
