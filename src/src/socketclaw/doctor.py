"""Non-secret launch diagnostics for the local SocketClaw runtime."""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import stat
import unicodedata
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import ConfigError, ConfigStore
from .openai import redact_secrets
from .storage import Repository

CheckStatus = Literal["pass", "warn", "fail"]
CommandFinder = Callable[[str], str | None]


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    """One stable, display-ready environment check."""

    name: str
    status: CheckStatus
    detail: str
    blocking: bool = False


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Ordered doctor output and its launch-readiness decision."""

    checks: tuple[DiagnosticCheck, ...]

    @property
    def launch_ready(self) -> bool:
        return not any(check.blocking and check.status == "fail" for check in self.checks)

    def check(self, name: str) -> DiagnosticCheck:
        try:
            return next(check for check in self.checks if check.name == name)
        except StopIteration as exc:
            raise KeyError(name) from exc

    def render(self) -> str:
        labels = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}  # nosec B105
        lines = [
            f"[{labels[check.status]}] {_terminal_text(check.name)}: {_terminal_text(check.detail)}"
            for check in self.checks
        ]
        lines.append(
            "Launch readiness: READY" if self.launch_ready else "Launch readiness: BLOCKED"
        )
        return "\n".join(lines)


DatabaseProbe = Callable[[ConfigStore], Awaitable[DiagnosticCheck]]


async def inspect_environment(
    store: ConfigStore,
    *,
    which: CommandFinder = shutil.which,
    database_probe: DatabaseProbe | None = None,
) -> DoctorReport:
    """Inspect launch-critical paths without sending data or model requests."""
    checks: list[DiagnosticCheck] = [
        DiagnosticCheck(
            name="Runtime",
            status="pass",
            detail=f"Python {platform.python_version()} on {platform.system()}",
        )
    ]
    home_ready = False
    try:
        store.ensure_home()
    except ConfigError as exc:
        checks.append(
            DiagnosticCheck(
                name="Application home",
                status="fail",
                detail=str(exc),
                blocking=True,
            )
        )
    else:
        home_ready = True
        checks.append(
            DiagnosticCheck(
                name="Application home",
                status="pass",
                detail=f"private writable path at {store.home}",
            )
        )

    checks.append(_disk_space_check(store))

    try:
        config = store.load()
    except ConfigError as exc:
        checks.append(
            DiagnosticCheck(
                name="Configuration",
                status="fail",
                detail=str(exc),
                blocking=True,
            )
        )
    else:
        checks.append(
            DiagnosticCheck(
                name="Configuration",
                status="pass",
                detail=(
                    f"{len(config.targets)} target(s), "
                    f"{config.preset.label} / {config.preset.reasoning_label}"
                ),
            )
        )
        checks.append(_log_paths_check(config.log_paths))

    try:
        key = store.load_api_key()
    except ConfigError as exc:
        checks.append(
            DiagnosticCheck(
                name="OpenAI key",
                status="fail",
                detail=str(exc),
                blocking=True,
            )
        )
    else:
        checks.append(
            DiagnosticCheck(
                name="OpenAI key",
                status="pass" if key else "warn",
                detail=(
                    "configured" if key else "not configured; AI investigations are unavailable"
                ),
            )
        )

    if not home_ready:
        database_check = DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail="not checked because the application home is unavailable",
            blocking=True,
        )
    else:
        probe = database_probe or _probe_database
        try:
            database_check = await probe(store)
        except Exception as exc:
            database_check = DiagnosticCheck(
                name="SQLite database",
                status="fail",
                detail=_error_detail(exc),
                blocking=True,
            )
    checks.append(database_check)
    checks.append(_inspect_command("ping", which))
    return DoctorReport(tuple(checks))


async def _probe_database(store: ConfigStore) -> DiagnosticCheck:
    if not store.database_path.exists() and not store.database_path.is_symlink():
        return DiagnosticCheck(
            name="SQLite database",
            status="pass",
            detail="not created yet; the first TUI launch will initialize storage",
        )
    try:
        repository = Repository(store.database_path, read_only=True)
    except Exception as exc:
        return DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail=_error_detail(exc),
            blocking=True,
        )

    info = None
    error: Exception | None = None
    try:
        info = await repository.database_info()
    except asyncio.CancelledError:
        with suppress(Exception):
            await repository.close()
        raise
    except Exception as exc:
        error = exc
    try:
        await repository.close()
    except Exception as exc:
        if error is None:
            error = exc
    if error is not None:
        return DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail=_error_detail(error),
            blocking=True,
        )
    if info is None:
        return DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail="database probe did not return schema information",
            blocking=True,
        )
    return DiagnosticCheck(
        name="SQLite database",
        status="pass",
        detail=(
            f"schema {info.schema_version}, {info.journal_mode.upper()}, "
            f"foreign keys {'ON' if info.foreign_keys else 'OFF'}"
        ),
    )


def _disk_space_check(store: ConfigStore) -> DiagnosticCheck:
    """Estimate reserve for SQLite growth and a recoverable backup without writes."""
    try:
        usage = shutil.disk_usage(store.home)
        database_bytes = 0
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(store.database_path) + suffix)
            with suppress(FileNotFoundError):
                database_bytes += path.stat().st_size
        reserve = max(100 * 1024 * 1024, 2 * database_bytes + 1024 * 1024)
        headroom = usage.free - reserve
        return DiagnosticCheck(
            name="Disk space",
            status="warn" if headroom < 0 else "pass",
            detail=(
                f"{usage.free:,} free bytes; database plus sidecars {database_bytes:,} bytes; "
                f"reserve {reserve:,} bytes; estimated headroom {headroom:,} bytes. "
                + (
                    "Low disk space: free space before backups or continued collection."
                    if headroom < 0
                    else "Reserve covers at least 100 MiB or two database copies plus 1 MiB."
                )
            ),
        )
    except OSError as exc:
        return DiagnosticCheck(
            name="Disk space",
            status="fail",
            detail=f"Cannot inspect disk capacity: {_error_detail(exc)}",
        )


def _command_check(command: str, path: str | None) -> DiagnosticCheck:
    return DiagnosticCheck(
        name=f"{command} command",
        status="pass" if path else "warn",
        detail=path or f"{command} was not found; related diagnostics will be unavailable",
    )


def _inspect_command(command: str, which: CommandFinder) -> DiagnosticCheck:
    try:
        return _command_check(command, which(command))
    except Exception as exc:
        return DiagnosticCheck(
            name=f"{command} command",
            status="warn",
            detail=f"could not inspect command availability: {_error_detail(exc)}",
        )


def _log_paths_check(configured_paths: list[str]) -> DiagnosticCheck:
    if not configured_paths:
        return DiagnosticCheck(
            name="Log paths",
            status="warn",
            detail="not configured; no authentication or security logs are monitored",
        )

    problems: list[str] = []
    for configured in configured_paths:
        fd: int | None = None
        try:
            path = Path(configured).expanduser()
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode):
                problems.append(f"{path} is a symbolic link")
                continue
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                problems.append(f"{path} is not a regular file")
                continue
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                problems.append(f"{path} changed while it was inspected")
        except FileNotFoundError:
            problems.append(f"{configured} is not a regular file")
        except (OSError, RuntimeError) as exc:
            problems.append(f"{configured}: {_error_detail(exc)}")
        finally:
            if fd is not None:
                with suppress(OSError):
                    os.close(fd)

    if not problems:
        return DiagnosticCheck(
            name="Log paths",
            status="pass",
            detail=f"{len(configured_paths)} readable file(s)",
        )
    visible = problems[:3]
    if len(problems) > len(visible):
        visible.append(f"and {len(problems) - len(visible)} more")
    return DiagnosticCheck(
        name="Log paths",
        status="warn",
        detail="; ".join(visible),
    )


def _error_detail(error: Exception) -> str:
    return _terminal_text(str(error) or type(error).__name__)


def _terminal_text(value: str) -> str:
    """Keep diagnostic text on one inert terminal line without credentials."""
    redacted = redact_secrets(value)
    safe: list[str] = []
    for character in redacted:
        codepoint = ord(character)
        if character in {"\r", "\n", "\t"}:
            safe.append(" ")
        elif (
            codepoint >= 0x20
            and not 0x7F <= codepoint <= 0x9F
            and unicodedata.category(character) != "Cf"
        ):
            safe.append(character)
    return redact_secrets("".join(safe))
