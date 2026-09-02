"""Non-secret launch diagnostics for the local SocketClaw runtime."""

from __future__ import annotations

import platform
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from .config import ConfigError, ConfigStore
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
        labels = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
        lines = [f"[{labels[check.status]}] {check.name}: {check.detail}" for check in self.checks]
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
        checks.append(
            DiagnosticCheck(
                name="Application home",
                status="pass",
                detail=f"private writable path at {store.home}",
            )
        )

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
                detail="configured" if key else "not configured; onboarding will open",
            )
        )

    probe = database_probe or _probe_database
    checks.append(await probe(store))
    checks.extend(_command_check(name, which(name)) for name in ("ping", _traceroute_command()))
    return DoctorReport(tuple(checks))


async def _probe_database(store: ConfigStore) -> DiagnosticCheck:
    repository = Repository(store.database_path)
    try:
        await repository.initialize()
        info = await repository.database_info()
    except Exception as exc:
        return DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail=str(exc),
            blocking=True,
        )
    finally:
        await repository.close()
    return DiagnosticCheck(
        name="SQLite database",
        status="pass",
        detail=(
            f"schema {info.schema_version}, {info.journal_mode.upper()}, "
            f"foreign keys {'ON' if info.foreign_keys else 'OFF'}"
        ),
    )


def _command_check(command: str, path: str | None) -> DiagnosticCheck:
    label = "traceroute command" if command in {"traceroute", "tracert"} else "ping command"
    return DiagnosticCheck(
        name=label,
        status="pass" if path else "warn",
        detail=path or f"{command} was not found; related diagnostics will be unavailable",
    )


def _traceroute_command() -> str:
    return "tracert" if platform.system() == "Windows" else "traceroute"
