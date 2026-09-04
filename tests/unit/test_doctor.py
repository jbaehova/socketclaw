from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from socketclaw.config import AppConfig, ConfigStore
from socketclaw.doctor import DiagnosticCheck, inspect_environment


@pytest.mark.asyncio
async def test_doctor_reports_missing_optional_commands_without_blocking(
    tmp_path: Path,
) -> None:
    store = ConfigStore(tmp_path)
    store.save_api_key("sk-proj-secret")

    report = await inspect_environment(store, which=lambda _command: None)

    assert report.launch_ready is True
    assert report.check("OpenAI key").status == "pass"
    assert report.check("ping command").status == "warn"
    assert "sk-proj-secret" not in report.render()


@pytest.mark.asyncio
async def test_doctor_marks_malformed_config_as_launch_blocker(
    tmp_path: Path,
) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text('model = "terra"\ntargets = [')

    report = await inspect_environment(store)

    assert report.launch_ready is False
    assert report.check("Configuration").status == "fail"
    assert "config.toml" in report.check("Configuration").detail


@pytest.mark.asyncio
async def test_doctor_describes_keyless_offline_operation(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.save(AppConfig())

    report = await inspect_environment(store)

    assert report.launch_ready is True
    assert report.check("OpenAI key").status == "warn"
    assert report.check("OpenAI key").detail == (
        "not configured; AI investigations are unavailable"
    )


@pytest.mark.asyncio
async def test_doctor_surfaces_database_failure_as_launch_blocker(
    tmp_path: Path,
) -> None:
    async def broken_database(_store: ConfigStore) -> DiagnosticCheck:
        return DiagnosticCheck(
            name="SQLite database",
            status="fail",
            detail="directory is read-only",
            blocking=True,
        )

    probe: Callable[[ConfigStore], Awaitable[DiagnosticCheck]] = broken_database
    report = await inspect_environment(
        ConfigStore(tmp_path),
        database_probe=probe,
    )

    assert report.launch_ready is False
    assert report.check("SQLite database").detail == "directory is read-only"


@pytest.mark.asyncio
async def test_doctor_converts_unusable_home_into_blocking_check(tmp_path: Path) -> None:
    home = tmp_path / "not-a-directory"
    home.write_text("occupied")

    report = await inspect_environment(ConfigStore(home), which=lambda _command: None)

    assert report.launch_ready is False
    assert report.check("Application home").status == "fail"
    assert "Cannot prepare application home" in report.check("Application home").detail


@pytest.mark.asyncio
async def test_doctor_converts_raised_database_probe_into_blocking_check(
    tmp_path: Path,
) -> None:
    async def broken_database(_store: ConfigStore) -> DiagnosticCheck:
        raise RuntimeError()

    report = await inspect_environment(
        ConfigStore(tmp_path),
        database_probe=broken_database,
    )

    assert report.launch_ready is False
    assert report.check("SQLite database").status == "fail"
    assert report.check("SQLite database").detail == "RuntimeError"


@pytest.mark.asyncio
async def test_doctor_converts_command_lookup_failure_into_warning(tmp_path: Path) -> None:
    def broken_which(_command: str) -> str | None:
        raise OSError("PATH is unreadable")

    report = await inspect_environment(ConfigStore(tmp_path), which=broken_which)

    assert report.launch_ready is True
    assert report.check("ping command").status == "warn"
    assert "PATH is unreadable" in report.check("ping command").detail


@pytest.mark.asyncio
async def test_doctor_reports_unreadable_or_missing_log_paths(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.save(AppConfig(log_paths=[str(tmp_path / "missing.log")]))

    report = await inspect_environment(store)

    assert report.launch_ready is True
    assert report.check("Log paths").status == "warn"
    assert "not a regular file" in report.check("Log paths").detail


@pytest.mark.asyncio
async def test_doctor_warns_for_unexpandable_log_user(tmp_path: Path) -> None:
    configured = "~socketclaw-user-that-cannot-exist-90817/auth.log"
    store = ConfigStore(tmp_path)
    store.save(AppConfig(log_paths=[configured]))

    report = await inspect_environment(store)

    assert report.launch_ready is True
    assert report.check("Log paths").status == "warn"
    assert configured in report.check("Log paths").detail


@pytest.mark.asyncio
async def test_doctor_warns_for_symbolic_link_log_path(tmp_path: Path) -> None:
    actual = tmp_path / "actual.log"
    actual.write_text("event\n")
    linked = tmp_path / "linked.log"
    linked.symlink_to(actual)
    store = ConfigStore(tmp_path / "home")
    store.save(AppConfig(log_paths=[str(linked)]))

    report = await inspect_environment(store)

    assert report.check("Log paths").status == "warn"
    assert "symbolic link" in report.check("Log paths").detail


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are unavailable")
@pytest.mark.asyncio
async def test_doctor_warns_for_fifo_log_path_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "events.pipe"
    os.mkfifo(fifo)
    store = ConfigStore(tmp_path / "home")
    store.save(AppConfig(log_paths=[str(fifo)]))

    report = await inspect_environment(store)

    assert report.check("Log paths").status == "warn"
    assert "not a regular file" in report.check("Log paths").detail


@pytest.mark.asyncio
async def test_doctor_render_strips_credentials_and_terminal_controls(tmp_path: Path) -> None:
    secret = "sk-proj-THIS_SHOULD_NOT_LEAK_123456"
    separated = secret.replace("LEAK", "LE\x1bAK")

    async def unsafe_database(_store: ConfigStore) -> DiagnosticCheck:
        return DiagnosticCheck(
            name="SQLite\x1b]0;owned\x07 database",
            status="fail",
            detail=f"failed\nfor {separated}",
            blocking=True,
        )

    report = await inspect_environment(
        ConfigStore(tmp_path),
        database_probe=unsafe_database,
    )
    rendered = report.render()

    assert secret not in rendered
    assert "[REDACTED]" in rendered
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "failed for" in rendered
