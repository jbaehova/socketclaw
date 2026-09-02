from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from socketclaw.config import ConfigStore
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
    assert report.check("traceroute command").status == "warn"
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
