from __future__ import annotations

import asyncio
import json
from pathlib import Path

from typer.testing import CliRunner

from socketclaw import __version__
from socketclaw.cli import app
from socketclaw.config import ConfigStore
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.storage import Repository

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"SocketClaw {__version__}"


def test_config_path_uses_effective_socketclaw_home(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))

    result = runner.invoke(app, ["config", "path"])

    assert result.exit_code == 0
    assert result.stdout.strip() == str(tmp_path)


def test_no_argument_command_launches_tui(
    tmp_path: Path,
    monkeypatch,
) -> None:
    launched: list[Path] = []
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    monkeypatch.setattr(
        "socketclaw.cli._launch_tui",
        lambda store: launched.append(store.home),
    )

    result = runner.invoke(app)

    assert result.exit_code == 0
    assert launched == [tmp_path]


def test_doctor_command_redacts_configured_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    ConfigStore(tmp_path).save_api_key("sk-proj-secret")

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "OpenAI key" in result.stdout
    assert "configured" in result.stdout
    assert "sk-proj-secret" not in result.stdout


def test_export_latest_event_as_redacted_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    store = ConfigStore(tmp_path)
    store.save_api_key("sk-proj-secret")

    async def seed() -> str:
        repository = Repository(store.database_path)
        await repository.initialize()
        event = SecurityEvent(
            source="manual",
            event_type="manual.test",
            title="Synthetic incident",
            summary="Evidence contains sk-proj-secret",
            target="1.1.1.1",
            evidence={"secret": "sk-proj-secret"},
        )
        stored = await repository.save_event(
            event,
            Detector().score(event, ()),
        )
        await repository.close()
        return str(stored.id)

    event_id = asyncio.run(seed())
    destination = tmp_path / "incident.json"

    result = runner.invoke(
        app,
        ["export", "--format", "json", "--output", str(destination)],
    )

    assert result.exit_code == 0
    assert str(destination) in result.stdout
    payload = json.loads(destination.read_text())
    assert payload["event"]["id"] == event_id
    assert "sk-proj-secret" not in destination.read_text()
    assert "[REDACTED]" in destination.read_text()


def test_export_explains_empty_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))

    result = runner.invoke(app, ["export", "--format", "markdown"])

    assert result.exit_code == 1
    assert "No events are available to export." in result.stdout


def test_help_lists_operational_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("doctor", "config", "export", "version"):
        assert command in result.stdout
