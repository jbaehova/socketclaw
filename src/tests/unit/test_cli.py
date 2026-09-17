from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from click import ClickException
from typer.testing import CliRunner

from socketclaw import __version__
from socketclaw import cli as cli_module
from socketclaw.cli import (
    _ApplicationLock,
    _atomic_private_write,
    _build_probe_plan,
    _launch_tui,
    _ProbePlanner,
    app,
)
from socketclaw.config import AppConfig, ConfigStore
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


def test_config_path_reports_unexpandable_home_without_traceback(monkeypatch) -> None:
    monkeypatch.setenv(
        "SOCKETCLAW_HOME",
        "~socketclaw-user-that-cannot-exist-90817/config",
    )

    result = runner.invoke(app, ["config", "path"])

    assert result.exit_code == 1
    assert "Cannot resolve SocketClaw home" in result.output
    assert "Traceback" not in result.output


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


def test_launch_error_redacts_credentials_and_terminal_controls(monkeypatch) -> None:
    secret = "sk-proj-THIS_SHOULD_NOT_LEAK_123456"
    separated = secret.replace("LEAK", "LE\x1bAK")

    def fail(_store: ConfigStore) -> None:
        raise RuntimeError(f"failed\nfor {separated}\x1b]0;owned\x07")

    monkeypatch.setattr("socketclaw.cli._launch_tui", fail)

    result = runner.invoke(app)

    assert result.exit_code == 1
    assert secret not in result.output
    assert "[REDACTED]" in result.output
    assert "\x1b" not in result.output
    assert "\x07" not in result.output


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


def test_doctor_does_not_echo_key_shaped_invalid_env_name(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    store = ConfigStore(tmp_path)
    store.ensure_home()
    secret = "sk-proj-THIS_SHOULD_NOT_LEAK_123456"
    store.env_path.write_text(f"{secret}=x\n")

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert secret not in result.output


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


def test_export_distinguishes_unknown_event_from_empty_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    event_id = uuid4()

    result = runner.invoke(app, ["export", "--event", str(event_id)])

    assert result.exit_code == 1
    assert f"Event {event_id} was not found." in result.stdout


def test_export_reports_unusable_home_without_traceback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "not-a-directory"
    home.write_text("occupied")
    monkeypatch.setenv("SOCKETCLAW_HOME", str(home))

    result = runner.invoke(app, ["export"])

    assert result.exit_code == 1
    assert "Cannot export incident" in result.output
    assert "Traceback" not in result.output


def test_export_refuses_managed_file_and_hardlink_destinations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))
    store = ConfigStore(tmp_path)
    store.save(AppConfig(theme="textual-light"))

    async def seed() -> None:
        repository = Repository(store.database_path)
        await repository.initialize()
        event = SecurityEvent(
            source="manual",
            event_type="manual.test",
            title="Synthetic incident",
            summary="Protected destination test",
        )
        await repository.save_event(event, Detector().score(event, ()))
        await repository.close()

    asyncio.run(seed())
    original_config = store.config_path.read_bytes()
    alias = tmp_path / "config-alias"
    alias.hardlink_to(store.config_path)

    exact_result = runner.invoke(
        app,
        ["export", "--output", str(store.config_path)],
    )
    alias_result = runner.invoke(
        app,
        ["export", "--output", str(alias)],
    )

    assert exact_result.exit_code == 1
    assert alias_result.exit_code == 1
    assert "Refusing to overwrite managed SocketClaw file" in exact_result.output
    assert "Refusing to overwrite managed SocketClaw file" in alias_result.output
    assert store.config_path.read_bytes() == original_config


def test_probe_plan_omits_unavailable_ping_and_keeps_other_collectors() -> None:
    config = AppConfig(
        targets=["1.1.1.1", "example.com"],
        log_paths=["~/security.log"],
    )

    jobs, diagnostics = _build_probe_plan(config, which=lambda _command: None)

    assert [job.name for job in jobs] == [
        "ports:1.1.1.1",
        "ports:example.com",
        "logs",
    ]
    assert set(diagnostics) == {"ports"}


def test_probe_plan_rejects_unexpandable_log_user() -> None:
    config = AppConfig(log_paths=["~socketclaw-user-that-cannot-exist-90817/auth.log"])

    with pytest.raises(ClickException, match="Cannot expand log path"):
        _build_probe_plan(config, which=lambda _command: None)


def test_probe_plan_includes_ping_when_command_is_available() -> None:
    jobs, diagnostics = _build_probe_plan(
        AppConfig(targets=["1.1.1.1"]),
        which=lambda _command: "/usr/bin/ping",
    )

    assert [job.name for job in jobs] == ["ping:1.1.1.1", "ports:1.1.1.1"]
    assert set(diagnostics) == {"ping", "ports"}


@pytest.mark.asyncio
async def test_probe_planner_preserves_log_cursor_across_unrelated_change(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("historical line\n")
    initial = AppConfig(log_paths=[str(log_path)], ping_interval=5)
    planner = _ProbePlanner(which=lambda _command: None)
    first = planner.prepare(initial)
    planner.commit(first)
    first_log_job = next(job for job in first.jobs if job.name == "logs")
    assert await first_log_job.collect() == []
    with log_path.open("a") as stream:
        stream.write("authentication failure from 10.0.0.8\n")

    second = planner.prepare(initial.model_copy(update={"ping_interval": 10}))
    second_log_job = next(job for job in second.jobs if job.name == "logs")
    events = await second_log_job.collect()

    assert second.log_probe is first.log_probe
    assert [event.event_type for event in events] == ["log.auth_failure"]


def test_probe_planner_preserves_port_baseline_across_non_port_changes(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.log"
    second_path = tmp_path / "second.log"
    initial = AppConfig(log_paths=[str(first_path)], ports=[22, 443])
    planner = _ProbePlanner(which=lambda _command: None)
    first = planner.prepare(initial)
    planner.commit(first)

    second = planner.prepare(
        initial.model_copy(
            update={
                "ping_interval": 10,
                "log_paths": [str(first_path), str(second_path)],
            }
        )
    )

    assert second.port_probe is first.port_probe
    assert second.log_probe is first.log_probe


@pytest.mark.asyncio
async def test_probe_planner_prunes_removed_port_targets_and_readds_as_baseline() -> None:
    async def connector(_target: str, _port: int, _timeout: float) -> bool:
        return True

    planner = _ProbePlanner(which=lambda _command: None)
    initial = planner.prepare(AppConfig(targets=["1.1.1.1"], ports=[443]))
    initial.port_probe.connector = connector
    first_event = await initial.port_probe.collect("1.1.1.1", [443])
    assert first_event.evidence["baseline"] is True
    planner.commit(initial)

    removed = planner.prepare(AppConfig(targets=["8.8.8.8"], ports=[443]))
    planner.commit(removed)
    assert removed.port_probe is not initial.port_probe

    readded = planner.prepare(AppConfig(targets=["1.1.1.1"], ports=[443]))
    readded.port_probe.connector = connector
    event = await readded.port_probe.collect("1.1.1.1", [443])

    assert event.evidence["baseline"] is True
    assert event.evidence["newly_opened"] == []
    assert set(readded.port_probe._previous) == {"1.1.1.1"}


@pytest.mark.asyncio
async def test_probe_planner_reconfigures_intersecting_logs_and_rolls_back_failure(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.log"
    retained_path = tmp_path / "retained.log"
    added_path = tmp_path / "added.log"
    planner = _ProbePlanner(which=lambda _command: None)
    initial_config = AppConfig(log_paths=[str(first_path), str(retained_path)])
    initial = planner.prepare(initial_config)
    planner.commit(initial)
    replacement = planner.prepare(
        initial_config.model_copy(update={"log_paths": [str(retained_path), str(added_path)]})
    )

    class BrokenMonitor:
        async def reconfigure(self, *, jobs, diagnostics) -> None:
            assert jobs
            assert diagnostics
            raise RuntimeError("reconfigure failed")

    with pytest.raises(RuntimeError, match="reconfigure failed"):
        await planner.activate(BrokenMonitor(), replacement)  # type: ignore[arg-type]

    assert initial.log_probe is not None
    assert initial.log_probe.paths == [first_path, retained_path]


@pytest.mark.asyncio
async def test_probe_plan_collectors_bind_each_target_and_port_snapshot(monkeypatch) -> None:
    ping_targets: list[str] = []
    port_calls: list[tuple[str, tuple[int, ...]]] = []
    ping_executables: list[str] = []

    class FakePing:
        def __init__(self, *, executable: str) -> None:
            ping_executables.append(executable)

        async def collect(self, target: str) -> SecurityEvent:
            ping_targets.append(target)
            return SecurityEvent(
                source="ping",
                event_type="ping.test",
                title="Ping test",
                summary="Ping test",
                target=target,
            )

    class FakePorts:
        async def collect(self, target: str, ports) -> SecurityEvent:
            selected_ports = tuple(ports)
            port_calls.append((target, selected_ports))
            return SecurityEvent(
                source="port_scan",
                event_type="ports.test",
                title="Port test",
                summary="Port test",
                target=target,
            )

    monkeypatch.setattr(cli_module, "PingProbe", FakePing)
    monkeypatch.setattr(cli_module, "PortProbe", FakePorts)
    jobs, _diagnostics = _build_probe_plan(
        AppConfig(targets=["1.1.1.1", "example.com"], ports=[22, 8443]),
        which=lambda _command: "/usr/bin/ping",
    )

    for job in jobs:
        await job.collect()

    assert ping_targets == ["1.1.1.1", "example.com"]
    assert ping_executables == [str(Path("/usr/bin/ping").resolve())]
    assert port_calls == [
        ("1.1.1.1", (22, 8443)),
        ("example.com", (22, 8443)),
    ]


def test_launch_records_clean_run_and_reconfigures_existing_monitor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    operations: list[str] = []
    run_id = uuid4()

    class FakeRepository:
        async def initialize(self) -> None:
            operations.append("initialize")

        async def start_run(self, version: str):
            operations.append(f"start:{version}")
            return SimpleNamespace(id=run_id)

        async def stop_run(self, selected_id, *, clean_shutdown: bool):
            assert selected_id == run_id
            operations.append(f"stop:{clean_shutdown}")

        async def close(self) -> None:
            operations.append("close")

    class FakeMonitor:
        async def reconfigure(self, *, jobs, diagnostics) -> None:
            operations.append("reconfigure")
            assert jobs
            assert "ports" in diagnostics

        async def stop(self) -> None:
            operations.append("monitor.stop")

    monitor = FakeMonitor()

    class FakeApp:
        def __init__(self, services) -> None:
            self.services = services

        async def run_async(self) -> None:
            operations.append("run")
            assert self.services.monitor is monitor
            assert self.services.reconfigure is not None
            await self.services.reconfigure(AppConfig(theme="textual-light"))
            await self.services.reconfigure(AppConfig(targets=["example.com"]))

    repository = FakeRepository()
    monkeypatch.setattr(cli_module, "Repository", lambda _path: repository)
    monkeypatch.setattr(
        cli_module,
        "_build_monitor",
        lambda _config, _repository, **_kwargs: monitor,
    )
    monkeypatch.setattr(cli_module, "SocketClawApp", FakeApp)

    _launch_tui(ConfigStore(tmp_path))

    assert operations == [
        "initialize",
        f"start:{__version__}",
        "run",
        "reconfigure",
        "monitor.stop",
        "stop:True",
        "close",
    ]


def test_launch_records_unclean_run_and_closes_repository(
    tmp_path: Path,
    monkeypatch,
) -> None:
    operations: list[str] = []
    run_id = uuid4()

    class FakeRepository:
        async def initialize(self) -> None:
            operations.append("initialize")

        async def start_run(self, _version: str):
            operations.append("start")
            return SimpleNamespace(id=run_id)

        async def stop_run(self, _selected_id, *, clean_shutdown: bool):
            operations.append(f"stop:{clean_shutdown}")

        async def close(self) -> None:
            operations.append("close")

    class FakeApp:
        def __init__(self, _services) -> None:
            pass

        async def run_async(self) -> None:
            operations.append("run")
            raise RuntimeError("TUI failed")

    class FakeMonitor:
        async def stop(self) -> None:
            operations.append("monitor.stop")

    monkeypatch.setattr(cli_module, "Repository", lambda _path: FakeRepository())
    monkeypatch.setattr(
        cli_module,
        "_build_monitor",
        lambda _config, _repository, **_kwargs: FakeMonitor(),
    )
    monkeypatch.setattr(cli_module, "SocketClawApp", FakeApp)

    with pytest.raises(RuntimeError, match="TUI failed"):
        _launch_tui(ConfigStore(tmp_path))

    assert operations == [
        "initialize",
        "start",
        "run",
        "monitor.stop",
        "stop:False",
        "close",
    ]


def test_monitor_stop_failure_still_terminates_run_and_closes_repository(
    tmp_path: Path,
    monkeypatch,
) -> None:
    operations: list[str] = []
    run_id = uuid4()

    class FakeRepository:
        async def initialize(self) -> None:
            operations.append("initialize")

        async def start_run(self, _version: str):
            operations.append("start")
            return SimpleNamespace(id=run_id)

        async def stop_run(self, _selected_id, *, clean_shutdown: bool):
            operations.append(f"stop:{clean_shutdown}")

        async def close(self) -> None:
            operations.append("close")

    class FakeMonitor:
        async def stop(self) -> None:
            operations.append("monitor.stop")
            raise RuntimeError("monitor cleanup failed")

    class FakeApp:
        def __init__(self, _services) -> None:
            pass

        async def run_async(self) -> None:
            operations.append("run")

    monkeypatch.setattr(cli_module, "Repository", lambda _path: FakeRepository())
    monkeypatch.setattr(
        cli_module,
        "_build_monitor",
        lambda _config, _repository, **_kwargs: FakeMonitor(),
    )
    monkeypatch.setattr(cli_module, "SocketClawApp", FakeApp)

    with pytest.raises(RuntimeError, match="monitor cleanup failed"):
        _launch_tui(ConfigStore(tmp_path))

    assert operations == [
        "initialize",
        "start",
        "run",
        "monitor.stop",
        "stop:False",
        "close",
    ]


def test_application_lock_rejects_contention_and_can_be_reacquired(tmp_path: Path) -> None:
    lock_path = tmp_path / ".instance.lock"
    first = _ApplicationLock(lock_path)
    second = _ApplicationLock(lock_path)
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()


def test_application_lock_rejects_hard_link_without_mutating_target(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.write_text("must remain intact")
    lock_path = tmp_path / ".instance.lock"
    lock_path.hardlink_to(protected)

    with pytest.raises(RuntimeError, match="must not be hard linked"):
        _ApplicationLock(lock_path).acquire()

    assert protected.read_text() == "must remain intact"


def test_application_lock_rejects_symbolic_link_without_mutating_target(
    tmp_path: Path,
) -> None:
    protected = tmp_path / "protected"
    protected.write_text("must remain intact")
    lock_path = tmp_path / ".instance.lock"
    lock_path.symlink_to(protected)

    with pytest.raises(RuntimeError, match="must not be a symbolic link"):
        _ApplicationLock(lock_path).acquire()

    assert protected.read_text() == "must remain intact"


def test_launch_releases_application_lock_after_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def fail(_store: ConfigStore) -> None:
        contender = _ApplicationLock(tmp_path / ".instance.lock")
        with pytest.raises(RuntimeError, match="already running"):
            contender.acquire()
        raise RuntimeError("startup failed")

    monkeypatch.setattr(cli_module, "_run_tui", fail)

    with pytest.raises(RuntimeError, match="startup failed"):
        _launch_tui(ConfigStore(tmp_path))

    lock = _ApplicationLock(tmp_path / ".instance.lock")
    lock.acquire()
    lock.release()


def test_atomic_export_write_cleans_failed_temporary_file(tmp_path: Path) -> None:
    destination = tmp_path / "incident.md"

    with pytest.raises(ClickException, match="Cannot write export"):
        _atomic_private_write(destination, "broken-\ud800")

    assert not destination.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_help_lists_operational_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("doctor", "config", "export", "version"):
        assert command in result.stdout
