"""Runtime regressions for service intent and durable delivery."""

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from socketclaw.cli import _build_probe_plan, _run_monitor
from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig, ConfigStore, NotificationConfig, ServiceConfig
from socketclaw.detection import Detector
from socketclaw.discovery import parse_listeners
from socketclaw.domain import DetectionSignal, EventSource, SecurityEvent
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.notifications import NotificationOutbox
from socketclaw.probes.ping import CommandResult, PingProbe, _ping_command
from socketclaw.probes.ports import PortProbe
from socketclaw.probes.services import ServiceProbe, check_service
from socketclaw.storage import Repository


async def test_long_targets_remain_complete() -> None:
    target = ".".join(["a" * 63] * 3 + ["b" * 61])
    assert len(target) == 253

    async def runner(command, timeout):
        return CommandResult(0, "1 packets transmitted, 1 received, 0% packet loss", "")

    async def connect(host, port, timeout):
        return False

    events = [
        await PingProbe(runner=runner, platform_name="Linux").collect(target),
        await PortProbe(connector=connect).collect(target, [80]),
    ]
    for event in events:
        assert len(event.title) <= 200
        assert event.target == target


def test_ipv6_platform_commands() -> None:
    assert _ping_command("ping6", "Darwin", "::1", 1, 1) == ["ping6", "-c", "1", "::1"]
    assert "-6" in _ping_command("ping", "Linux", "::1", 1, 1)


def test_log_only_and_service_config_round_trip(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "home")
    config = AppConfig(
        targets=[],
        log_paths=["/tmp/one,two.log"],
        profile="logs",
        services=[ServiceConfig(id="api", name="API", host="localhost", port=8080)],
        notifications=NotificationConfig(local=True),
    )
    store.save(config)
    assert store.load() == config
    jobs, _ = _build_probe_plan(AppConfig(targets=[]), which=lambda _: None)
    assert not jobs


async def test_service_confirmation_checkpoint(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "events.db")
    await repository.initialize()
    states = iter(
        [("closed", "refused"), ("closed", "refused"), ("available", "ok"), ("available", "ok")]
    )

    async def check(service):
        return next(states)

    probe = ServiceProbe(repository, check=check)
    service = ServiceConfig(
        id="api", name="API", host="127.0.0.1", port=8080, failure_threshold=2, recovery_threshold=2
    )
    try:
        for expected in (False, True, False, True):
            batch = await probe.collect(service)
            assert batch.observations[0].evidence["confirmed"] is expected
            await repository.ingest_batch(batch, Detector())
        assert (await repository.load_checkpoint("service:api")).state["successes"] == 2
    finally:
        await repository.close()


async def test_real_tcp_http_service() -> None:
    async def handler(reader, writer):
        await reader.read(4096)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nready")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config = ServiceConfig(id="web", name="Web", host="127.0.0.1", port=port)
    try:
        assert (await check_service(config))[0] == "available"
        assert (
            await check_service(
                config.model_copy(update={"protocol": "http", "body_contains": "ready"})
            )
        )[0] == "available"
        assert (
            await check_service(
                config.model_copy(update={"protocol": "http", "expected_status": 204})
            )
        )[0] == "http_mismatch"
    finally:
        server.close()
        await server.wait_closed()
    assert (await check_service(config))[0] == "closed"


def test_listener_process_bindings() -> None:
    listeners = parse_listeners(
        "p123\ncpython\nf4\nn127.0.0.1:8080\nf5\nn*:9090\np125\ncnode\nf8\nn[::1]:3000\n"
    )
    assert [item.exposure for item in listeners] == ["loopback", "all_interfaces", "loopback"]
    assert listeners[0].pid == 123
    assert listeners[0].process == "python"


async def test_quarantine_allows_removal(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "events.db")
    await repository.initialize()
    event = SecurityEvent(
        source=EventSource.SYSTEM, event_type="test.result", title="Test", summary="Test"
    )
    batch = ProbeBatch(observations=(event,))

    class InvalidDetector(Detector):
        def score(self, event, *args, **kwargs):
            DetectionSignal(code="bad", label="Bad", points=1, detail="x" * 501)
            raise AssertionError("unreachable")

    async def collect():
        return batch

    monitor = MonitorService(repository, InvalidDetector(), jobs=[ProbeJob("test", 1, collect)])
    try:
        with pytest.raises(ValidationError):
            await monitor._execute_job(monitor.jobs[0], due=0)
        saved = json.loads(next((tmp_path / "quarantine").glob("*.json")).read_text())
        assert saved["batch"]["batch_id"] == str(batch.batch_id)
        assert monitor.status.quarantined_batches == 1
        await monitor.reconfigure(jobs=[], diagnostics={})
        assert not monitor.jobs
    finally:
        await repository.close()


def test_notification_dedup_retry(tmp_path: Path) -> None:
    database = tmp_path / "events.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE incident_transitions(id TEXT, data_json TEXT)")
        connection.execute(
            "INSERT INTO incident_transitions VALUES(?,?)",
            ("t1", json.dumps({"incident_id": "i1", "action": "opened", "at": "now"})),
        )
    outbox = NotificationOutbox(database, NotificationConfig(local=True))
    for _ in range(100):
        outbox.collect()
    pending = outbox.pending()
    assert len(pending) == 1
    outbox._record(pending[0][0], 0, "temporary")
    assert not outbox.pending()
    with sqlite3.connect(outbox.path) as connection:
        connection.execute("UPDATE deliveries SET next_attempt=0")
    assert outbox.pending()[0][3] == 1
    outbox._record(pending[0][0], 1, None)
    outbox.collect()
    assert not outbox.pending()


async def test_headless_clean_stop(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "home")
    store.save(AppConfig(targets=[]))
    stop = asyncio.Event()
    stop.set()
    await _run_monitor(store, stop)
    assert store.database_path.exists()


async def test_oversized_evidence_is_preserved_and_job_removable(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "events.db")
    await repository.initialize()
    event = SecurityEvent(
        source=EventSource.SYSTEM,
        event_type="test.large",
        title="Large",
        summary="Large",
        evidence={str(i): "x" * 1000 for i in range(60)},
    )
    batch = ProbeBatch(observations=(event,))

    async def collect():
        return batch

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("large", 1, collect)])
    try:
        with pytest.raises(ValueError, match="evidence must not exceed"):
            await monitor._execute_job(monitor.jobs[0], due=0)
        assert (tmp_path / "quarantine" / f"{batch.batch_id}.json").exists()
        await monitor.reconfigure(jobs=[], diagnostics={})
    finally:
        await repository.close()


async def test_local_scan_preserves_process_binding_intent(monkeypatch) -> None:
    from socketclaw.discovery import DiscoveryReport, Listener
    from socketclaw.probes import ports

    async def discovery():
        return DiscoveryReport(
            (Listener("*", 8080, 123, "python", "/usr/bin/python", "all_interfaces"),),
            (),
            ("Internet reachability is not measured",),
        )

    async def connect(host, port, timeout):
        return True

    monkeypatch.setattr(ports, "discover_sources", discovery)
    service = ServiceConfig(id="api", name="API", host="127.0.0.1", port=8080)
    event = await PortProbe(connector=connect, local_context=True, services=[service]).collect(
        "localhost", [8080]
    )
    assert event.evidence["local_listeners"][0]["pid"] == 123
    assert event.evidence["exposure_violations"][0]["allowed_exposure"] == "loopback"


async def test_read_only_viewer_close_keeps_collector_running(tmp_path: Path) -> None:
    from socketclaw.ui.attached import AttachedApp

    repository = Repository(tmp_path / "events.db")
    await repository.initialize()

    async def collect():
        return [
            SecurityEvent(
                source=EventSource.SYSTEM, event_type="test.tick", title="Tick", summary="Tick"
            )
        ]

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("test", 0.03, collect)])
    reader = Repository(tmp_path / "events.db", read_only=True)
    try:
        await monitor.start()
        async with AttachedApp(reader, ["test"]).run_test(size=(80, 24)) as pilot:
            await pilot.pause(0.1)
        assert monitor.status.running
        before = await repository.list_events()
        await asyncio.sleep(0.1)
        assert len(await repository.list_events()) > len(before)
    finally:
        await monitor.stop()
        await reader.close()
        await repository.close()


async def test_service_endpoint_change_resets_confirmation(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "events.db")
    await repository.initialize()

    async def check(service):
        return "closed", "refused"

    probe = ServiceProbe(repository, check=check)
    original = ServiceConfig(id="api", name="API", host="127.0.0.1", port=8088, failure_threshold=2)
    try:
        first = await probe.collect(original)
        await repository.ingest_batch(first, Detector())
        updated = await probe.collect(original.model_copy(update={"port": 8089}))
        assert updated.observations[0].evidence["confirmed"] is False
        assert updated.observations[0].evidence["consecutive_failures"] == 1
    finally:
        await repository.close()


async def test_service_only_config_includes_actual_exposure_scope(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "events.db")
    config = AppConfig(
        targets=[],
        ports=[22],
        services=[ServiceConfig(id="api", name="API", host="127.0.0.1", port=8088)],
    )
    jobs, _ = _build_probe_plan(config, repository=repository, which=lambda _: None)
    assert {job.name for job in jobs} == {"ports:127.0.0.1", "service:api"}
    await repository.close()


async def test_webhook_failure_retry_uses_same_delivery_key(tmp_path: Path, monkeypatch) -> None:
    import httpx

    from socketclaw import notifications

    database = tmp_path / "events.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE incident_transitions(id TEXT, data_json TEXT)")
        connection.execute(
            "INSERT INTO incident_transitions VALUES(?,?)",
            (
                "t1",
                json.dumps(
                    {"incident_id": "i1", "action": "opened", "at": "2020-01-01T00:00:00+00:00"}
                ),
            ),
        )
    attempts = []

    def respond(request):
        attempts.append(request)
        return httpx.Response(503 if len(attempts) == 1 else 200)

    client_type = httpx.AsyncClient
    monkeypatch.setattr(
        notifications.httpx,
        "AsyncClient",
        lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs),
    )
    outbox = NotificationOutbox(
        database, NotificationConfig(webhook="https://configured.test/hook")
    )
    outbox.collect()
    await outbox.deliver()
    assert {key: outbox.status()[key] for key in ("pending", "failed", "delivered")} == {
        "pending": 1,
        "failed": 1,
        "delivered": 0,
    }
    assert outbox.status()["last_error"] == "HTTPStatusError"
    assert outbox.status()["next_attempt_at"] is not None
    with sqlite3.connect(outbox.path) as connection:
        connection.execute("UPDATE deliveries SET next_attempt=0")
    await outbox.deliver()
    assert {key: outbox.status()[key] for key in ("pending", "failed", "delivered")} == {
        "pending": 0,
        "failed": 0,
        "delivered": 1,
    }
    assert attempts[0].headers["Idempotency-Key"] == attempts[1].headers["Idempotency-Key"]
    assert json.loads(attempts[0].content)["delayed_evidence"] is True


def test_doctor_reports_low_disk_and_backup_headroom(tmp_path: Path, monkeypatch) -> None:
    from collections import namedtuple

    from socketclaw import doctor

    store = ConfigStore(tmp_path / "home")
    store.ensure_home()
    store.database_path.write_bytes(b"x" * 1024)
    usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(doctor.shutil, "disk_usage", lambda _: usage(1024**3, 1024**3 - 50, 50))
    check = doctor._disk_space_check(store)
    assert check.status == "warn"
    assert "50 free bytes" in check.detail
    assert "1,024 bytes" in check.detail
    assert "estimated headroom -" in check.detail


async def test_disabled_notifications_never_deliver_or_create_status_db(
    tmp_path: Path, monkeypatch
) -> None:
    from socketclaw import notifications

    async def forbidden(*args, **kwargs):
        raise AssertionError("unconfigured destination must not be contacted")

    monkeypatch.setattr(notifications, "_local_notification", forbidden)
    monkeypatch.setattr(notifications.httpx, "AsyncClient", forbidden)
    outbox = NotificationOutbox(tmp_path / "events.db", NotificationConfig())
    outbox.collect()
    await outbox.deliver()
    status = outbox.status()
    assert status["pending"] == 0
    assert status["last_error"] is None
    assert status["enabled_channels"] == []
    assert not outbox.path.exists()
    # Even a queue retained from a previous configuration cannot send when disabled.
    with sqlite3.connect(outbox.path) as connection:
        connection.execute(
            "CREATE TABLE deliveries(id TEXT,channel TEXT,payload TEXT,"
            "attempts INTEGER, next_attempt REAL,delivered_at REAL,error TEXT)"
        )
        connection.execute("INSERT INTO deliveries VALUES('old','webhook','{}',0,0,NULL,NULL)")
    await outbox.deliver()
    assert outbox.status()["pending"] == 1
