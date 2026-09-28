"""Completion contracts exercised against real SQLite and same-user IPC."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text

from socketclaw.application import ApplicationService
from socketclaw.cli import _build_monitor
from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig, ConfigStore, NotificationConfig, ServiceConfig
from socketclaw.control import ControlClient, ControlError, ControlServer
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent, utc_now
from socketclaw.gateway import RemoteRepository
from socketclaw.maintenance import (
    MaintenanceService,
    backup_inventory,
    restore_database,
    verify_backup,
)
from socketclaw.migrations import SCHEMA_VERSION, recovery_backup
from socketclaw.notifications import NotificationOutbox
from socketclaw.probes.services import ServiceProbe
from socketclaw.storage import Repository


def observation(*, loss=100, target="192.0.2.1", at=None):
    return SecurityEvent(
        source="ping",
        event_type="ping.result",
        target=target,
        title="Reachability",
        summary="Measured reachability",
        observed_at=at or utc_now(),
        evidence={"packet_loss": loss, "outcome": "ok"},
    )


@pytest.fixture
async def owner():
    # AF_UNIX paths are deliberately short; long-home failure has a separate test.
    with tempfile.TemporaryDirectory(prefix="sc-", dir="/tmp") as root:
        store = ConfigStore(Path(root))
        store.save(AppConfig(targets=[]))
        repository = Repository(store.database_path)
        await repository.initialize()
        NotificationOutbox(store.database_path, NotificationConfig()).configure()
        monitor = _build_monitor(store.load(), repository)

        async def reconfigure(config):
            NotificationOutbox(store.database_path, config.notifications).configure()

        application = ApplicationService(store, repository, monitor, reconfigure)
        server = ControlServer(application)
        await server.start()
        try:
            yield store, repository, application, server
        finally:
            await server.close()
            await application.close()
            await monitor.stop()
            await repository.close()


async def test_restore_first_new_incident_is_enqueued(tmp_path):
    database = tmp_path / "socketclaw.db"
    repo = Repository(database)
    await repo.initialize()
    outbox = NotificationOutbox(database, NotificationConfig(local=True))
    outbox.configure()
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    first = outbox.pending()
    assert len(first) == 1
    outbox._record(first[0][0], 0, None)
    backup = recovery_backup(database, SCHEMA_VERSION)
    await repo.ingest_batch(ProbeBatch(observations=(observation(target="192.0.2.2"),)), Detector())
    old_id = outbox.pending()[0][0]
    await repo.close()
    restore_database(database, backup.path, apply=True)
    repo = Repository(database)
    await repo.initialize()
    await repo.ingest_batch(ProbeBatch(observations=(observation(target="192.0.2.3"),)), Detector())
    pending = outbox.pending()
    assert len(pending) == 1 and pending[0][0] != old_id
    assert outbox.status()["failed"] == 0
    assert not (tmp_path / "notifications.db").exists()
    await repo.close()


async def test_transition_and_outbox_rollback_together(owner):
    store, repo, _application, _ = owner
    box = NotificationOutbox(store.database_path, NotificationConfig(local=True))
    box.configure()
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    before = box.status()["pending"]
    async with repo.sessions() as session:
        await session.execute(
            text(
                "INSERT INTO incident_transitions(id,incident_id,revision,dat"
                "a_json) SELECT :id,incident_id,999,json_set(data_json,'$.act"
                "ion','reopened') FROM incident_transitions LIMIT 1"
            ),
            {"id": str(uuid4())},
        )
        assert await session.scalar(text("SELECT COUNT(*) FROM deliveries")) == before + 1
        await session.rollback()
    assert box.status()["pending"] == before


async def test_same_request_is_atomic_and_replayed_once(owner):
    store, repo, _application, _ = owner
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    incident = (await repo.incidents.list())[0]
    client = ControlClient(store.home)
    request_id = uuid4()
    params = {
        "identifier": str(incident.id),
        "body": "Investigated via attached client",
        "expected_revision": incident.revision,
    }
    first = await client.call("incidents.add_note", params, request_id=request_id)
    second = await client.call("incidents.add_note", params, request_id=request_id)
    assert first == second
    assert len(await repo.incidents.notes(incident.id)) == 1
    with pytest.raises(ControlError, match="different content"):
        await client.call(
            "incidents.add_note", {**params, "body": "changed"}, request_id=request_id
        )
    async with repo.sessions() as session:
        assert (
            await session.scalar(
                text("SELECT status FROM command_receipts WHERE id=:id"), {"id": str(request_id)}
            )
            == "complete"
        )
    remote = RemoteRepository(client)
    assert (await remote.get_event((await repo.list_events())[0].id)).title == "Reachability"


async def test_failed_domain_command_does_not_leave_receipt(owner):
    store, _repo, _, _ = owner
    client = ControlClient(store.home)
    request_id = uuid4()
    with pytest.raises(ControlError):
        await client.call(
            "incidents.change_status",
            {
                "identifier": str(uuid4()),
                "status": "resolved",
                "expected_revision": 0,
                "reason": "missing",
            },
            request_id=request_id,
        )
    assert await client.call("request.get", {"identifier": str(request_id)}) == {
        "status": "not_found"
    }


async def test_control_cannot_call_arbitrary_methods_or_cross_generation(owner):
    store, _, _, _ = owner
    client = ControlClient(store.home)
    with pytest.raises(ControlError, match="Unsupported"):
        await client.call("repository.close")
    client.generation = "not-the-current-database"
    with pytest.raises(ControlError) as exc:
        await client.call("monitor.pause")
    assert exc.value.code == "recovery_required"


async def test_config_conflict_and_readonly_connection_keep_owner_running(owner):
    store, _, application, _ = owner
    client = ControlClient(store.home)
    initial = await client.call("config.get")
    changed = await client.call(
        "config.update", {"base_revision": initial["revision"], "changes": {"ping_interval": 11}}
    )
    assert changed["config"]["ping_interval"] == 11
    with pytest.raises(ControlError) as exc:
        await client.call(
            "config.update",
            {"base_revision": initial["revision"], "changes": {"ping_interval": 12}},
        )
    assert exc.value.code == "conflict"
    assert application.config.ping_interval == 11
    assert (store.home / "control.sock").stat().st_mode & 0o777 == 0o600


async def test_endpoint_change_holds_old_pending_delivery(owner):
    store, repo, _, _ = owner
    box = NotificationOutbox(
        store.database_path, NotificationConfig(webhook="https://old.example/hook")
    )
    box.configure()
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    identifier = box.pending()[0][0]
    new = NotificationOutbox(
        store.database_path, NotificationConfig(webhook="https://new.example/hook")
    )
    new.configure()
    assert new._claim(identifier) is None
    assert new.status()["held"] == 1
    new.resolve_delivery(identifier, cancel=False)
    assert new._claim(identifier) == "https://old.example/hook"


async def test_legacy_reconciliation_ignores_wrong_cursor(owner):
    store, repo, _, _ = owner
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    with sqlite3.connect(store.database_path) as db:
        db.execute("DELETE FROM notification_metadata")
        transition = db.execute("SELECT id FROM incident_transitions LIMIT 1").fetchone()[0]
    with sqlite3.connect(store.home / "notifications.db") as legacy:
        legacy.execute(
            "CREATE TABLE deliveries(id TEXT,channel TEXT,payload "
            "TEXT,attempts INTEGER,next_attempt REAL,delivered_at "
            "REAL,error TEXT)"
        )
        legacy.execute("CREATE TABLE metadata(key TEXT,value INTEGER)")
        legacy.execute("INSERT INTO metadata VALUES('transition_cursor',999999)")
    box = NotificationOutbox(store.database_path, NotificationConfig(local=True))
    box.configure()
    assert json.loads(box.pending()[0][2])["transition_id"] == transition
    box.configure()
    assert len(box.pending()) == 1


async def test_retention_one_backup_many_batches_protects_incident(owner):
    _, repo, _, _ = owner
    old = utc_now() - timedelta(days=60)
    await repo.ingest_batch(
        ProbeBatch(observations=(observation(at=old),), collected_at=old), Detector()
    )
    incident_event = (await repo.list_events())[0]
    for _ in range(3):
        await repo.ingest_batch(
            ProbeBatch(
                observations=tuple(
                    observation(loss=0, at=old, target="192.0.2.9") for _ in range(500)
                ),
                collected_at=old,
            ),
            Detector(),
        )
    service = MaintenanceService(repo)
    preview = await service.preview(30)
    assert preview["eligible"] >= 1499
    job = await service.create(30)
    await service.run(job.id)
    result = await service.get(job.id)
    assert result.status == "completed", result.error
    assert result.deleted == preview["eligible"]
    assert await repo.get_event(incident_event.id) is not None
    assert (
        len([b for b in backup_inventory(repo.database_path) if b["purpose"] == "retention"]) == 1
    )
    verify_backup(Path(result.backup))
    await service.run(job.id)
    assert (
        len([b for b in backup_inventory(repo.database_path) if b["purpose"] == "retention"]) == 1
    )


async def test_last_service_observation_survives_large_unrelated_history(owner):
    _, repo, _, _ = owner
    config = ServiceConfig(id="api", name="API", host="127.0.0.1", port=8080)

    async def check(_):
        return "available", "test measurement"

    probe = ServiceProbe(repo, check=check)
    saved = await repo.ingest_batch(await probe.collect(config), Detector())
    event = saved[0]
    # A production-shaped row-count fixture avoids 10,000 artificial probe invocations.
    with sqlite3.connect(repo.database_path) as db:
        columns = [r[1] for r in db.execute("PRAGMA table_info(events)")]
        original = list(db.execute("SELECT * FROM events WHERE id=?", (str(event.id),)).fetchone())
        rows = []
        for seq in range(2, 10002):
            row = original.copy()
            for key, value in {
                "id": str(uuid4()),
                "ingest_seq": seq,
                "service_id": None,
                "service_scope_hash": None,
                "event_type": "system.result",
                "evidence_json": "{}",
            }.items():
                row[columns.index(key)] = value
            rows.append(row)
        db.executemany(f"INSERT INTO events VALUES({','.join('?' for _ in columns)})", rows)
    assert (await repo.latest_service_observations(["api"]))["api"].id == event.id
    changed = config.model_copy(update={"timeout": 5})
    batch = await probe.collect(changed)
    assert batch.observations[0].evidence["consecutive_successes"] == 1


async def test_export_job_survives_client_disconnection(owner):
    store, repo, _, _ = owner
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    incident = (await repo.incidents.list())[0]
    job = await ControlClient(store.home).call("export.request", {"identifier": str(incident.id)})
    client = ControlClient(store.home)
    for _ in range(100):
        result = await client.call("operation.get", {"identifier": job["job_id"]})
        if result["status"] != "running":
            break
        await asyncio.sleep(0.01)
    assert result["status"] == "complete", result
    assert Path(result["result"]).is_file()


async def test_stale_notification_queue_does_not_starve_current_destination(owner):
    store, repo, _, _ = owner
    old = NotificationOutbox(store.database_path, NotificationConfig(webhook="https://old.example"))
    old.configure()
    for number in range(55):
        await repo.ingest_batch(
            ProbeBatch(observations=(observation(target=f"192.0.2.{number + 1}"),)), Detector()
        )
    new = NotificationOutbox(store.database_path, NotificationConfig(webhook="https://new.example"))
    new.configure()
    await repo.ingest_batch(
        ProbeBatch(observations=(observation(target="192.0.2.200"),)), Detector()
    )
    assert len(new.pending()) == 1
    assert new._claim(new.pending()[0][0]) == "https://new.example"


async def test_legacy_pending_webhook_needs_explicit_destination_review(owner):
    store, repo, _, _ = owner
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    with sqlite3.connect(store.database_path) as db:
        db.execute("DELETE FROM notification_metadata")
        transition = db.execute("SELECT id,data_json FROM incident_transitions LIMIT 1").fetchone()
    with sqlite3.connect(store.home / "notifications.db") as legacy:
        legacy.execute(
            "CREATE TABLE deliveries(id,channel,payload,attempts,next_attempt,delivered_at,error)"
        )
        legacy.execute(
            "INSERT INTO deliveries VALUES(?,?,?,?,?,?,?)",
            (
                transition[0] + ":webhook",
                "webhook",
                json.dumps(
                    {"transition_id": transition[0], "incident_id": "fixture", "action": "opened"}
                ),
                0,
                0,
                None,
                None,
            ),
        )
    box = NotificationOutbox(store.database_path, NotificationConfig(webhook="https://new.example"))
    box.configure()
    assert box.pending() == []
    assert box.status()["reconciliation"] == "required"
    with pytest.raises(ValueError, match="unknown"):
        box.resolve_delivery(transition[0] + ":webhook", cancel=False)
    box.reconcile(send_history=True)
    assert len(box.pending()) == 1


async def test_restore_requires_review_after_config_change(tmp_path):
    from socketclaw.maintenance import acknowledge_restore, require_reviewed_restore

    store = ConfigStore(tmp_path)
    store.save(AppConfig(targets=[]))
    repo = Repository(store.database_path)
    await repo.initialize()
    backup = recovery_backup(store.database_path, SCHEMA_VERSION)
    await repo.close()
    store.save(AppConfig(targets=["127.0.0.1"]))
    restore_database(store.database_path, backup.path, apply=True)
    with pytest.raises(RuntimeError, match="acknowledge-restore"):
        require_reviewed_restore(store.database_path)
    acknowledge_restore(store.database_path)
    require_reviewed_restore(store.database_path)


async def test_restore_journal_recovers_without_original_database(tmp_path):
    from socketclaw.maintenance import private_json, recover_restore, require_reviewed_restore

    database = tmp_path / "socketclaw.db"
    repo = Repository(database)
    await repo.initialize()
    backup = recovery_backup(database, SCHEMA_VERSION)
    await repo.close()
    database.unlink()
    private_json(tmp_path / "restore-journal.json", {"rescue": None, "backup": str(backup.path)})
    result = recover_restore(database)
    assert result["restored_backup"] == str(backup.path)
    assert not (tmp_path / "restore-journal.json").exists()
    with pytest.raises(RuntimeError, match="acknowledge-restore"):
        require_reviewed_restore(database)


async def test_cleanup_cancel_resume_reuses_verified_backup(owner):
    _, repo, _, _ = owner
    old = utc_now() - timedelta(days=60)
    await repo.ingest_batch(
        ProbeBatch(
            observations=tuple(observation(loss=0, at=old) for _ in range(1000)), collected_at=old
        ),
        Detector(),
    )
    service = MaintenanceService(repo)
    job = await service.create(30)
    await service.cancel(job.id)
    await service.run(job.id)
    cancelled = await service.get(job.id)
    assert cancelled.status == "cancelled" and cancelled.deleted == 0
    assert cancelled.backup is not None
    await service.resume(job.id)
    for _ in range(200):
        current = await service.get(job.id)
        if current.status == "completed":
            break
        await asyncio.sleep(0.01)
    assert current.status == "completed", current.error
    assert current.backup == cancelled.backup
    await service.close()


async def test_validation_error_does_not_echo_secret_input(owner):
    store, _, _, _ = owner
    sentinel = "a-secret-that-must-not-be-returned"
    with pytest.raises(ControlError) as caught:
        await ControlClient(store.home).call("investigation.request", {"event_id": sentinel})
    assert sentinel not in str(caught.value)


async def test_lost_response_replays_committed_note_without_duplication(owner):
    from socketclaw.control import read_frame, write_frame

    store, repo, _, _ = owner
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    incident = (await repo.incidents.list())[0]
    client = ControlClient(store.home)
    await client.connect()
    identifier = uuid4()
    params = {
        "identifier": str(incident.id),
        "body": "Lost response fixture",
        "expected_revision": incident.revision,
    }
    reader, writer = await asyncio.open_unix_connection(store.home / "control.sock")
    await write_frame(
        writer,
        {
            "protocol": 1,
            "request_id": str(identifier),
            "owner_session": client.session,
            "database_generation": client.generation,
            "method": "incidents.add_note",
            "params": params,
        },
    )
    response = await read_frame(reader)
    writer.close()
    await writer.wait_closed()
    # Discard the original result, as a client would after losing its response.
    repeated = await client.call("incidents.add_note", params, request_id=identifier)
    assert repeated == response["result"]
    assert len(await repo.incidents.notes(incident.id)) == 1


async def test_cross_uid_and_oversized_frames_are_rejected(owner, monkeypatch):
    import os
    import struct

    import socketclaw.control as protocol

    store, _, _, _ = owner
    monkeypatch.setattr(protocol, "peer_uid", lambda _: os.getuid() + 1)
    reader, writer = await asyncio.open_unix_connection(store.home / "control.sock")
    response = await protocol.read_frame(reader)
    assert response["error"]["code"] == "read_only"
    writer.close()
    await writer.wait_closed()
    monkeypatch.setattr(protocol, "peer_uid", lambda _: os.getuid())
    reader, writer = await asyncio.open_unix_connection(store.home / "control.sock")
    writer.write(struct.pack("!I", protocol.MAX_FRAME + 1))
    await writer.drain()
    response = await protocol.read_frame(reader)
    assert response["error"]["code"] == "validation"
    writer.close()
    await writer.wait_closed()


async def test_backup_failure_deletes_no_evidence(owner, monkeypatch):
    import socketclaw.maintenance as maintenance

    _, repo, _, _ = owner
    old = utc_now() - timedelta(days=60)
    await repo.ingest_batch(
        ProbeBatch(observations=(observation(loss=0, at=old),), collected_at=old), Detector()
    )
    service = MaintenanceService(repo)
    job = await service.create(30)
    original = await repo.list_events()

    def no_space(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(maintenance, "recovery_backup", no_space)
    await service.run(job.id)
    failed = await service.get(job.id)
    assert failed.status == "failed" and failed.deleted == 0
    assert await repo.list_events() == original


async def test_v5_upgrade_failure_is_atomic_and_retryable(tmp_path, monkeypatch):
    from contextlib import closing

    from sqlalchemy.ext.asyncio import create_async_engine

    import socketclaw.storage as storage
    from socketclaw.migrations import migrate_v4_to_v5

    database = tmp_path / "socketclaw.db"
    fixture = Path(__file__).parents[1] / "fixtures" / "schema-v4.sql"
    with closing(sqlite3.connect(database)) as db:
        db.executescript(fixture.read_text())
    engine = create_async_engine(f"sqlite+aiosqlite:///{database}")
    async with engine.begin() as conn:
        await migrate_v4_to_v5(conn)
        await conn.exec_driver_sql("UPDATE schema_meta SET value='5' WHERE key='schema_version'")
    await engine.dispose()
    with closing(sqlite3.connect(database)) as db:
        before = db.execute("SELECT id,score,evidence_json FROM events ORDER BY id").fetchall()
    original = storage.migrate_v5_to_v6

    async def fail(conn):
        await original(conn)
        raise RuntimeError("Injected interruption after outbox DDL")

    monkeypatch.setattr(storage, "migrate_v5_to_v6", fail)
    repo = Repository(database)
    with pytest.raises(RuntimeError, match="rolled back"):
        await repo.initialize()
    await repo.close()
    with closing(sqlite3.connect(database)) as db:
        assert db.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone() == ("5",)
        assert "service_id" not in [row[1] for row in db.execute("PRAGMA table_info(events)")]
    monkeypatch.setattr(storage, "migrate_v5_to_v6", original)
    repo = Repository(database)
    await repo.initialize()
    with closing(sqlite3.connect(database)) as db:
        assert (
            db.execute("SELECT id,score,evidence_json FROM events ORDER BY id").fetchall() == before
        )
    await repo.close()


async def test_owner_deduplicates_ai_and_persists_interruption(owner, monkeypatch):
    from uuid import UUID

    from socketclaw.openai import OpenAIClient

    store, repo, application, _ = owner
    store.save_api_key("fixture-never-sent")
    await repo.ingest_batch(ProbeBatch(observations=(observation(),)), Detector())
    event = (await repo.list_events())[0]
    started = asyncio.Event()
    calls = 0

    async def blocked(self, event, *, context):
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(OpenAIClient, "investigate", blocked)
    client = ControlClient(store.home)
    first = await client.call("investigation.request", {"event_id": str(event.id)})
    await asyncio.wait_for(started.wait(), 2)
    second = await ControlClient(store.home).call(
        "investigation.request", {"event_id": str(event.id)}
    )
    assert first["id"] == second["id"] and calls == 1
    # Closing/replacing a client did not cancel the paid operation.
    assert (await repo.get_investigation(UUID(first["id"]))).status == "running"
    await application.close()
    failed = await repo.get_investigation(UUID(first["id"]))
    assert failed.status == "failed" and "unknown" in failed.error
    assert "fixture-never-sent" not in failed.error


async def test_failed_configuration_rollback_exposes_unknown_runtime_state(owner):
    store, _, application, _ = owner
    original = application.config

    async def broken(_config):
        raise RuntimeError("fixture activation failure")

    application.reconfigure = broken
    with pytest.raises(ControlError):
        await ControlClient(store.home).call(
            "config.update",
            {"base_revision": application.config_revision, "changes": {"ping_interval": 7}},
        )
    assert store.load() == original
    state = await application.health()
    assert "restart" in state["configuration_error"]


async def test_cleanup_preserves_source_deduplication_after_deletion(owner):
    _, repo, _, _ = owner
    old = utc_now() - timedelta(days=60)
    event = observation(loss=0, at=old).model_copy(update={"source_key": "retention-fixture:1"})
    await repo.ingest_batch(ProbeBatch(observations=(event,), collected_at=old), Detector())
    service = MaintenanceService(repo)
    job = await service.create(30)
    await service.run(job.id)
    assert (await service.get(job.id)).deleted == 1
    assert await repo.get_event(event.id) is None
    assert await repo.ingest_batch(ProbeBatch(observations=(event,)), Detector()) == []


async def test_prune_keeps_backup_referenced_by_cancelled_cleanup(owner):
    from socketclaw.maintenance import private_json, prune_backups

    _, repo, _, _ = owner
    service = MaintenanceService(repo)
    job = await service.create(30)
    await service.cancel(job.id)
    await service.run(job.id)
    job = await service.get(job.id)
    assert job.backup is not None
    referenced = Path(job.backup)
    paths = [referenced]
    for _ in range(3):
        paths.append(recovery_backup(repo.database_path, SCHEMA_VERSION).path)
    for index, path in enumerate(paths):
        manifest = verify_backup(path)
        manifest.update(
            pinned=False, created_at=(utc_now() - timedelta(days=90 - index)).isoformat()
        )
        private_json(path.with_suffix(".json"), manifest)
    proposed = prune_backups(repo.database_path, keep_last=1, older_than_days=30)
    assert str(referenced) not in proposed and len(proposed) == 2
    deleted = prune_backups(repo.database_path, keep_last=1, older_than_days=30, apply=True)
    assert deleted == proposed
    assert referenced.is_file()
    assert all(not Path(path).exists() for path in deleted)


async def test_stalled_owner_health_is_bounded_and_explicit(owner, monkeypatch):
    import socketclaw.gateway as gateway

    store, _, _, _ = owner
    client = ControlClient(store.home)
    await client.connect()

    async def stalled(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(client, "call", stalled)
    monkeypatch.setattr(gateway, "HEALTH_TIMEOUT", 0.02)
    monitor = gateway.RemoteMonitor(client)
    await asyncio.wait_for(monitor.refresh(), 0.5)
    assert not client.connected and not monitor.status.running
    assert "unknown" in monitor.status.last_error
