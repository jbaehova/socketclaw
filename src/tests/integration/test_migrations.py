"""Real SQLite migration, recovery, read-only, and ownership contracts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import stat
import threading
from contextlib import closing
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection
from typer.testing import CliRunner

import socketclaw.storage as storage
from socketclaw.cli import _ApplicationLock, app
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.migrations import SCHEMA_VERSION, MigrationBackup
from socketclaw.storage import Repository


@pytest.fixture
def legacy(tmp_path: Path) -> Path:
    database = tmp_path / "socketclaw.db"
    sql = Path(__file__).parents[1] / "fixtures" / "schema-v1.sql"
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript(sql.read_text())
    return database


def version(database: Path) -> int:
    with closing(sqlite3.connect(database)) as connection:
        return int(
            connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()[0]
        )


def facts(database: Path) -> dict[str, tuple[list[str], list[tuple[object, ...]]]]:
    with closing(sqlite3.connect(database)) as connection:
        result = {}
        for table in ("events", "investigations", "response_proposals", "runs"):
            cursor = connection.execute(f"SELECT * FROM {table} ORDER BY id")
            result[table] = ([column[0] for column in cursor.description], cursor.fetchall())
        return result


async def test_migration_preserves_all_legacy_facts_and_verified_private_backup(
    legacy: Path,
) -> None:
    before = facts(legacy)
    repository = Repository(legacy)
    try:
        await repository.initialize()
        assert version(legacy) == SCHEMA_VERSION
        events = await repository.list_events()
        assert [item.ingest_seq for item in events] == [1]
        assert events[0].ingested_at is None
        assert events[0].source_at is None
        assert events[0].source_key is None
        assert events[0].outcome == "unknown"
        assert events[0].observed_quality == "legacy_unknown"
        assert events[0].ingest_order_origin == "legacy_reconstructed"
        for table, (columns, rows) in before.items():
            with closing(sqlite3.connect(legacy)) as connection:
                actual = connection.execute(
                    f"SELECT {', '.join(columns)} FROM {table} ORDER BY id"
                ).fetchall()
            assert actual == rows
        backup = next((legacy.parent / "backups").glob("*.db"))
        assert facts(backup) == before
        manifest = json.loads(backup.with_suffix(".json").read_text())
        assert manifest["schema_version"] == 1
        assert manifest["sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
        assert manifest["includes_private_evidence"] is True
        assert manifest["includes_api_key_file"] is False
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert stat.S_IMODE(backup.with_suffix(".json").stat().st_mode) == 0o600
        await repository.initialize()
        assert len(list((legacy.parent / "backups").glob("*.db"))) == 1
    finally:
        await repository.close()


@pytest.mark.parametrize("failure", ["ddl", "domain"])
async def test_failed_migration_rolls_back_and_can_be_retried(
    legacy: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    before = facts(legacy)
    original = storage.migrate_v1_to_v2

    async def fail(connection: AsyncConnection) -> None:
        await original(connection)
        if failure == "ddl":
            raise RuntimeError("injected DDL failure")
        await connection.exec_driver_sql("UPDATE events SET observed_at='invalid timestamp'")

    monkeypatch.setattr(storage, "migrate_v1_to_v2", fail)
    repository = Repository(legacy)
    try:
        with pytest.raises(RuntimeError, match=r"Migration rolled back\. Recovery backup:"):
            await repository.initialize()
        assert version(legacy) == 1
        assert facts(legacy) == before
        monkeypatch.setattr(storage, "migrate_v1_to_v2", original)
        await repository.initialize()
        assert version(legacy) == SCHEMA_VERSION
    finally:
        await repository.close()


async def test_backup_failure_prevents_any_schema_change(
    legacy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = facts(legacy)

    def fail(_path: Path, _version: int) -> MigrationBackup:
        raise OSError("injected disk-full error")

    monkeypatch.setattr(storage, "recovery_backup", fail)
    repository = Repository(legacy)
    try:
        with pytest.raises(OSError, match="disk-full"):
            await repository.initialize()
        assert version(legacy) == 1
        assert facts(legacy) == before
    finally:
        await repository.close()


async def test_backup_includes_committed_data_still_in_wal(legacy: Path) -> None:
    with closing(sqlite3.connect(legacy)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("UPDATE events SET title='Committed WAL evidence'")
        writer.commit()
        assert Path(f"{legacy}-wal").stat().st_size > 0
        repository = Repository(legacy)
        try:
            await repository.initialize()
        finally:
            await repository.close()
        backup = next((legacy.parent / "backups").glob("*.db"))
        with closing(sqlite3.connect(backup)) as reader:
            assert reader.execute("SELECT title FROM events").fetchone() == (
                "Committed WAL evidence",
            )


async def test_newer_schema_is_rejected_before_mutation(legacy: Path) -> None:
    with closing(sqlite3.connect(legacy)) as connection:
        connection.execute("UPDATE schema_meta SET value='999' WHERE key='schema_version'")
        connection.commit()
    before = legacy.read_bytes()
    repository = Repository(legacy)
    try:
        with pytest.raises(RuntimeError, match=r"Unsupported.*999"):
            await repository.initialize()
        assert legacy.read_bytes() == before
        assert not (legacy.parent / "backups").exists()
    finally:
        await repository.close()


@pytest.mark.parametrize("command", [["doctor"], ["export"], ["db", "status"]])
def test_read_commands_do_not_migrate_or_recover_legacy_storage(
    legacy: Path, monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(legacy.parent))
    before = facts(legacy)
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 1
    assert "needs migration" in result.output
    assert version(legacy) == 1
    assert facts(legacy) == before
    assert not (legacy.parent / "backups").exists()


def test_explicit_migration_respects_writer_ownership(
    legacy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(legacy.parent))
    lock = _ApplicationLock(legacy.parent / ".instance.lock")
    lock.acquire()
    try:
        denied = CliRunner().invoke(app, ["db", "migrate"])
        assert denied.exit_code == 1
        assert "already running" in denied.output
        assert version(legacy) == 1
    finally:
        lock.release()
    migrated = CliRunner().invoke(app, ["db", "migrate"])
    assert migrated.exit_code == 0, migrated.output
    assert f"schema {SCHEMA_VERSION} verified" in migrated.output
    assert version(legacy) == SCHEMA_VERSION


async def test_read_only_repository_cannot_write_or_initialize(tmp_path: Path) -> None:
    database = tmp_path / "path?#with-uri-characters.db"
    writer = Repository(database)
    await writer.initialize()
    await writer.close()
    reader = Repository(database, read_only=True)
    try:
        await reader.require_current_schema()
        with pytest.raises(RuntimeError, match="read-only"):
            await reader.initialize()
        async with reader._engine.connect() as connection:
            with pytest.raises(OperationalError, match="readonly"):
                await connection.execute(text("DELETE FROM schema_meta"))
    finally:
        await reader.close()


async def test_ingest_sequence_never_reuses_deleted_tail(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "db")
    await repository.initialize()
    event = SecurityEvent(source="manual", event_type="manual.test", title="Test", summary="Test")
    try:
        first = await repository.save_event(event, Detector().score(event, []))
        async with repository._engine.begin() as connection:
            await connection.execute(text("DELETE FROM events"))
        second = await repository.save_event(event, Detector().score(event, []))
        assert first.ingest_seq == 1
        assert second.ingest_seq == 2
        assert second.ingested_at is not None
    finally:
        await repository.close()


async def test_cancelled_backup_worker_finishes_before_migration_releases_ownership(
    legacy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original = storage.recovery_backup

    def delayed(path: Path, version: int) -> MigrationBackup:
        started.set()
        assert release.wait(5)
        try:
            return original(path, version)
        finally:
            finished.set()

    monkeypatch.setattr(storage, "recovery_backup", delayed)
    repository = Repository(legacy)
    task = asyncio.create_task(repository.initialize())
    try:
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
        assert version(legacy) == 1
    finally:
        release.set()
        await repository.close()


def _all_historical_facts(database: Path) -> dict[str, tuple[list[str], list[tuple]]]:
    """Freeze original column values, excluding migration bookkeeping only."""
    with closing(sqlite3.connect(database)) as connection:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            if row[0] not in {"schema_meta", "schema_migrations"}
        ]
        result = {}
        for name in names:
            cursor = connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid')
            result[name] = ([column[0] for column in cursor.description], cursor.fetchall())
        return result


def _assert_historical_facts(database: Path, before: dict) -> None:
    with closing(sqlite3.connect(database)) as connection:
        for name, (columns, rows) in before.items():
            projected = ", ".join(f'"{column}"' for column in columns)
            assert (
                connection.execute(f'SELECT {projected} FROM "{name}" ORDER BY rowid').fetchall()
                == rows
            ), name


def _clone_fixture(tmp_path: Path, schema: int) -> Path:
    """Exercise SQLite backup from a real historical schema, not a version relabel."""
    source = tmp_path / "historical-source.db"
    target = tmp_path / "socketclaw.db"
    fixture = Path(__file__).parents[1] / "fixtures" / f"schema-v{schema}.sql"
    with closing(sqlite3.connect(source)) as original:
        original.executescript(fixture.read_text())
        with closing(sqlite3.connect(target)) as clone:
            original.backup(clone)
    assert version(target) == schema
    return target


@pytest.mark.parametrize("schema", [1, 2, 3, 4])
async def test_historical_clones_backup_restart_doctor_and_export(
    tmp_path: Path, schema: int
) -> None:
    from socketclaw.config import ConfigStore
    from socketclaw.doctor import inspect_environment
    from socketclaw.export import (
        export_incident_json,
        export_incident_markdown,
        export_json,
        export_markdown,
    )

    database = _clone_fixture(tmp_path, schema)
    before = _all_historical_facts(database)
    writer = Repository(database)
    try:
        await writer.initialize()
        assert version(database) == SCHEMA_VERSION
        _assert_historical_facts(database, before)
        with closing(sqlite3.connect(database)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            assert (
                connection.execute(
                    "SELECT collected_at, committed_at, correlation_at, time_basis FROM events"
                ).fetchall()
                == [(None, None, None, "legacy_collection")] * count
            )
            assert connection.execute("SELECT COUNT(*) FROM action_records").fetchone() == (0,)
            assert connection.execute("SELECT COUNT(*) FROM retained_source_keys").fetchone() == (
                0,
            )
        backup = next((tmp_path / "backups").glob("*.db"))
        assert version(backup) == schema
        _assert_historical_facts(backup, before)
        manifest = json.loads(backup.with_suffix(".json").read_text())
        assert manifest["sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
        assert manifest["schema_version"] == schema
    finally:
        await writer.close()

    restarted = Repository(database)
    try:
        await restarted.initialize()
        assert len(list((tmp_path / "backups").glob("*.db"))) == 1
        events = await restarted.list_events()
        assert events
        for event in events:
            for renderer in (export_json, export_markdown):
                rendered = renderer(event, None)
                assert str(event.id) in rendered
            assert event.time_basis == "legacy_collection"
            assert event.collected_at is None and event.committed_at is None
        incidents = await restarted.incidents.list()
        if schema == 4:
            assert len(incidents) == 1
            report = await restarted.incident_report(incidents[0].id)
            assert report is not None
            assert report.history.notes[0].body == "Historical operator investigation"
            assert report.rule_versions
            for renderer in (export_incident_json, export_incident_markdown):
                rendered = renderer(report)
                assert str(incidents[0].id) in rendered
                assert str(events[0].id) in rendered
                assert "Historical operator investigation" in rendered
        else:
            # Migration does not reinterpret historical observations into new incidents.
            assert incidents == []
    finally:
        await restarted.close()
    doctor = await inspect_environment(ConfigStore(tmp_path), which=lambda _: None)
    assert doctor.check("SQLite database").status == "pass", doctor.render()
    _assert_historical_facts(database, before)


async def test_v4_failed_upgrade_rolls_back_ddl_and_retries_from_preserved_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _clone_fixture(tmp_path, 4)
    before = _all_historical_facts(database)
    original = storage.migrate_v4_to_v5

    async def fail(connection: AsyncConnection) -> None:
        await original(connection)
        raise RuntimeError("injected v5 failure after clock and action DDL")

    monkeypatch.setattr(storage, "migrate_v4_to_v5", fail)
    repository = Repository(database)
    try:
        with pytest.raises(RuntimeError, match="Migration rolled back"):
            await repository.initialize()
        assert version(database) == 4
        assert _all_historical_facts(database) == before
        with closing(sqlite3.connect(database)) as connection:
            assert "collected_at" not in {
                row[1] for row in connection.execute("PRAGMA table_info(events)")
            }
            assert (
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name='action_records'"
                ).fetchone()
                is None
            )
        backup = next((tmp_path / "backups").glob("*.db"))
        assert version(backup) == 4
        _assert_historical_facts(backup, before)
        monkeypatch.setattr(storage, "migrate_v4_to_v5", original)
        await repository.initialize()
        assert version(database) == SCHEMA_VERSION
        _assert_historical_facts(database, before)
    finally:
        await repository.close()
