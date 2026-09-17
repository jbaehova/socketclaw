"""Trusted collection clocks, durable policy isolation, and atomic rule evidence."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from socketclaw.collection import CheckpointChange, ProbeBatch
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.rules import RuleConfig, RulePoints
from socketclaw.storage import Repository, RuleVersionRow

NOW = datetime(2026, 9, 17, 12, tzinfo=UTC)


@pytest.fixture
async def repository(tmp_path: Path):
    result = Repository(tmp_path / "rules.db")
    await result.initialize()
    try:
        yield result
    finally:
        await result.close()


def failure(**changes) -> SecurityEvent:
    return SecurityEvent(
        source="log",
        event_type="log.auth_failure",
        title="Failed authentication",
        summary="Failed authentication",
        target="192.0.2.1",
        **changes,
    )


async def ingest(repository, events, *, at=NOW, rules=None):
    return await repository.ingest_batch(
        ProbeBatch(observations=tuple(events), collected_at=at), Detector(rules)
    )


async def test_untrusted_observation_clocks_do_not_change_the_collection_window(repository):
    events = [
        failure(
            observed_at=NOW + timedelta(days=offset),
            source_at=NOW - timedelta(days=offset),
            ingested_at=NOW + timedelta(days=100),
        )
        for offset in range(6)
    ]
    rows = await ingest(repository, events)
    assert rows[-1].score == 100
    assert {row.ingested_at for row in rows} == {NOW}
    assert rows[-1].observed_at == events[-1].observed_at
    assert rows[-1].source_at == events[-1].source_at
    version = await repository.get_rule_version(rows[-1].rule_version)
    assert version is not None
    assert json.loads(version.snapshot_json)["config"] == RuleConfig().model_dump()
    assert len({row.rule_version for row in rows}) == 1


@pytest.mark.parametrize("offset,expected", [(300, 100), (300.000001, 25), (-0.000001, 25)])
async def test_collection_window_has_exact_inclusive_boundaries(repository, offset, expected):
    await ingest(repository, [failure() for _ in range(5)], at=NOW - timedelta(seconds=offset))
    result = (await ingest(repository, [failure()]))[0]
    assert result.score == expected


async def test_changed_policy_does_not_reuse_old_counts_even_when_reverted(repository):
    original = await ingest(repository, [failure() for _ in range(5)])
    changed = RuleConfig(auth_failure_count=2)
    new = await ingest(repository, [failure()], rules=changed)
    assert new[0].score == 25
    assert new[0].rule_version != original[0].rule_version
    assert (await ingest(repository, [failure()], rules=changed))[0].score == 100
    reverted = (await ingest(repository, [failure()]))[0]
    assert reverted.score == 25
    assert reverted.rule_version not in {new[0].rule_version, original[0].rule_version}
    assert (await repository.get_event(original[0].id)).score == original[0].score


async def test_restart_reuses_the_same_committed_version_and_window(repository):
    first = await ingest(repository, [failure() for _ in range(5)])
    await repository.close()
    reopened = Repository(repository.database_path)
    try:
        await reopened.initialize()
        last = (await ingest(reopened, [failure()]))[0]
        assert last.score == 100
        assert last.rule_version == first[0].rule_version
    finally:
        await reopened.close()


async def test_failed_rule_batch_rolls_back_activation_and_retry_keeps_collection_time(repository):
    config = RuleConfig(auth_failure_count=2, points=RulePoints(log_auth_failure=10))
    event = failure()
    invalid = CheckpointChange(
        probe_id="synthetic", expected_revision=0, state={"too_large": "x" * 70000}
    )
    batch = ProbeBatch(observations=(event,), checkpoints=(invalid,), collected_at=NOW)
    with pytest.raises(ValueError, match="64 KiB"):
        await repository.ingest_batch(batch, Detector(config))
    async with repository._sessions() as session:
        assert await session.scalar(select(func.count()).select_from(RuleVersionRow)) == 0
    fixed = batch.model_copy(update={"checkpoints": ()})
    row = (await repository.ingest_batch(fixed, Detector(config)))[0]
    assert row.ingested_at == NOW
    assert row.score == 10
    assert await repository.ingest_batch(fixed, Detector()) == []
    assert (await repository.get_rule_version(row.rule_version)).fingerprint == config.fingerprint


async def test_source_key_replay_does_not_count_or_activate_an_unused_policy(repository):
    first = (await ingest(repository, [failure(source_key="one")]))[0]
    assert (
        await ingest(
            repository, [failure(source_key="one")], rules=RuleConfig(auth_failure_count=2)
        )
        == []
    )
    second = (await ingest(repository, [failure()]))[0]
    assert first.rule_version == second.rule_version
    async with repository._sessions() as session:
        assert await session.scalar(select(func.count()).select_from(RuleVersionRow)) == 1


async def test_v2_upgrade_preserves_unknown_rule_provenance(tmp_path: Path):
    path = tmp_path / "v2.db"
    with sqlite3.connect(path) as connection:
        connection.executescript((Path(__file__).parents[1] / "fixtures/schema-v2.sql").read_text())
        before = connection.execute("SELECT * FROM events").fetchall()
        columns = [column[1] for column in connection.execute("PRAGMA table_info(events)")]
    repository = Repository(path)
    try:
        await repository.initialize()
        assert (await repository.database_info()).schema_version == 4
        assert (await repository.list_events())[0].rule_version is None
        with sqlite3.connect(path) as connection:
            assert (
                connection.execute(f"SELECT {', '.join(columns)} FROM events").fetchall() == before
            )
        backups = list((tmp_path / "backups").glob("*.json"))
        assert len(backups) == 1
        assert json.loads(backups[0].read_text())["schema_version"] == 2
    finally:
        await repository.close()


async def test_v2_migration_failure_rolls_back_and_retry_preserves_rows(tmp_path, monkeypatch):
    import socketclaw.storage as storage

    path = tmp_path / "v2.db"
    with sqlite3.connect(path) as connection:
        connection.executescript((Path(__file__).parents[1] / "fixtures/schema-v2.sql").read_text())
    original = storage.migrate_v2_to_v3

    async def fail(connection):
        await original(connection)
        raise RuntimeError("synthetic v3 migration failure")

    monkeypatch.setattr(storage, "migrate_v2_to_v3", fail)
    repository = Repository(path)
    try:
        with pytest.raises(RuntimeError, match="Migration rolled back"):
            await repository.initialize()
        with sqlite3.connect(path) as connection:
            assert connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone() == ("2",)
            assert "rule_version" not in [
                row[1] for row in connection.execute("PRAGMA table_info(events)")
            ]
        monkeypatch.setattr(storage, "migrate_v2_to_v3", original)
        await repository.initialize()
        assert (await repository.database_info()).schema_version == 4
    finally:
        await repository.close()


async def test_diagnostic_rejects_corrupted_rule_snapshot(repository):
    from sqlalchemy import update

    await ingest(repository, [failure()])
    async with repository._engine.begin() as connection:
        await connection.execute(update(RuleVersionRow).values(snapshot_json="{}"))
    with pytest.raises(RuntimeError, match="invalid rule version"):
        await repository.database_info()


async def test_planner_activates_rules_without_changing_probe_configuration(repository):
    from socketclaw.cli import _build_monitor, _monitoring_settings, _ProbePlanner
    from socketclaw.config import AppConfig

    original = AppConfig()
    revised = AppConfig(rules=RuleConfig(auth_failure_count=2))
    assert _monitoring_settings(original) != _monitoring_settings(revised)
    planner = _ProbePlanner(repository=repository, which=lambda _: None)
    monitor = _build_monitor(original, repository, planner=planner)
    await monitor.process_event(failure())
    await planner.activate(monitor, planner.prepare(revised))
    assert (await monitor.process_event(failure())).score == 25
    assert (await monitor.process_event(failure())).score == 100


async def test_unversioned_imports_cannot_supply_counts_to_current_rules(repository):
    detector = Detector()
    for _ in range(5):
        event = failure(ingested_at=NOW)
        await repository.save_event(event, detector.score(event, []))
    row = (await ingest(repository, [failure()]))[0]
    assert row.score == 25
    assert row.rule_version is not None
