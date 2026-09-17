"""Incident lifetime is durable and never mutates the underlying observations."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError

from socketclaw.collection import CheckpointChange, ProbeBatch
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.incidents import SuppressionRule
from socketclaw.storage import EventRow, Repository

NOW = datetime(2026, 9, 17, 12, tzinfo=UTC)


@pytest.fixture
async def repository(tmp_path):
    result = Repository(tmp_path / "incidents.db")
    await result.initialize()
    try:
        yield result
    finally:
        await result.close()


def ping(loss=100, **changes):
    return SecurityEvent(
        source="ping",
        event_type="ping.result",
        target="192.0.2.1",
        title="Ping",
        summary="Measured ping",
        evidence={"packet_loss": loss, "outcome": "ok"},
        **changes,
    )


def auth(**changes):
    return SecurityEvent(
        source="log",
        event_type="log.auth_failure",
        target="192.0.2.1",
        title="Authentication",
        summary="Failed authentication",
        **changes,
    )


async def ingest(repository, *events, at=NOW):
    return await repository.ingest_batch(
        ProbeBatch(collected_at=at, observations=events), Detector()
    )


async def test_repeated_anomalies_and_replay_group_atomically(repository):
    batch = ProbeBatch(
        collected_at=NOW, observations=tuple(auth(source_key=str(i)) for i in range(6))
    )
    saved = await repository.ingest_batch(batch, Detector())
    assert saved[-1].score == 100
    incidents = await repository.incidents.list()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.observation_count == 6
    assert incident.occurrence_count == 1
    assert incident.highest_score == 100
    assert len(await repository.incidents.links(incident.id)) == 6
    assert await repository.ingest_batch(batch, Detector()) == []
    assert (
        await repository.ingest_batch(ProbeBatch(observations=batch.observations), Detector()) == []
    )
    assert await repository.incidents.get(incident.id) == incident
    await repository.database_info()


async def test_acknowledge_note_resolve_and_recur_preserve_observations(repository):
    original = (await ingest(repository, auth()))[0]
    incident = (await repository.incidents.list())[0]
    acknowledged = await repository.incidents.change_status(
        incident.id,
        "acknowledged",
        expected_revision=incident.revision,
        reason="Triaged",
        at=NOW + timedelta(seconds=1),
    )
    note = await repository.incidents.add_note(
        incident.id, "Investigating account", expected_revision=acknowledged.revision
    )
    current = await repository.incidents.get(incident.id)
    corrected = await repository.incidents.add_note(
        incident.id, "Account confirmed", expected_revision=current.revision, supersedes_id=note.id
    )
    current = await repository.incidents.get(incident.id)
    resolved = await repository.incidents.change_status(
        incident.id,
        "resolved",
        expected_revision=current.revision,
        reason="Credentials rotated",
        at=NOW + timedelta(seconds=2),
    )
    await ingest(repository, auth(), at=NOW + timedelta(seconds=3))
    reopened = await repository.incidents.get(incident.id)
    assert reopened.status == "open"
    assert reopened.occurrence_count == 2
    assert reopened.last_reopened_at == NOW + timedelta(seconds=3)
    assert [item.action for item in await repository.incidents.transitions(incident.id)] == [
        "opened",
        "acknowledged",
        "resolved",
        "reopened",
    ]
    assert [item.id for item in await repository.incidents.notes(incident.id)] == [
        note.id,
        corrected.id,
    ]
    assert (await repository.get_event(original.id)) == original
    assert resolved.status == "resolved"


async def test_recovery_is_evidence_not_operator_resolution(repository):
    await ingest(repository, ping())
    incident = (await repository.incidents.list())[0]
    await ingest(repository, ping(0), at=NOW + timedelta(seconds=1))
    recovered = await repository.incidents.get(incident.id)
    assert recovered.status == "open"
    assert recovered.observation_count == 1
    assert (await repository.incidents.occurrences(incident.id))[0].recovered_at == NOW + timedelta(
        seconds=1
    )
    assert [item.kind for item in await repository.incidents.links(incident.id)].count(
        "observed_recovery"
    ) == 1
    await ingest(repository, ping(), at=NOW + timedelta(seconds=2))
    recurred = await repository.incidents.get(incident.id)
    assert recurred.status == "open"
    assert recurred.occurrence_count == 2
    assert (await repository.incidents.transitions(incident.id))[-1].action == "recurred"


async def test_unknown_measurements_and_scope_removal_do_not_claim_recovery(repository):
    event = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        target="server",
        title="Open SSH",
        summary="SSH exposed",
        evidence={
            "initial_open_ports": [22],
            "open_ports": [22],
            "scanned_ports": [22],
            "outcome": "ok",
        },
    )
    await ingest(repository, event)
    incident = (await repository.incidents.list())[0]
    for index, evidence in enumerate(
        (
            {"scanned_ports": [443], "open_ports": [], "unresolved_ports": [], "outcome": "ok"},
            {
                "scanned_ports": [22],
                "open_ports": [],
                "unresolved_ports": [22],
                "outcome": "unknown",
            },
        ),
        1,
    ):
        await ingest(
            repository,
            event.model_copy(update={"id": uuid4(), "evidence": evidence}),
            at=NOW + timedelta(seconds=index),
        )
    assert (await repository.incidents.occurrences(incident.id))[0].recovered_at is None
    closed = event.model_copy(
        update={
            "id": uuid4(),
            "evidence": {
                "scanned_ports": [22],
                "open_ports": [],
                "unresolved_ports": [],
                "outcome": "ok",
            },
        }
    )
    await ingest(repository, closed, at=NOW + timedelta(seconds=3))
    assert (await repository.incidents.occurrences(incident.id))[0].recovered_at is not None


async def test_normal_observations_do_not_create_incidents(repository):
    await ingest(repository, ping(0))
    assert await repository.incidents.list() == []


async def test_long_gap_creates_linked_incident_without_erasing_old_notes(repository):
    await ingest(repository, auth())
    first = (await repository.incidents.list())[0]
    await repository.incidents.change_status(
        first.id,
        "resolved",
        expected_revision=first.revision,
        reason="Resolved",
        at=NOW + timedelta(seconds=1),
    )
    await ingest(repository, auth(), at=NOW + timedelta(days=2))
    latest = (await repository.incidents.list())[0]
    assert latest.id != first.id
    assert latest.previous_incident_id == first.id
    assert (await repository.incidents.get(first.id)).status == "resolved"


async def test_delayed_pre_resolution_batch_does_not_reopen_incident(repository):
    await ingest(repository, auth())
    first = (await repository.incidents.list())[0]
    await repository.incidents.change_status(
        first.id,
        "resolved",
        expected_revision=first.revision,
        reason="Resolved",
        at=NOW + timedelta(seconds=10),
    )
    await ingest(repository, auth(), at=NOW + timedelta(seconds=5))
    current = await repository.incidents.get(first.id)
    assert current.status == "resolved"
    assert current.occurrence_count == 1
    assert current.observation_count == 2


async def test_manual_reopen_does_not_invent_an_observation(repository):
    await ingest(repository, auth())
    first = (await repository.incidents.list())[0]
    resolved = await repository.incidents.change_status(
        first.id,
        "resolved",
        expected_revision=first.revision,
        reason="Resolved",
        at=NOW + timedelta(seconds=1),
    )
    reopened = await repository.incidents.change_status(
        first.id,
        "open",
        expected_revision=resolved.revision,
        reason="Review again",
        at=NOW + timedelta(seconds=2),
    )
    assert reopened.observation_count == 1
    latest = (await repository.incidents.occurrences(first.id))[-1]
    assert latest.observation_count == 0
    assert latest.last_seen_at is None
    await ingest(repository, auth(), at=NOW + timedelta(seconds=3))
    assert (await repository.incidents.get(first.id)).occurrence_count == 2


async def test_stale_revision_and_empty_reason_cannot_mutate_state(repository):
    await ingest(repository, auth())
    incident = (await repository.incidents.list())[0]
    with pytest.raises(ValueError):
        await repository.incidents.change_status(
            incident.id,
            "resolved",
            expected_revision=incident.revision,
            reason="  ",
            at=NOW + timedelta(seconds=1),
        )
    assert await repository.incidents.get(incident.id) == incident
    results = await asyncio.gather(
        *[
            repository.incidents.change_status(
                incident.id,
                "acknowledged",
                expected_revision=incident.revision,
                reason="Triaged",
                at=NOW + timedelta(seconds=1),
            )
            for _ in range(2)
        ],
        return_exceptions=True,
    )
    assert sum(isinstance(result, ValueError) for result in results) == 1


async def test_failed_batch_rolls_back_incident_history(repository):
    batch = ProbeBatch(
        collected_at=NOW,
        observations=(auth(),),
        checkpoints=(
            CheckpointChange(probe_id="bad", expected_revision=0, state={"too_big": "x" * 70000}),
        ),
    )
    with pytest.raises(ValueError, match="64 KiB"):
        await repository.ingest_batch(batch, Detector())
    assert await repository.incidents.list() == []
    assert await repository.list_events() == []
    await repository.ingest_batch(batch.model_copy(update={"checkpoints": ()}), Detector())
    assert (await repository.incidents.list())[0].observation_count == 1


async def test_suppression_expires_without_changing_original_detection(repository):
    rule = SuppressionRule(
        family="authentication",
        target="192.0.2.1",
        starts_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        reason="Maintenance",
    )
    await repository.incidents.create_suppression(rule)
    suppressed = await ingest(repository, *[auth() for _ in range(6)])
    assert suppressed[-1].score == 100
    assert await repository.incidents.list() == []
    decisions = await repository.incidents.suppression_decisions(suppressed[-1].id)
    assert decisions[0].reason == "Maintenance"
    assert decisions[0].expires_at == rule.expires_at
    assert set(decisions[0].rule_codes) == {"log.auth_failure", "log.auth_burst"}
    await ingest(repository, auth(), at=rule.expires_at)
    assert len(await repository.incidents.list()) == 1
    assert (await repository.get_event(suppressed[-1].id)) == suppressed[-1]


async def test_rule_specific_suppression_retains_other_signal_and_audit_after_disable(repository):
    rule = SuppressionRule(
        rule_code="log.auth_burst",
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        reason="Known login exercise",
    )
    await repository.incidents.create_suppression(rule)
    events = await ingest(repository, *[auth() for _ in range(6)])
    incident = (await repository.incidents.list())[0]
    assert incident.highest_score == 25
    assert events[-1].score == 100
    await repository.incidents.disable_suppression(rule.id, "Exercise complete")
    assert (await repository.incidents.suppression_decisions(events[-1].id))[
        0
    ].reason == rule.reason
    await ingest(repository, auth(), at=NOW + timedelta(seconds=1))
    assert (await repository.incidents.get(incident.id)).highest_score == 100


async def test_incident_evidence_cannot_be_cascade_deleted(repository):
    event = (await ingest(repository, auth()))[0]
    with pytest.raises(IntegrityError):
        async with repository._engine.begin() as connection:
            await connection.execute(delete(EventRow).where(EventRow.id == str(event.id)))
    assert await repository.get_event(event.id) == event


async def test_restart_retains_incident_state_and_notes(repository):
    await ingest(repository, auth())
    incident = (await repository.incidents.list())[0]
    await repository.incidents.add_note(
        incident.id, "Persistent note", expected_revision=incident.revision
    )
    await repository.close()
    reopened = Repository(repository.database_path)
    try:
        await reopened.initialize()
        await ingest(reopened, auth(), at=NOW + timedelta(seconds=1))
        assert (await reopened.incidents.get(incident.id)).observation_count == 2
        assert (await reopened.incidents.notes(incident.id))[0].body == "Persistent note"
    finally:
        await reopened.close()


async def test_v3_migration_preserves_rule_and_event_history(tmp_path):
    path = tmp_path / "v3.db"
    with sqlite3.connect(path) as connection:
        connection.executescript((Path(__file__).parents[1] / "fixtures/schema-v3.sql").read_text())
        before = connection.execute("SELECT * FROM events").fetchall()
    repository = Repository(path)
    try:
        await repository.initialize()
        assert (await repository.database_info()).schema_version == 4
        assert await repository.incidents.list() == []
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT * FROM events").fetchall() == before
        manifest = next((tmp_path / "backups").glob("*.json"))
        assert json.loads(manifest.read_text())["schema_version"] == 3
    finally:
        await repository.close()


async def test_late_batch_links_to_old_incident_after_long_gap_split(repository):
    await ingest(repository, auth())
    old = (await repository.incidents.list())[0]
    await repository.incidents.change_status(
        old.id,
        "resolved",
        expected_revision=old.revision,
        reason="Resolved",
        at=NOW + timedelta(seconds=10),
    )
    await ingest(repository, auth(), at=NOW + timedelta(days=2))
    latest = (await repository.incidents.list())[0]
    await ingest(repository, auth(), at=NOW + timedelta(seconds=5))
    assert (await repository.incidents.get(old.id)).observation_count == 2
    assert (await repository.incidents.get(old.id)).status == "resolved"
    assert (await repository.incidents.get(latest.id)).observation_count == 1
    await repository.database_info()


async def test_late_evidence_does_not_erase_a_recorded_recovery(repository):
    await ingest(repository, ping())
    first = (await repository.incidents.list())[0]
    await ingest(repository, ping(0), at=NOW + timedelta(seconds=5))
    current = await repository.incidents.get(first.id)
    await repository.incidents.change_status(
        first.id,
        "resolved",
        expected_revision=current.revision,
        reason="Verified",
        at=NOW + timedelta(seconds=10),
    )
    await ingest(repository, ping(), at=NOW + timedelta(seconds=7))
    current = await repository.incidents.get(first.id)
    assert current.status == "resolved"
    assert (await repository.incidents.occurrences(first.id))[0].recovered_at == NOW + timedelta(
        seconds=5
    )
    await repository.database_info()


async def test_cross_incident_note_correction_is_rejected(repository):
    await ingest(repository, auth(), ping())
    first, second = await repository.incidents.list()
    note = await repository.incidents.add_note(
        first.id, "Original", expected_revision=first.revision
    )
    with pytest.raises(ValueError, match="same incident"):
        await repository.incidents.add_note(
            second.id, "Wrong target", expected_revision=second.revision, supersedes_id=note.id
        )
    assert await repository.incidents.notes(second.id) == []


async def test_v3_upgrade_failure_rolls_back_and_retry_keeps_facts(tmp_path, monkeypatch):
    import socketclaw.storage as storage

    path = tmp_path / "v3.db"
    with sqlite3.connect(path) as connection:
        connection.executescript((Path(__file__).parents[1] / "fixtures/schema-v3.sql").read_text())
        before = connection.execute("SELECT * FROM events").fetchall()
        versions = connection.execute("SELECT * FROM rule_versions").fetchall()
    original = storage.migrate_v3_to_v4

    async def fail(connection):
        await original(connection)
        raise RuntimeError("synthetic incident migration failure")

    monkeypatch.setattr(storage, "migrate_v3_to_v4", fail)
    repository = Repository(path)
    try:
        with pytest.raises(RuntimeError, match="Migration rolled back"):
            await repository.initialize()
        with sqlite3.connect(path) as connection:
            assert connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone() == ("3",)
            assert (
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name='incidents'"
                ).fetchone()
                is None
            )
        monkeypatch.setattr(storage, "migrate_v3_to_v4", original)
        await repository.initialize()
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT * FROM events").fetchall() == before
            assert connection.execute("SELECT * FROM rule_versions").fetchall() == versions
    finally:
        await repository.close()


async def test_doctor_rejects_incident_projection_mismatch(repository):
    from sqlalchemy import update

    from socketclaw.incident_store import IncidentRow

    await ingest(repository, auth())
    async with repository._engine.begin() as connection:
        await connection.execute(update(IncidentRow).values(revision=999))
    with pytest.raises(RuntimeError, match="invalid incident history"):
        await repository.database_info()
