"""Cross-feature guarantees for explicit clocks, action history and retention."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from socketclaw.collection import ProbeBatch
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.response_actions import ActionRecord
from socketclaw.storage import EventQuery, Repository

NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)


@pytest.fixture
async def repo(tmp_path):
    repository = Repository(tmp_path / "home" / "socketclaw.db")
    await repository.initialize()
    yield repository
    await repository.close()


def auth(at, *, user="alice", actor="192.0.2.9", success=False):
    return SecurityEvent(
        source="log",
        event_type="log.auth_success" if success else "log.auth_failure",
        title="Authentication observation",
        summary="Accepted password" if success else "Failed password",
        source_at=at,
        observed_at=NOW,
        target="server-a",
        evidence={
            "asset": "server-a",
            "user": user,
            "actor_ip": actor,
            "source_ip": actor,
            "message": "Accepted password" if success else "Failed password",
            "source_time_quality": "explicit_timezone",
            "auth_failure_count": 0 if success else 1,
        },
    )


async def ingest(repo, events, at=NOW):
    return await repo.ingest_batch(
        ProbeBatch(observations=tuple(events), collected_at=at), Detector()
    )


async def test_explicit_clocks_backlog_and_reversed_restart(repo):
    spaced = [auth(NOW - timedelta(hours=i + 1)) for i in range(6)]
    saved = await ingest(repo, spaced)
    assert max(e.score for e in saved) < 90
    assert all(
        e.time_basis == "delayed_source" and e.collected_at == NOW and e.committed_at for e in saved
    )
    assert all(e.ingested_at == NOW for e in saved)
    burst = [auth(NOW - timedelta(seconds=i * 20), user="bob") for i in range(6)]
    first = await ingest(repo, burst[:3])
    second = await ingest(repo, burst[3:])
    assert max(e.score for e in first + second) == 100
    future = auth(NOW + timedelta(days=1))
    future_saved = (await ingest(repo, [future]))[0]
    assert future_saved.time_basis == "future_source_fallback"
    assert future_saved.correlation_at == NOW


async def test_note_idempotency_operator_conflict_and_success_context(repo):
    await ingest(repo, [auth(NOW - timedelta(seconds=60))])
    incident = (await repo.incidents.list())[0]
    await ingest(repo, [auth(NOW - timedelta(seconds=i)) for i in range(10)])
    identifier = uuid4()
    first = await repo.incidents.add_note(
        incident.id, "Kept my draft", expected_revision=incident.revision, note_id=identifier
    )
    repeated = await repo.incidents.add_note(
        incident.id, "Kept my draft", expected_revision=incident.revision, note_id=identifier
    )
    assert first == repeated
    assert len(await repo.incidents.notes(incident.id)) == 1
    updated = await repo.incidents.change_status(
        incident.id, "acknowledged", expected_revision=incident.revision, reason="reviewed", at=NOW
    )
    with pytest.raises(ValueError, match="operator state changed"):
        await repo.incidents.change_status(
            incident.id, "resolved", expected_revision=incident.revision, reason="stale", at=NOW
        )
    success = (await ingest(repo, [auth(NOW, success=True)]))[0]
    unrelated = (await ingest(repo, [auth(NOW, user="unrelated", success=True)]))[0]
    report = await repo.incident_report(incident.id)
    assert report and success.id in {e.id for e in report.observations}
    assert unrelated.id not in {e.id for e in report.observations}
    assert report.history.incident.status == updated.status
    await repo.database_info()


async def test_service_recovery_attention_and_action_provenance(repo):
    def service(kind, at):
        return SecurityEvent(
            source="system",
            event_type="service." + kind,
            observed_at=at,
            target="localhost",
            title="Required web service",
            summary="endpoint check",
            evidence={
                "service_id": "web",
                "confirmed": True,
                "required": True,
                "status": "available" if kind == "available" else "closed",
            },
        )

    failed = (await ingest(repo, [service("failed", NOW)]))[0]
    report = await repo.incident_report_for_event(failed.id)
    assert report and (await repo.session_stats()).attention_incidents == 1
    action = ActionRecord(
        incident_id=report.history.incident.id,
        status="user_performed",
        summary="Restarted web",
        created_at=NOW + timedelta(seconds=1),
    )
    await repo.record_action(action)
    recovery = (
        await ingest(
            repo, [service("available", NOW + timedelta(seconds=2))], NOW + timedelta(seconds=2)
        )
    )[0]
    verification = ActionRecord(
        incident_id=action.incident_id,
        status="verified",
        summary="TCP recovered",
        evidence_ids=(recovery.id,),
        created_at=NOW + timedelta(seconds=3),
    )
    await repo.record_action(verification)
    report = await repo.incident_report(action.incident_id)
    assert report and len(report.action_records) == 2
    assert any(link.kind == "observed_recovery" for link in report.history.links)
    await repo.incidents.change_status(
        action.incident_id,
        "resolved",
        expected_revision=report.history.incident.revision,
        reason="verified",
        at=NOW + timedelta(seconds=4),
    )
    assert (await repo.session_stats()).attention_incidents == 0
    await repo.database_info()


async def test_retention_preserves_dedup_and_incident_evidence(repo):
    old = NOW - timedelta(days=91)
    event = SecurityEvent(
        source="ping",
        event_type="ping.result",
        observed_at=old,
        target="localhost",
        title="healthy",
        summary="normal",
        source_key="retained-example",
        evidence={"packet_loss": 0},
    )
    await ingest(repo, [event], old)
    anomaly = auth(old)
    await ingest(repo, [anomaly], old)
    preview = await repo.retain_history(now=NOW)
    assert preview.eligible_events == 1 and preview.deleted_events == 0
    applied = await repo.retain_history(now=NOW, dry_run=False)
    assert applied.deleted_events == 1 and applied.backup_path
    assert await ingest(repo, [event], old) == []
    assert await repo.get_event(anomaly.id)
    assert (await repo.load_checkpoint("unconfigured")).expected_revision == 0
    await repo.database_info()


async def test_cursor_search_reaches_old_history_and_is_stable(repo):
    observations = [
        SecurityEvent(
            source="manual",
            event_type="manual.fact",
            title=f"row {i}",
            summary="old searchable" if i == 0 else "other",
            observed_at=NOW,
        )
        for i in range(510)
    ]
    await ingest(repo, observations)
    found = await repo.list_events(EventQuery(text="old searchable"))
    assert len(found) == 1 and found[0].id == observations[0].id
    first = await repo.list_events(EventQuery(limit=100))
    await ingest(
        repo, [SecurityEvent(source="manual", event_type="manual.fact", title="new", summary="new")]
    )
    second = await repo.list_events(
        EventQuery(limit=100, watermark=first[0].ingest_seq, before_seq=first[-1].ingest_seq)
    )
    assert not {e.id for e in first} & {e.id for e in second}
    assert second[0].ingest_seq == first[-1].ingest_seq - 1


async def test_max_ports_with_process_evidence_and_binding_repair(repo):
    ports = list(range(64000, 65024))
    event = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        title="Full allowed port scope",
        summary="Measured process context",
        target="127.0.0.1",
        evidence={
            "scanned_ports": ports,
            "open_ports": ports,
            "newly_opened": ports,
            "newly_closed": [],
            "local_listeners": [
                {
                    "port": port,
                    "binding_address": "*",
                    "pid": 12,
                    "process": "python",
                    "path": "/usr/bin/python",
                }
                for port in ports
            ],
        },
    )
    saved = (await ingest(repo, [event]))[0]
    assert len(saved.evidence["newly_opened"]) == 1024
    # Full-list preservation also holds on the inverse transition.
    closed = event.model_copy(
        update={
            "id": uuid4(),
            "evidence": {
                "scanned_ports": ports,
                "open_ports": [],
                "newly_opened": [],
                "newly_closed": ports,
            },
        }
    )
    assert len((await ingest(repo, [closed]))[0].evidence["newly_closed"]) == 1024
    violation = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        title="Wrong binding",
        summary="Wildcard instead of loopback",
        target="localhost",
        evidence={
            "scanned_ports": [8088],
            "open_ports": [8088],
            "exposure_violations": [
                {"port": 8088, "binding_address": "*", "allowed_exposure": "loopback"}
            ],
            "exposure_violation_ports": [8088],
        },
    )
    anomaly = (await ingest(repo, [violation]))[0]
    report = await repo.incident_report_for_event(anomaly.id)
    assert report
    fixed = violation.model_copy(
        update={
            "id": uuid4(),
            "evidence": {
                "scanned_ports": [8088],
                "open_ports": [8088],
                "exposure_violations": [],
                "exposure_violation_ports": [],
                "exposure_checked_ports": [8088],
                "local_context_status": "observed",
            },
        }
    )
    await ingest(repo, [fixed], NOW + timedelta(seconds=1))
    assert (await repo.incidents.occurrences(report.history.incident.id))[-1].recovered_at


async def test_typed_log_failure_and_job_failure_share_recoverable_incident(repo):
    import time

    from socketclaw.health import ProbeHealthSignal
    from socketclaw.monitor import MonitorService, ProbeJob

    async def denied():
        return ProbeBatch(
            observations=(
                SecurityEvent(
                    source="system",
                    event_type="system.log_probe_error",
                    title="Cannot read file",
                    summary="permission denied",
                    evidence={"path": "/tmp/auth.log", "error": "permission denied"},
                ),
            ),
            health=(
                ProbeHealthSignal(
                    probe_id="log:source",
                    state="degraded",
                    error_kind="read_error",
                    detail="denied",
                ),
            ),
        )

    async def healthy():
        return ProbeBatch(health=(ProbeHealthSignal(probe_id="log:source", state="healthy"),))

    monitor = MonitorService(repo, Detector(), jobs=[])
    await monitor._execute_job(ProbeJob("logs", 1, denied), due=time.monotonic())
    await monitor._execute_job(ProbeJob("logs", 1, healthy), due=time.monotonic())
    incidents = await repo.incidents.list()
    assert len(incidents) == 1
    assert (await repo.incidents.occurrences(incidents[0].id))[-1].recovered_at


async def test_response_targets_actor_without_falling_back_to_structured_asset(repo):
    from socketclaw.domain import Assessment, InvestigationResult, ModelUsage, ResponseProposal
    from socketclaw.openai import _validate_assessment_target

    def result(target):
        return InvestigationResult(
            model_id="fixture",
            requested_effort="medium",
            usage=ModelUsage(),
            assessment=Assessment(
                classification="suspicious",
                confidence=0.7,
                summary="review",
                rationale=("observed actor",),
                response_proposal=ResponseProposal(
                    action="block", target_ip=target, reason="review"
                ),
            ),
        )

    event = auth(NOW, actor="10.0.0.9").model_copy(update={"target": "10.0.0.2"})
    event = (await ingest(repo, [event]))[0]
    _validate_assessment_target(result("10.0.0.9").assessment, event)
    queued = await repo.queue_investigation(event.id, model_id="fixture", requested_effort="medium")
    await repo.start_investigation(queued.id)
    await repo.complete_investigation(queued.id, result("10.0.0.9"))
    proposal = (await repo.list_response_proposals(event_id=event.id))[0]
    await repo.update_response_proposal_status(
        proposal.id, "approved", expected_status="pending", protected_targets=("10.0.0.2",)
    )
    unknown = event.model_copy(
        update={"evidence": {"asset": "10.0.0.2", "actor_ip": None, "source_ip": None}}
    )
    with pytest.raises(ValueError, match="no corresponding"):
        _validate_assessment_target(result("10.0.0.2").assessment, unknown)


async def test_small_future_source_skew_cannot_hide_or_block_an_incident(repo):
    event = auth(NOW + timedelta(seconds=30))
    saved = (await ingest(repo, [event]))[0]
    assert saved.correlation_at == NOW
    assert saved.time_basis == "future_source_fallback"
    incident = (await repo.incidents.list(through=NOW))[0]
    await repo.incidents.change_status(
        incident.id,
        "acknowledged",
        expected_revision=incident.revision,
        reason="Review current evidence",
        at=NOW,
    )
