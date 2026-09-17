from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from socketclaw.domain import (
    Assessment,
    DetectionResult,
    DetectionSignal,
    InvestigationResult,
    ModelUsage,
    ResponseProposal,
    SecurityEvent,
    Severity,
)
from socketclaw.storage import EventQuery, Repository, StoredInvestigation

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def event_fixture(
    *,
    source: str = "ping",
    severity: Severity = Severity.HIGH,
    target: str = "1.1.1.1",
    title: str = "Target stopped responding",
    observed_at: datetime = NOW,
) -> SecurityEvent:
    return SecurityEvent(
        observed_at=observed_at,
        source=source,
        event_type=f"{source}.result",
        title=title,
        summary=f"{title} on {target}",
        target=target,
        evidence={"packet_loss": 100.0},
        score=70,
        severity=severity,
    )


def detection_fixture() -> DetectionResult:
    return DetectionResult(
        score=70,
        severity="high",
        signals=(
            DetectionSignal(
                code="ping.total_loss",
                label="Target stopped responding",
                points=70,
                detail="Packet loss reached 100%.",
            ),
        ),
    )


def detection_for(event: SecurityEvent) -> DetectionResult:
    score = {
        Severity.INFO: 0,
        Severity.LOW: 15,
        Severity.MEDIUM: 40,
        Severity.HIGH: 70,
        Severity.CRITICAL: 95,
    }[event.severity]
    signals = (
        (
            DetectionSignal(
                code=f"test.{event.source.value}",
                label="Test signal",
                points=score,
                detail="Synthetic test explanation.",
            ),
        )
        if score
        else ()
    )
    return DetectionResult(score=score, severity=event.severity, signals=signals)


def investigation_fixture(*, cost: float = 0.0042) -> InvestigationResult:
    return InvestigationResult(
        assessment=Assessment(
            classification="suspicious",
            confidence=0.91,
            summary="The target is unexpectedly unreachable.",
            rationale=["The probe observed complete packet loss."],
            recommended_actions=["Confirm routing and target availability."],
        ),
        usage=ModelUsage(
            prompt_tokens=100,
            completion_tokens=30,
            reasoning_tokens=20,
            cost_usd=cost,
            latency_ms=800,
            provider_request_id="gen-test",
        ),
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )


async def persist_investigation(
    repository: Repository,
    event_id: UUID,
    result: InvestigationResult,
) -> StoredInvestigation:
    queued = await repository.queue_investigation(
        event_id,
        model_id=result.model_id,
        requested_effort=result.requested_effort,
    )
    await repository.start_investigation(queued.id)
    return await repository.complete_investigation(queued.id, result)


@pytest.fixture
async def repository(tmp_path: Path):
    repo = Repository(tmp_path / "socketclaw.db")
    await repo.initialize()
    yield repo
    await repo.close()


@pytest.mark.asyncio
async def test_initialize_is_idempotent_and_enables_database_safety(
    tmp_path: Path,
) -> None:
    repo = Repository(tmp_path / "nested" / "socketclaw.db")

    await repo.initialize()
    await repo.initialize()
    info = await repo.database_info()

    assert info.schema_version == 4
    assert info.journal_mode == "wal"
    assert info.foreign_keys is True
    assert (tmp_path / "nested" / "socketclaw.db").exists()
    assert stat.S_IMODE((tmp_path / "nested" / "socketclaw.db").stat().st_mode) == 0o600
    await repo.close()


@pytest.mark.asyncio
async def test_event_and_investigation_round_trip(repository: Repository) -> None:
    event = event_fixture()

    stored = await repository.save_event(event, detection_fixture())
    investigation = await persist_investigation(repository, stored.id, investigation_fixture())

    loaded = await repository.get_event(stored.id)
    investigations = await repository.list_investigations()
    assert loaded is not None
    assert loaded.id == event.id
    assert loaded.evidence == {"packet_loss": 100.0}
    assert loaded.signals[0].code == "ping.total_loss"
    assert loaded.investigation_state == "complete"
    assert investigations == [investigation]
    assert investigation.event_id == stored.id
    assert investigation.assessment is not None
    assert investigation.assessment.confidence == 0.91
    assert investigation.usage is not None
    assert investigation.usage.cost_usd == 0.0042


@pytest.mark.asyncio
async def test_event_query_filters_and_paginates(repository: Repository) -> None:
    fixtures = [
        event_fixture(
            source="ping",
            severity=Severity.HIGH,
            target="1.1.1.1",
            title="Primary DNS unreachable",
            observed_at=NOW - timedelta(minutes=2),
        ),
        event_fixture(
            source="log",
            severity=Severity.CRITICAL,
            target="10.0.0.8",
            title="SSH authentication burst",
            observed_at=NOW - timedelta(minutes=1),
        ),
        event_fixture(
            source="port_scan",
            severity=Severity.MEDIUM,
            target="example.com",
            title="New TCP service",
            observed_at=NOW,
        ),
    ]
    for item in fixtures:
        await repository.save_event(item, detection_for(item))

    critical = await repository.list_events(EventQuery(severity=Severity.CRITICAL))
    log_events = await repository.list_events(EventQuery(source="log"))
    search = await repository.list_events(EventQuery(text="dns UNREACHABLE"))
    window = await repository.list_events(
        EventQuery(
            after=NOW - timedelta(minutes=1, seconds=30),
            before=NOW + timedelta(seconds=1),
        )
    )
    second_page = await repository.list_events(EventQuery(limit=1, offset=1))

    assert [item.target for item in critical] == ["10.0.0.8"]
    assert [item.target for item in log_events] == ["10.0.0.8"]
    assert [item.target for item in search] == ["1.1.1.1"]
    assert [item.target for item in window] == ["example.com", "10.0.0.8"]
    assert [item.target for item in second_page] == ["10.0.0.8"]


@pytest.mark.asyncio
async def test_failed_investigation_is_durable_and_retryable(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())

    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    failure = await repository.fail_investigation(
        queued.id,
        error="OpenAI rate limited the request",
    )

    loaded = await repository.get_event(stored.id)
    assert failure.status == "failed"
    assert failure.error == "OpenAI rate limited the request"
    assert loaded is not None
    assert loaded.investigation_state == "failed"


@pytest.mark.asyncio
async def test_response_proposal_is_stored_as_pending_operator_work(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated root authentication failures were observed."],
                recommended_actions=["Block after operator review."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="1.1.1.1",
                    reason="Repeated SSH authentication failures",
                ),
            )
        }
    )

    investigation = await persist_investigation(repository, stored.id, result)
    proposals = await repository.list_response_proposals(event_id=stored.id)

    assert len(proposals) == 1
    assert proposals[0].investigation_id == investigation.id
    assert proposals[0].status == "pending"
    assert proposals[0].proposal.action == "block"
    assert proposals[0].proposal.target_ip == "1.1.1.1"


@pytest.mark.asyncio
async def test_response_status_requires_safe_transition(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated root authentication failures were observed."],
                recommended_actions=["Block after operator review."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="1.1.1.1",
                    reason="Repeated SSH authentication failures",
                ),
            )
        }
    )
    await persist_investigation(repository, stored.id, result)
    proposal = (await repository.list_response_proposals(event_id=stored.id))[0]

    with pytest.raises(ValueError, match="unknown response status"):
        await repository.update_response_proposal_status(
            proposal.id,
            "executed",
            expected_status="pending",
            protected_targets=(),
        )

    with pytest.raises(ValueError, match="unknown response status"):
        await repository.update_response_proposal_status(
            proposal.id,
            "simulated",  # type: ignore[arg-type]
            expected_status="pending",
            protected_targets=(),
        )


@pytest.mark.asyncio
async def test_legacy_mismatched_block_target_cannot_be_approved(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="1.1.1.1",
                    reason="Repeated authentication failures",
                ),
            )
        }
    )
    await persist_investigation(repository, stored.id, result)
    proposal = (await repository.list_response_proposals(event_id=stored.id))[0]
    connection = sqlite3.connect(repository.database_path)
    try:
        payload = json.loads(
            connection.execute(
                "SELECT proposal_json FROM response_proposals WHERE id = ?",
                (str(proposal.id),),
            ).fetchone()[0]
        )
        payload["target_ip"] = "8.8.8.8"
        connection.execute(
            "UPDATE response_proposals SET proposal_json = ? WHERE id = ?",
            (json.dumps(payload), str(proposal.id)),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="does not match"):
        await repository.update_response_proposal_status(
            proposal.id,
            "approved",
            expected_status="pending",
            protected_targets=(),
        )

    latest = (await repository.list_response_proposals(event_id=stored.id))[0]
    assert latest.status == "pending"


@pytest.mark.asyncio
async def test_response_status_cannot_claim_unimplemented_execution(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="1.1.1.1",
                    reason="Repeated authentication failures",
                ),
            )
        }
    )
    await persist_investigation(repository, stored.id, result)
    proposal = (await repository.list_response_proposals(event_id=stored.id))[0]
    approved = await repository.update_response_proposal_status(
        proposal.id,
        "approved",
        expected_status="pending",
        protected_targets=(),
    )

    with pytest.raises(ValueError, match="unknown response status"):
        await repository.update_response_proposal_status(
            approved.id,
            "executed",
            expected_status="approved",
            protected_targets=(),
        )

    unchanged = (await repository.list_response_proposals(event_id=stored.id))[0]
    assert unchanged.status == "approved"


@pytest.mark.asyncio
async def test_session_stats_aggregate_severity_usage_and_failures(
    repository: Repository,
) -> None:
    first = await repository.save_event(event_fixture(), detection_fixture())
    second_event = event_fixture(
        severity=Severity.CRITICAL,
        target="10.0.0.8",
        title="Authentication burst",
    )
    second = await repository.save_event(second_event, detection_for(second_event))
    await persist_investigation(repository, first.id, investigation_fixture(cost=0.004))
    queued = await repository.queue_investigation(
        second.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    await repository.fail_investigation(
        queued.id,
        error="Provider unavailable",
    )

    stats = await repository.session_stats()

    assert stats.total_events == 2
    assert stats.by_severity == {"critical": 1, "high": 1}
    assert stats.completed_investigations == 1
    assert stats.failed_investigations == 1
    assert stats.total_tokens == 130
    assert stats.cost_usd == pytest.approx(0.004)


@pytest.mark.asyncio
async def test_unknown_event_cannot_receive_investigation(
    repository: Repository,
) -> None:
    unknown = event_fixture().id

    with pytest.raises(KeyError, match=str(unknown)):
        await repository.queue_investigation(
            unknown,
            model_id="gpt-5.6-luna",
            requested_effort="high",
        )


@pytest.mark.asyncio
async def test_investigation_lifecycle_is_durable_before_provider_work(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())

    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    queued_event = await repository.get_event(stored.id)
    assert queued.status == "queued"
    assert queued.completed_at is None
    assert queued_event is not None
    assert queued_event.investigation_state == "queued"

    running = await repository.start_investigation(queued.id)
    running_event = await repository.get_event(stored.id)
    assert running.status == "running"
    assert running_event is not None
    assert running_event.investigation_state == "running"

    completed = await repository.complete_investigation(
        running.id,
        investigation_fixture(),
    )
    completed_event = await repository.get_event(stored.id)
    assert completed.status == "complete"
    assert completed.assessment is not None
    assert completed_event is not None
    assert completed_event.investigation_state == "complete"


@pytest.mark.asyncio
async def test_duplicate_active_investigation_is_rejected_and_recoverable(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )

    with pytest.raises(ValueError, match="active investigation"):
        await repository.queue_investigation(
            stored.id,
            model_id="gpt-5.6-luna",
            requested_effort="high",
        )

    assert await repository.recover_incomplete_investigations() == 1
    recovered = (await repository.list_investigations(event_id=stored.id))[0]
    recovered_event = await repository.get_event(stored.id)
    assert recovered.id == queued.id
    assert recovered.status == "failed"
    assert recovered.error == "SocketClaw stopped before the investigation completed"
    assert recovered_event is not None
    assert recovered_event.investigation_state == "failed"


@pytest.mark.asyncio
async def test_running_investigation_failure_is_atomic(repository: Repository) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    await repository.start_investigation(queued.id)

    failed = await repository.fail_investigation(queued.id, error="Provider unavailable")
    failed_event = await repository.get_event(stored.id)

    assert failed.status == "failed"
    assert failed.error == "Provider unavailable"
    assert failed_event is not None
    assert failed_event.investigation_state == "failed"


@pytest.mark.asyncio
async def test_blank_investigation_failure_gets_a_durable_fallback(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )

    failed = await repository.fail_investigation(queued.id, error=" \n\t ")

    assert failed.status == "failed"
    assert failed.error == "Investigation failed without an error message"
    failed_event = await repository.get_event(stored.id)
    assert failed_event is not None
    assert failed_event.investigation_state == "failed"


@pytest.mark.asyncio
async def test_oversized_investigation_failure_is_redacted_and_bounded(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    secret = "sk-proj-this-must-not-be-stored"

    failed = await repository.fail_investigation(
        queued.id,
        error=f"{secret} {'x' * 5000}",
    )

    assert failed.error is not None
    assert secret not in failed.error
    assert "[REDACTED]" in failed.error
    assert len(failed.error) <= 4000
    assert failed.error.endswith("[truncated]")


@pytest.mark.asyncio
async def test_list_limits_reject_bool_and_non_integer_values(
    repository: Repository,
) -> None:
    with pytest.raises(ValueError, match="integer between"):
        await repository.list_investigations(limit=True)
    with pytest.raises(ValueError, match="integer between"):
        await repository.list_response_proposals(limit=1.5)
    with pytest.raises(ValueError, match="integer between"):
        await repository.list_runs(limit=False)


@pytest.mark.asyncio
async def test_protected_target_is_enforced_by_repository(repository: Repository) -> None:
    event = event_fixture(target="192.168.1.42")
    stored = await repository.save_event(event, detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="192.168.1.42",
                    reason="Repeated authentication failures",
                ),
            )
        }
    )
    await persist_investigation(repository, stored.id, result)
    proposal = (await repository.list_response_proposals(event_id=stored.id))[0]

    with pytest.raises(ValueError, match="protected target"):
        await repository.update_response_proposal_status(
            proposal.id,
            "approved",
            expected_status="pending",
            protected_targets=("192.168.1.42",),
        )

    unchanged = (await repository.list_response_proposals(event_id=stored.id))[0]
    assert unchanged.status == "pending"


@pytest.mark.asyncio
async def test_concurrent_response_transitions_have_one_winner(repository: Repository) -> None:
    event = event_fixture(target="198.51.100.24")
    stored = await repository.save_event(event, detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="198.51.100.24",
                    reason="Repeated authentication failures",
                ),
            )
        }
    )
    await persist_investigation(repository, stored.id, result)
    proposal = (await repository.list_response_proposals(event_id=stored.id))[0]

    outcomes = await asyncio.gather(
        repository.update_response_proposal_status(
            proposal.id,
            "approved",
            expected_status="pending",
            protected_targets=(),
        ),
        repository.update_response_proposal_status(
            proposal.id,
            "rejected",
            expected_status="pending",
            protected_targets=(),
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, ValueError) for outcome in outcomes) == 1


@pytest.mark.asyncio
async def test_run_lifecycle_is_persisted_once(repository: Repository) -> None:
    started = await repository.start_run("0.3.0")
    assert started.stopped_at is None
    assert started.clean_shutdown is False

    stopped = await repository.stop_run(started.id, clean_shutdown=True)
    assert stopped.stopped_at is not None
    assert stopped.clean_shutdown is True
    assert await repository.list_runs() == [stopped]

    with pytest.raises(ValueError, match="already stopped"):
        await repository.stop_run(started.id, clean_shutdown=True)


@pytest.mark.asyncio
async def test_new_evidence_is_bounded_but_legacy_rows_remain_readable(
    repository: Repository,
) -> None:
    oversized = "x" * (40 * 1024)
    event = event_fixture().model_copy(update={"evidence": {"payload": oversized}})
    with pytest.raises(ValueError, match="evidence"):
        await repository.save_event(event, detection_fixture())

    stored = await repository.save_event(event_fixture(), detection_fixture())
    connection = sqlite3.connect(repository.database_path)
    try:
        connection.execute(
            "UPDATE events SET evidence_json = ? WHERE id = ?",
            (json.dumps({"payload": oversized}), str(stored.id)),
        )
        connection.commit()
    finally:
        connection.close()

    historical = await repository.get_event(stored.id)
    assert historical is not None
    assert historical.evidence["payload"] == oversized


@pytest.mark.asyncio
async def test_legacy_event_text_signals_and_nonfinite_evidence_remain_readable(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    connection = sqlite3.connect(repository.database_path)
    try:
        connection.execute(
            "UPDATE events SET event_type = ' ', title = ' ', summary = ' ', "
            "target = '', evidence_json = ?, signals_json = ? WHERE id = ?",
            (
                '{"latency":NaN,"nested":[Infinity,-Infinity]}',
                json.dumps(
                    [
                        {
                            "code": " ",
                            "label": " ",
                            "points": 70,
                            "detail": " ",
                        }
                    ]
                ),
                str(stored.id),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    historical = (await repository.list_events())[0]

    assert historical.event_type == "legacy.event"
    assert historical.title == "Legacy event"
    assert historical.summary == "Legacy event had no summary"
    assert historical.target is None
    assert historical.evidence == {
        "latency": "NaN",
        "nested": ["Infinity", "-Infinity"],
    }
    assert historical.signals[0].code == "legacy.signal.1"


@pytest.mark.asyncio
async def test_database_info_rejects_malformed_domain_payload(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    connection = sqlite3.connect(repository.database_path)
    try:
        connection.execute(
            "UPDATE events SET evidence_json = '{' WHERE id = ?",
            (str(stored.id),),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="invalid event record"):
        await repository.database_info()


@pytest.mark.asyncio
async def test_legacy_blank_failure_remains_readable(repository: Repository) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    queued = await repository.queue_investigation(
        stored.id,
        model_id="gpt-5.6-luna",
        requested_effort="high",
    )
    completed_at = datetime.now(UTC).isoformat()
    connection = sqlite3.connect(repository.database_path)
    try:
        connection.execute(
            "UPDATE investigations SET status = 'failed', error = '   ', "
            "completed_at = ? WHERE id = ?",
            (completed_at, str(queued.id)),
        )
        connection.execute(
            "UPDATE events SET investigation_state = 'failed' WHERE id = ?",
            (str(stored.id),),
        )
        connection.commit()
    finally:
        connection.close()

    historical = (await repository.list_investigations(event_id=stored.id))[0]

    assert historical.status == "failed"
    assert historical.error == "Investigation failed without an error message"


@pytest.mark.asyncio
async def test_legacy_complete_payload_is_safely_normalized(
    repository: Repository,
) -> None:
    stored = await repository.save_event(event_fixture(), detection_fixture())
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="1.1.1.1",
                    reason="Repeated authentication failures",
                ),
            )
        }
    )
    investigation = await persist_investigation(repository, stored.id, result)
    connection = sqlite3.connect(repository.database_path)
    try:
        assessment_json, usage_json = connection.execute(
            "SELECT assessment_json, usage_json FROM investigations WHERE id = ?",
            (str(investigation.id),),
        ).fetchone()
        assessment = json.loads(assessment_json)
        assessment["summary"] = "   "
        assessment["rationale"] = [" ", "x" * 1500]
        assessment["recommended_actions"] = [" ", "a" * 1500]
        assessment["response_proposal"]["requires_approval"] = False
        assessment["response_proposal"]["reason"] = " "
        usage = json.loads(usage_json)
        usage["total_tokens"] = 999
        usage["provider_request_id"] = ""
        connection.execute(
            "UPDATE investigations SET assessment_json = ?, usage_json = ? WHERE id = ?",
            (json.dumps(assessment), json.dumps(usage), str(investigation.id)),
        )
        proposal_id, proposal_json = connection.execute(
            "SELECT id, proposal_json FROM response_proposals WHERE investigation_id = ?",
            (str(investigation.id),),
        ).fetchone()
        proposal = json.loads(proposal_json)
        proposal["requires_approval"] = False
        proposal["reason"] = " "
        connection.execute(
            "UPDATE response_proposals SET proposal_json = ? WHERE id = ?",
            (json.dumps(proposal), proposal_id),
        )
        connection.commit()
    finally:
        connection.close()

    historical = (await repository.list_investigations(event_id=stored.id))[0]
    proposals = await repository.list_response_proposals(event_id=stored.id)
    stats = await repository.session_stats()

    assert historical.assessment is not None
    assert historical.assessment.summary == "Legacy assessment had no summary"
    assert historical.assessment.rationale == ("x" * 1000,)
    assert historical.assessment.recommended_actions == ("a" * 1000,)
    assert historical.assessment.response_proposal is not None
    assert historical.assessment.response_proposal.requires_approval is True
    assert historical.assessment.response_proposal.reason.startswith("Legacy response")
    assert historical.usage is not None
    assert historical.usage.total_tokens == 130
    assert historical.usage.provider_request_id is None
    assert stats.total_tokens == 130
    assert proposals[0].proposal.requires_approval is True

    approved = await repository.update_response_proposal_status(
        proposals[0].id,
        "approved",
        expected_status="pending",
        protected_targets=(),
    )
    assert approved.status == "approved"
    assert approved.proposal.requires_approval is True


@pytest.mark.asyncio
async def test_legacy_unsafe_block_proposal_is_downgraded_to_review_only(
    repository: Repository,
) -> None:
    stored = await repository.save_event(
        event_fixture(target="8.8.8.8"),
        detection_fixture(),
    )
    result = investigation_fixture().model_copy(
        update={
            "assessment": Assessment(
                classification="critical",
                confidence=0.98,
                summary="The source is attacking SSH.",
                rationale=["Repeated authentication failures were observed."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="8.8.8.8",
                    reason="Repeated authentication failures",
                    command="firewall block 8.8.8.8",
                ),
            )
        }
    )
    investigation = await persist_investigation(repository, stored.id, result)
    connection = sqlite3.connect(repository.database_path)
    try:
        assessment_json = connection.execute(
            "SELECT assessment_json FROM investigations WHERE id = ?",
            (str(investigation.id),),
        ).fetchone()[0]
        assessment = json.loads(assessment_json)
        assessment["response_proposal"]["target_ip"] = "169.254.10.20"
        proposal_id, proposal_json = connection.execute(
            "SELECT id, proposal_json FROM response_proposals WHERE investigation_id = ?",
            (str(investigation.id),),
        ).fetchone()
        proposal = json.loads(proposal_json)
        proposal["target_ip"] = "169.254.10.20"
        connection.execute(
            "UPDATE investigations SET assessment_json = ? WHERE id = ?",
            (json.dumps(assessment), str(investigation.id)),
        )
        connection.execute(
            "UPDATE response_proposals SET proposal_json = ? WHERE id = ?",
            (json.dumps(proposal), proposal_id),
        )
        connection.commit()
    finally:
        connection.close()

    historical = (await repository.list_investigations(event_id=stored.id))[0]
    proposals = await repository.list_response_proposals(event_id=stored.id)

    assert historical.assessment is not None
    assert historical.assessment.response_proposal is not None
    assert historical.assessment.response_proposal.action == "monitor"
    assert historical.assessment.response_proposal.command is None
    assert proposals[0].proposal.action == "monitor"
    assert proposals[0].proposal.command is None
    assert "review only" in proposals[0].proposal.reason


@pytest.mark.asyncio
async def test_literal_search_escapes_sql_wildcards(repository: Repository) -> None:
    percent = event_fixture(title="CPU reached 100%_used")
    plain = event_fixture(target="8.8.8.8", title="CPU reached 100 percent used")
    await repository.save_event(percent, detection_fixture())
    await repository.save_event(plain, detection_fixture())

    matches = await repository.list_events(EventQuery(text="%_"))

    assert [item.id for item in matches] == [percent.id]


def test_event_query_rejects_inverted_time_window() -> None:
    with pytest.raises(ValueError, match="after"):
        EventQuery(after=NOW, before=NOW - timedelta(seconds=1))


@pytest.mark.asyncio
async def test_initialize_rejects_database_without_schema_metadata(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE stray (id INTEGER PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    repository = Repository(path)

    with pytest.raises(RuntimeError, match="no schema metadata"):
        await repository.initialize()
    await repository.close()

    connection = sqlite3.connect(path)
    try:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        connection.close()
    assert tables == {"stray"}


@pytest.mark.asyncio
async def test_database_path_with_url_characters_is_not_reinterpreted(tmp_path: Path) -> None:
    path = tmp_path / "socket?claw#local.db"
    repository = Repository(path)

    await repository.initialize()

    assert path.exists()
    await repository.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm"])
async def test_database_symlinks_are_rejected_before_sqlite_opens_them(
    tmp_path: Path,
    suffix: str,
) -> None:
    victim = tmp_path / "victim"
    original_bytes = b"do not modify this file"
    victim.write_bytes(original_bytes)
    victim.chmod(0o644)
    original_mode = stat.S_IMODE(victim.stat().st_mode)
    database_path = tmp_path / "socketclaw.db"
    Path(f"{database_path}{suffix}").symlink_to(victim)
    repository = Repository(database_path)

    with pytest.raises(RuntimeError, match="must not be a symlink"):
        await repository.initialize()

    assert Path(f"{database_path}{suffix}").is_symlink()
    assert victim.read_bytes() == original_bytes
    assert stat.S_IMODE(victim.stat().st_mode) == original_mode
    await repository.close()


@pytest.mark.asyncio
async def test_database_hardlink_is_rejected_before_sqlite_opens_it(
    tmp_path: Path,
) -> None:
    victim = tmp_path / "victim"
    original_bytes = b"do not modify this file"
    victim.write_bytes(original_bytes)
    victim.chmod(0o644)
    original_mode = stat.S_IMODE(victim.stat().st_mode)
    database_path = tmp_path / "socketclaw.db"
    os.link(victim, database_path)
    repository = Repository(database_path)

    with pytest.raises(RuntimeError, match="must not be hard-linked"):
        await repository.initialize()

    assert victim.read_bytes() == original_bytes
    assert stat.S_IMODE(victim.stat().st_mode) == original_mode
    await repository.close()


@pytest.mark.asyncio
async def test_nonregular_database_path_is_rejected(tmp_path: Path) -> None:
    database_path = tmp_path / "socketclaw.db"
    database_path.mkdir()
    repository = Repository(database_path)

    with pytest.raises(RuntimeError, match="must be a regular file"):
        await repository.initialize()

    assert database_path.is_dir()
    await repository.close()


@pytest.mark.asyncio
async def test_preexisting_managed_database_remains_usable(tmp_path: Path) -> None:
    database_path = tmp_path / "socketclaw.db"
    first = Repository(database_path)
    await first.initialize()
    await first.save_event(event_fixture(), detection_fixture())
    await first.close()

    reopened = Repository(database_path)
    await reopened.initialize()

    assert (await reopened.database_info()).schema_version == 4
    assert len(await reopened.list_events()) == 1
    await reopened.close()


@pytest.mark.asyncio
async def test_concurrent_initialization_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "shared.db"
    first = Repository(path)
    second = Repository(path)

    await asyncio.gather(first.initialize(), second.initialize())

    first_info, second_info = await asyncio.gather(
        first.database_info(),
        second.database_info(),
    )
    assert first_info.schema_version == second_info.schema_version == 4
    await asyncio.gather(first.close(), second.close())


async def test_severity_filter_precedes_limit_in_real_sqlite(repository: Repository) -> None:
    from socketclaw.detection import Detector

    important = event_fixture(observed_at=NOW - timedelta(minutes=1))
    await repository.save_event(important, detection_fixture())
    for _ in range(110):
        ordinary = event_fixture().model_copy(update={"evidence": {"packet_loss": 0}})
        await repository.save_event(ordinary, Detector().score(ordinary, []))
    selected = await repository.list_events(
        EventQuery(severities=(Severity.HIGH, Severity.CRITICAL), limit=8)
    )
    assert [event.id for event in selected] == [important.id]


async def test_correlation_query_exact_window_excludes_other_sources_and_future(
    repository: Repository,
) -> None:
    current = event_fixture(target="EXAMPLE.COM")
    boundary = event_fixture(target="example.com", observed_at=NOW - timedelta(minutes=5))
    before = event_fixture(
        target="example.com", observed_at=boundary.observed_at - timedelta(microseconds=1)
    )
    future = event_fixture(target="example.com", observed_at=NOW + timedelta(microseconds=1))
    unrelated = event_fixture(target="another.example")
    other_source = event_fixture(target="example.com", source="log")
    current = current.model_copy(update={"ingested_at": current.observed_at})
    for event in (current, boundary, before, future, unrelated, other_source):
        event = event.model_copy(update={"ingested_at": event.observed_at})
        await repository.save_event(event, detection_fixture())
    history = await repository.correlation_history(current, timedelta(minutes=5))
    assert [event.id for event in history] == [boundary.id]
