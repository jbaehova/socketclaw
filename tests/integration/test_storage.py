from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

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
from socketclaw.storage import EventQuery, Repository

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
        model_id="openai/gpt-5.6-terra",
        requested_effort="high",
    )


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

    assert info.schema_version == 1
    assert info.journal_mode == "wal"
    assert info.foreign_keys is True
    assert (tmp_path / "nested" / "socketclaw.db").exists()
    await repo.close()


@pytest.mark.asyncio
async def test_event_and_investigation_round_trip(repository: Repository) -> None:
    event = event_fixture()

    stored = await repository.save_event(event, detection_fixture())
    investigation = await repository.save_investigation(
        stored.id,
        investigation_fixture(),
    )

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
        detection = DetectionResult(
            score=item.score,
            severity=item.severity,
            signals=(),
        )
        await repository.save_event(item, detection)

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

    failure = await repository.save_investigation_failure(
        stored.id,
        model_id="qwen/qwen3.7-max",
        requested_effort="high",
        error="OpenRouter rate limited the request",
    )

    loaded = await repository.get_event(stored.id)
    assert failure.status == "failed"
    assert failure.error == "OpenRouter rate limited the request"
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
                    target_ip="198.51.100.24",
                    reason="Repeated SSH authentication failures",
                ),
            )
        }
    )

    investigation = await repository.save_investigation(stored.id, result)
    proposals = await repository.list_response_proposals(event_id=stored.id)

    assert len(proposals) == 1
    assert proposals[0].investigation_id == investigation.id
    assert proposals[0].status == "pending"
    assert proposals[0].proposal.action == "block"
    assert proposals[0].proposal.target_ip == "198.51.100.24"


@pytest.mark.asyncio
async def test_session_stats_aggregate_severity_usage_and_failures(
    repository: Repository,
) -> None:
    first = await repository.save_event(event_fixture(), detection_fixture())
    second = await repository.save_event(
        event_fixture(
            severity=Severity.CRITICAL,
            target="10.0.0.8",
            title="Authentication burst",
        ),
        DetectionResult(score=95, severity="critical", signals=()),
    )
    await repository.save_investigation(first.id, investigation_fixture(cost=0.004))
    await repository.save_investigation_failure(
        second.id,
        model_id="moonshotai/kimi-k3",
        requested_effort="max",
        error="Provider unavailable",
    )

    stats = await repository.session_stats()

    assert stats.total_events == 2
    assert stats.by_severity == {"critical": 1, "high": 1}
    assert stats.completed_investigations == 1
    assert stats.failed_investigations == 1
    assert stats.total_tokens == 150
    assert stats.cost_usd == pytest.approx(0.004)


@pytest.mark.asyncio
async def test_unknown_event_cannot_receive_investigation(
    repository: Repository,
) -> None:
    unknown = event_fixture().id

    with pytest.raises(KeyError, match=str(unknown)):
        await repository.save_investigation(unknown, investigation_fixture())
