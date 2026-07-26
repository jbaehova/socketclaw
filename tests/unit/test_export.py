from __future__ import annotations

import json
from datetime import UTC, datetime

from socketclaw.domain import (
    Assessment,
    DetectionSignal,
    ModelUsage,
)
from socketclaw.export import export_json, export_markdown
from socketclaw.storage import StoredEvent, StoredInvestigation


def incident_fixture() -> tuple[StoredEvent, StoredInvestigation]:
    event = StoredEvent(
        id="62ca5e00-a9e8-4986-bb45-c63f41dc78e3",
        observed_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        source="ping",
        event_type="ping.result",
        title="Target stopped responding",
        summary="Complete packet loss on 1.1.1.1",
        target="1.1.1.1",
        evidence={"packet_loss": 100.0, "debug": "sk-or-v1-secret"},
        score=70,
        severity="high",
        investigation_state="complete",
        created_at=datetime(2026, 7, 27, 12, 0, 1, tzinfo=UTC),
        signals=(
            DetectionSignal(
                code="ping.total_loss",
                label="Target stopped responding",
                points=70,
                detail="Packet loss reached 100%.",
            ),
        ),
    )
    investigation = StoredInvestigation(
        id="e1d8ccec-0100-4e63-847c-b94d530d141b",
        event_id=event.id,
        status="complete",
        assessment=Assessment(
            classification="suspicious",
            confidence=0.91,
            summary="The target is unexpectedly unreachable.",
            rationale=["Complete packet loss was observed."],
            recommended_actions=["Check target health."],
        ),
        usage=ModelUsage(
            prompt_tokens=100,
            completion_tokens=30,
            reasoning_tokens=20,
            cost_usd=0.0042,
            latency_ms=800,
            provider_request_id="gen-test",
        ),
        model_id="openai/gpt-5.6-terra",
        requested_effort="high",
        created_at=datetime(2026, 7, 27, 12, 0, 2, tzinfo=UTC),
        completed_at=datetime(2026, 7, 27, 12, 0, 3, tzinfo=UTC),
    )
    return event, investigation


def test_markdown_export_is_complete_and_redacts_secret() -> None:
    event, investigation = incident_fixture()

    rendered = export_markdown(
        event,
        investigation,
        secrets=["sk-or-v1-secret"],
    )

    assert rendered.startswith("# SocketClaw Incident\n")
    assert "**Severity:** HIGH (70/100)" in rendered
    assert "`ping.total_loss`" in rendered
    assert "GPT-5.6" not in rendered
    assert "openai/gpt-5.6-terra" in rendered
    assert "$0.004200" in rendered
    assert "sk-or-v1-secret" not in rendered
    assert "[REDACTED]" in rendered


def test_json_export_round_trips_typed_incident_without_secret() -> None:
    event, investigation = incident_fixture()

    rendered = export_json(
        event,
        investigation,
        secrets=["sk-or-v1-secret"],
    )
    parsed = json.loads(rendered)

    assert parsed["event"]["id"] == str(event.id)
    assert parsed["event"]["signals"][0]["code"] == "ping.total_loss"
    assert parsed["investigation"]["assessment"]["confidence"] == 0.91
    assert parsed["investigation"]["usage"]["total_tokens"] == 150
    assert "sk-or-v1-secret" not in rendered


def test_export_without_investigation_has_explicit_pending_state() -> None:
    event, _ = incident_fixture()

    markdown = export_markdown(event, None)
    payload = json.loads(export_json(event, None))

    assert "No AI investigation has been recorded." in markdown
    assert payload["investigation"] is None
