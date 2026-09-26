from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from socketclaw.config import OPENAI_MODEL
from socketclaw.context import build_incident_context, grounded_assessment
from socketclaw.export import (
    export_incident_json,
    export_incident_markdown,
    export_json,
    export_markdown,
)
from socketclaw.incidents import Incident, IncidentHistory, IncidentLink, Occurrence
from socketclaw.openai import OpenAIClient
from socketclaw.redaction import redact_data, redact_secrets
from socketclaw.response_actions import ActionRecord, incident_runbook
from socketclaw.storage import IncidentReport, StoredEvent

CORPUS = {
    "password": "synthetic-pass-9832",
    "Cookie": "opaque_cookie_324",
    "access_token": "access-87-x",
    "nested": {"private_key": "private-value-62"},
    "raw": "password=rawsecret42 token=generictoken23\nCookie: sid=cookie987; jwt=jwt987",
    "url": "https://admin:urlsecret77@example.invalid/path",
}
SECRET_VALUES = (
    "synthetic-pass-9832",
    "opaque_cookie_324",
    "access-87-x",
    "private-value-62",
    "rawsecret42",
    "generictoken23",
    "cookie987",
    "jwt987",
    "urlsecret77",
)


def report_fixture(count: int = 4, *, payload: dict | None = None) -> IncidentReport:
    at = datetime(2026, 9, 26, tzinfo=UTC)
    incident_id, occurrence_id = uuid4(), uuid4()
    events = tuple(
        StoredEvent(
            source="log",
            event_type="log.auth_failure",
            title="Authentication evidence",
            summary="Failed login observed",
            target="server.example",
            observed_at=at + timedelta(seconds=i),
            evidence=payload or {"user": "alice", "attempts": i + 1},
            score=80,
            severity="high",
        )
        for i in range(count)
    )
    incident = Incident(
        id=incident_id,
        current_occurrence_id=occurrence_id,
        correlation_key="auth:server:alice",
        family="authentication",
        target="server.example",
        title="Authentication incident",
        first_seen_at=at,
        last_seen_at=events[-1].observed_at,
        highest_score=80,
        rule_version=uuid4(),
        observation_count=count,
    )
    occurrence = Occurrence(
        id=occurrence_id,
        incident_id=incident_id,
        number=1,
        started_at=at,
        last_seen_at=events[-1].observed_at,
        observation_count=count,
    )
    links = tuple(
        IncidentLink(
            incident_id=incident_id,
            occurrence_id=occurrence_id,
            event_id=event.id,
            kind="anomaly",
            reason="test",
            linked_at=event.observed_at,
        )
        for event in events
    )
    return IncidentReport(
        history=IncidentHistory(
            incident=incident, occurrences=(occurrence,), notes=(), transitions=(), links=links
        ),
        observations=events,
    )


def answer(event: StoredEvent) -> dict:
    return dict(
        classification="suspicious",
        confidence=0.8,
        summary="Unsupported prose discarded",
        rationale=["Unsupported prose discarded"],
        recommended_actions=[],
        response_proposal=None,
        observed_facts=[
            dict(
                evidence_id=str(event.id),
                field="evidence.attempts",
                value=str(event.evidence["attempts"]),
            )
        ],
        possible_explanations=["An operator may have mistyped a credential"],
        missing_evidence=["No successful session observed"],
        next_checks=["Inspect session records"],
    )


def test_bounded_context_preserves_focus_and_explains_omissions() -> None:
    report = report_fixture(50)
    context = build_incident_context(report, report.observations[0], max_events=4)
    assert context.evidence[0]["id"] == str(report.observations[0].id)
    assert len(context.evidence) == 4
    assert "46 observations" in context.omissions[0]
    assert context.incident["current_occurrence_id"]
    assert context.local_summary and context.runbook
    large = report_fixture(payload={"raw": "x" * 200_000})
    bounded = build_incident_context(large, max_bytes=4096)
    assert len(bounded.model_dump_json().encode()) <= 4096
    assert bounded.evidence[0]["id"] == str(large.observations[-1].id)
    assert bounded.omissions


def test_factual_claims_must_quote_supplied_evidence_exactly() -> None:
    report = report_fixture()
    event = report.observations[0]
    context = build_incident_context(report)
    content = answer(event)
    result = grounded_assessment(content, context)
    assert str(event.id) in result.summary
    assert "Unsupported prose" not in result.model_dump_json()
    content["observed_facts"][0]["value"] = "Successful login and shell executed"
    with pytest.raises(ValueError, match="does not match"):
        grounded_assessment(content, context)
    content["observed_facts"][0]["evidence_id"] = str(uuid4())
    with pytest.raises(ValueError, match="not supplied"):
        grounded_assessment(content, context)


async def test_ai_request_contains_related_context_without_credentials() -> None:
    report = report_fixture()
    event = report.observations[0]
    secret_event = report.observations[-1].model_copy(update={"evidence": CORPUS})
    report = report.model_copy(update={"observations": (*report.observations[:-1], secret_event)})
    context = build_incident_context(report, event)
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "resp_context_test",
                "status": "completed",
                "model": OPENAI_MODEL.model_id,
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": json.dumps(answer(event))}],
                    }
                ],
                "usage": {"input_tokens": 10, "output_tokens": 10},
            },
        )

    result = await OpenAIClient(
        "synthetic-api-key", transport=httpx.MockTransport(handler)
    ).investigate(event, context=context)
    assert len(requests) == 1
    wire = json.dumps(requests[0])
    for evidence in report.observations:
        assert str(evidence.id) in wire
    for secret in SECRET_VALUES:
        assert secret not in wire
    assert "observed_facts" in wire
    assert str(event.id) in result.assessment.summary
    assert secret_event.evidence["password"] == SECRET_VALUES[0]


@pytest.mark.parametrize("formatter", [export_json, export_markdown])
def test_outbound_event_exports_redact_synthetic_corpus(formatter) -> None:
    event = report_fixture(payload=CORPUS).observations[0]
    rendered = formatter(event, None)
    for secret in SECRET_VALUES:
        assert secret not in rendered
    assert str(event.id) in rendered


@pytest.mark.parametrize("formatter", [export_incident_json, export_incident_markdown])
def test_incident_exports_redact_synthetic_corpus(formatter) -> None:
    report = report_fixture(payload=CORPUS)
    rendered = formatter(report)
    for secret in SECRET_VALUES:
        assert secret not in rendered
    assert str(report.history.incident.id) in rendered


def test_redaction_preserves_actor_linkage_and_is_idempotent() -> None:
    safe = redact_data({"actor": "192.0.2.9", "user": "alice", **CORPUS})
    assert safe["actor"] == "192.0.2.9"
    assert safe["user"] == "alice"
    assert redact_data(safe) == safe
    rendered = redact_secrets('password="spaces in password" token=small Cookie: a=secret')
    assert "spaces in password" not in rendered and "a=secret" not in rendered


def test_verification_requires_evidence_and_runbook_never_executes() -> None:
    with pytest.raises(ValidationError, match="requires subsequent"):
        ActionRecord(incident_id=uuid4(), status="verified", summary="looks fine")
    action = ActionRecord(incident_id=uuid4(), status="failed", summary="Restart failed")
    assert action.status == "failed"
    assert "approval alone executes nothing" in " ".join(incident_runbook("availability"))
    assert "victim server" in " ".join(incident_runbook("authentication"))


def test_incident_report_exports_operator_action_failure_and_verification() -> None:
    report = report_fixture()
    failed = ActionRecord(
        incident_id=report.history.incident.id,
        status="failed",
        summary="Service repair failed: password=repair-secret-44",
    )
    verified = ActionRecord(
        incident_id=report.history.incident.id,
        status="verified",
        summary="Recovery observed",
        evidence_ids=(report.observations[-1].id,),
    )
    report = report.model_copy(
        update={
            "action_records": (failed, verified),
            "omissions": ("older observations omitted",),
            "omitted_observations": 200,
        }
    )
    rendered_json = export_incident_json(report)
    rendered_markdown = export_incident_markdown(report)
    payload = json.loads(rendered_json)
    assert payload["action_records"][0]["status"] == "failed"
    assert payload["action_records"][1]["evidence_ids"] == [str(report.observations[-1].id)]
    for rendered in (rendered_json, rendered_markdown):
        assert "repair-secret-44" not in rendered
        assert "older observations omitted" in rendered
        assert str(verified.id) in rendered
    assert "200 observations omitted" in rendered_markdown
    assert "Response reviews" in rendered_markdown
    assert "Detection rule snapshots" in rendered_markdown


def test_known_credentials_and_auth_headers_are_redacted() -> None:
    raw = "Authorization: opaque_auth_value\nAuthorization: Bearer short\n" + "ghp_" + "a" * 24
    safe = redact_secrets(raw)
    assert "opaque_auth_value" not in safe
    assert "short" not in safe
    assert "ghp_" not in safe
    assert "Authorization: Bearer [REDACTED]" in safe
    assert redact_data({"database_password": "value", "AWS_SECRET_ACCESS_KEY": "aws-value"}) == {
        "database_password": "[REDACTED]",
        "AWS_SECRET_ACCESS_KEY": "[REDACTED]",
    }
