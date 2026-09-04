from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from socketclaw.domain import (
    Assessment,
    DetectionSignal,
    ModelUsage,
    ResponseProposal,
)
from socketclaw.export import (
    _write_managed_export_portable,
    export_json,
    export_markdown,
    write_managed_export,
)
from socketclaw.storage import StoredEvent, StoredInvestigation, StoredResponseProposal


def incident_fixture() -> tuple[StoredEvent, StoredInvestigation]:
    event = StoredEvent(
        id="62ca5e00-a9e8-4986-bb45-c63f41dc78e3",
        observed_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        source="ping",
        event_type="ping.result",
        title="Target stopped responding",
        summary="Complete packet loss on 1.1.1.1",
        target="1.1.1.1",
        evidence={"packet_loss": 100.0, "debug": "sk-proj-secret"},
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
        model_id="gpt-5.6-luna",
        requested_effort="high",
        created_at=datetime(2026, 7, 27, 12, 0, 2, tzinfo=UTC),
        completed_at=datetime(2026, 7, 27, 12, 0, 3, tzinfo=UTC),
    )
    return event, investigation


def test_managed_export_rejects_redirected_directory(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outside = tmp_path / "outside"
    home.mkdir(mode=0o700)
    outside.mkdir()
    (home / "exports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        write_managed_export(home, "incident.md", "secret incident\n")

    assert not (outside / "incident.md").exists()


def test_managed_export_fails_closed_without_secure_directory_handles(
    tmp_path: Path,
) -> None:
    with pytest.raises(OSError, match="explicit --output"):
        _write_managed_export_portable(tmp_path, "incident.md", "secret incident\n")


def test_managed_export_writes_private_file_and_directory(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)

    destination = write_managed_export(home, "incident.md", "incident\n")

    assert destination.read_text() == "incident\n"
    if os.name == "posix":
        assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_markdown_export_is_complete_and_redacts_secret() -> None:
    event, investigation = incident_fixture()

    rendered = export_markdown(
        event,
        investigation,
        secrets=["sk-proj-secret"],
    )

    assert rendered.startswith("# SocketClaw Incident\n")
    assert "**Severity:** HIGH (70/100)" in rendered
    assert "`ping.total_loss`" in rendered
    assert "GPT-5.6" not in rendered
    assert "gpt-5.6-luna" in rendered
    assert "$0.004200" in rendered
    assert "sk-proj-secret" not in rendered
    assert "[REDACTED]" in rendered


def test_json_export_round_trips_typed_incident_without_secret() -> None:
    event, investigation = incident_fixture()

    rendered = export_json(
        event,
        investigation,
        secrets=["sk-proj-secret"],
    )
    parsed = json.loads(rendered)

    assert parsed["event"]["id"] == str(event.id)
    assert parsed["event"]["signals"][0]["code"] == "ping.total_loss"
    assert parsed["investigation"]["assessment"]["confidence"] == 0.91
    assert parsed["investigation"]["usage"]["total_tokens"] == 130
    assert "sk-proj-secret" not in rendered


def test_export_without_investigation_has_explicit_pending_state() -> None:
    event, _ = incident_fixture()

    markdown = export_markdown(event, None)
    payload = json.loads(export_json(event, None))

    assert "No AI investigation has been recorded." in markdown
    assert payload["investigation"] is None


@pytest.mark.parametrize("status", ["queued", "running"])
def test_export_with_active_investigation_reports_current_state(status: str) -> None:
    event, investigation = incident_fixture()
    active = investigation.model_copy(
        update={
            "status": status,
            "assessment": None,
            "usage": None,
            "completed_at": None,
        }
    )

    markdown = export_markdown(event, active)
    payload = json.loads(export_json(event, active))

    assert f"**Status:** {status.title()}" in markdown
    assert f"currently {status}" in markdown
    assert payload["investigation"]["status"] == status


def test_exports_redact_json_and_markdown_escaped_secret_forms() -> None:
    event, investigation = incident_fixture()
    secret = 'credential-"quoted\\segment'
    event = event.model_copy(
        update={
            "summary": f"Observed {secret}",
            "evidence": {"credential": secret},
        }
    )

    json_rendered = export_json(event, investigation, secrets=[secret])
    markdown_rendered = export_markdown(event, investigation, secrets=[secret])

    assert secret not in json_rendered
    assert secret not in markdown_rendered
    assert json.loads(json_rendered)["event"]["evidence"]["credential"] == "[REDACTED]"
    assert "[REDACTED]" in markdown_rendered
    assert "quoted" not in markdown_rendered


def test_json_redaction_cannot_corrupt_serialized_structure() -> None:
    event, investigation = incident_fixture()
    secret = '": {'
    event = event.model_copy(update={"evidence": {"credential": secret}})

    rendered = export_json(event, investigation, secrets=[secret])

    parsed = json.loads(rendered)
    assert parsed["event"]["evidence"]["credential"] == "[REDACTED]"


def test_redacted_evidence_keys_do_not_drop_colliding_values() -> None:
    event, investigation = incident_fixture()
    secret = "credential-field-name"
    event = event.model_copy(
        update={"evidence": {secret: "secret key", "[REDACTED]": "literal key"}}
    )

    rendered = export_json(event, investigation, secrets=[secret])

    evidence = json.loads(rendered)["event"]["evidence"]
    assert set(evidence.values()) == {"secret key", "literal key"}
    assert secret not in rendered


def test_markdown_evidence_fence_is_longer_than_untrusted_backticks() -> None:
    event, investigation = incident_fixture()
    event = event.model_copy(update={"evidence": {"message": "```\n# not a report heading"}})

    rendered = export_markdown(event, investigation)

    assert "````json\n" in rendered
    assert "\n````\n\n## AI investigation" in rendered


def test_markdown_includes_safe_literal_response_proposal() -> None:
    event, investigation = incident_fixture()
    secret = "credential-command-secret"
    assert investigation.assessment is not None
    proposal = ResponseProposal(
        action="block",
        target_ip="8.8.8.8",
        reason="Confirmed source\n## not a heading",
        command=f"firewall block {secret}\n```\nthen verify",
        platform="linux",
        reversible=True,
        requires_approval=True,
    )
    assessment = investigation.assessment.model_copy(update={"response_proposal": proposal})
    investigation = investigation.model_copy(update={"assessment": assessment})

    rendered = export_markdown(event, investigation, secrets=[secret])

    assert "### Response proposal" in rendered
    assert "**Action:** Block" in rendered
    assert "**Target:** 8\\.8\\.8\\.8" in rendered
    assert "**Reversible:** Yes" in rendered
    assert "**Approval required:** Yes" in rendered
    assert "**Platform:** `linux`" in rendered
    assert "Confirmed source \\#\\# not a heading" in rendered
    assert "````text\n" in rendered
    assert "firewall block [REDACTED]" in rendered
    assert secret not in rendered


def test_exports_include_durable_response_transition_metadata() -> None:
    event, investigation = incident_fixture()
    proposal = ResponseProposal(
        action="block",
        target_ip="8.8.8.8",
        reason="Confirmed source",
    )
    assert investigation.assessment is not None
    investigation = investigation.model_copy(
        update={
            "assessment": investigation.assessment.model_copy(
                update={"response_proposal": proposal}
            )
        }
    )
    stored = StoredResponseProposal(
        id="6aab520f-c53d-429a-9132-4cf83fc1d145",
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=proposal,
        status="approved",
        created_at=datetime(2026, 7, 27, 12, 0, 4, tzinfo=UTC),
    )

    markdown = export_markdown(event, investigation, response_proposal=stored)
    payload = json.loads(export_json(event, investigation, response_proposal=stored))

    assert "**Durable status:** Approved" in markdown
    assert str(stored.id) in markdown
    assert stored.created_at.isoformat() in markdown
    assert payload["response_proposal"]["id"] == str(stored.id)
    assert payload["response_proposal"]["status"] == "approved"


def test_export_rejects_response_proposal_from_another_investigation() -> None:
    event, investigation = incident_fixture()
    proposal = StoredResponseProposal(
        id="6aab520f-c53d-429a-9132-4cf83fc1d145",
        event_id=event.id,
        investigation_id="f47947f7-6fb8-4b51-973f-eb4b6a21d4a0",
        proposal=ResponseProposal(
            action="monitor",
            reason="Observe only",
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 0, 4, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="does not belong to the exported investigation"):
        export_json(event, investigation, response_proposal=proposal)


def test_markdown_export_keeps_untrusted_text_inside_its_sections() -> None:
    event, investigation = incident_fixture()
    event = event.model_copy(
        update={
            "title": "Alert\n<script>run()</script>",
            "summary": "# Forged heading\n[click](https://example.invalid)",
        }
    )
    assert investigation.assessment is not None
    assessment = investigation.assessment.model_copy(
        update={"rationale": ["first line\n## Forged rationale", "*emphasis*"]}
    )
    investigation = investigation.model_copy(update={"assessment": assessment})

    rendered = export_markdown(event, investigation)

    assert "<script>" not in rendered
    assert r"&lt;script&gt;run\(\)&lt;/script&gt;" in rendered
    assert "\n# Forged heading" not in rendered
    assert "\\# Forged heading" in rendered
    assert "\\[click\\]\\(https://example\\.invalid\\)" in rendered
    assert "## Forged rationale" not in rendered
    assert "\\*emphasis\\*" in rendered


def test_exports_strip_terminal_control_sequences_from_untrusted_text() -> None:
    event, investigation = incident_fixture()
    dangerous = "\x1b]0;owned\x07\x9b31mvisible\x08"
    event = event.model_copy(
        update={
            "title": dangerous,
            "summary": dangerous,
            "evidence": {"message": f"{dangerous}\n\tcontinued"},
        }
    )

    markdown = export_markdown(event, investigation)
    rendered_json = export_json(event, investigation)
    payload = json.loads(rendered_json)

    for control in ("\x1b", "\x07", "\x9b", "\x08"):
        assert control not in markdown
        assert control not in rendered_json
        assert control not in payload["event"]["evidence"]["message"]
    assert "visible" in markdown
    assert payload["event"]["evidence"]["message"].endswith("\n\tcontinued")


def test_exports_strip_unicode_format_controls_from_untrusted_text() -> None:
    event, investigation = incident_fixture()
    dangerous = "abc\u202etxt.exe\u2066hidden\u2069"
    event = event.model_copy(update={"title": dangerous, "evidence": {"message": dangerous}})

    markdown = export_markdown(event, investigation)
    rendered_json = export_json(event, investigation)

    for control in ("\u202e", "\u2066", "\u2069"):
        assert control not in markdown
        assert control not in rendered_json
    assert "abctxt.exehidden" in markdown


def test_json_redacts_secret_before_stripping_embedded_controls() -> None:
    event, investigation = incident_fixture()
    secret = "credential\x1bvalue"
    event = event.model_copy(update={"evidence": {"credential": secret}})

    rendered = export_json(event, investigation, secrets=[secret])

    assert "credentialvalue" not in rendered
    assert json.loads(rendered)["event"]["evidence"]["credential"] == "[REDACTED]"


def test_exports_redact_secret_reconstructed_by_control_stripping() -> None:
    event, investigation = incident_fixture()
    secret = "credential-value"
    separated = "credential-\x1bvalue"
    event = event.model_copy(update={"summary": separated, "evidence": {"credential": separated}})

    json_rendered = export_json(event, investigation, secrets=[secret])
    markdown = export_markdown(event, investigation, secrets=[secret])

    assert secret not in json_rendered
    assert secret not in markdown
    assert json.loads(json_rendered)["event"]["evidence"]["credential"] == "[REDACTED]"


@pytest.mark.parametrize("exporter", [export_json, export_markdown])
def test_complete_investigation_requires_assessment_and_usage(exporter) -> None:
    event, investigation = incident_fixture()
    incomplete = investigation.model_copy(update={"assessment": None})

    with pytest.raises(ValueError, match="missing assessment or usage"):
        exporter(event, incomplete)
