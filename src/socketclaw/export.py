"""Deterministic, secret-safe incident exports."""

from __future__ import annotations

import json
from collections.abc import Sequence

from .openai import redact_secrets
from .storage import StoredEvent, StoredInvestigation


def export_json(
    event: StoredEvent,
    investigation: StoredInvestigation | None,
    *,
    secrets: Sequence[str] = (),
) -> str:
    """Export one incident as stable, redacted JSON."""
    payload = {
        "event": event.model_dump(mode="json"),
        "investigation": (
            investigation.model_dump(mode="json") if investigation is not None else None
        ),
    }
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return redact_secrets(rendered, secrets) + "\n"


def export_markdown(
    event: StoredEvent,
    investigation: StoredInvestigation | None,
    *,
    secrets: Sequence[str] = (),
) -> str:
    """Export one incident as an operator-readable Markdown report."""
    signal_lines = (
        "\n".join(
            f"- `{signal.code}` (+{signal.points}) - {signal.detail}" for signal in event.signals
        )
        or "- No deterministic detection signals were recorded."
    )
    evidence = json.dumps(
        event.evidence,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    sections = [
        "# SocketClaw Incident",
        "",
        f"**Event ID:** `{event.id}`  ",
        f"**Observed:** {event.observed_at.isoformat()}  ",
        f"**Severity:** {event.severity.value.upper()} ({event.score}/100)  ",
        f"**Source:** `{event.source.value}`  ",
        f"**Target:** {event.target or '-'}",
        "",
        f"## {event.title}",
        "",
        event.summary,
        "",
        "## Detection signals",
        "",
        signal_lines,
        "",
        "## Evidence",
        "",
        "```json",
        evidence,
        "```",
        "",
    ]
    if investigation is None:
        sections.extend(
            [
                "## AI investigation",
                "",
                "No AI investigation has been recorded.",
                "",
            ]
        )
    elif investigation.status == "failed":
        sections.extend(
            [
                "## AI investigation",
                "",
                "**Status:** Failed  ",
                f"**Model:** `{investigation.model_id}`  ",
                f"**Reasoning effort:** `{investigation.requested_effort}`",
                "",
                investigation.error or "The provider did not return an error message.",
                "",
            ]
        )
    else:
        assessment = investigation.assessment
        usage = investigation.usage
        if assessment is None or usage is None:
            raise ValueError("complete investigation is missing assessment or usage")
        rationale = "\n".join(f"- {item}" for item in assessment.rationale)
        actions = (
            "\n".join(f"- {item}" for item in assessment.recommended_actions)
            or "- No additional action was recommended."
        )
        sections.extend(
            [
                "## AI investigation",
                "",
                f"**Model:** `{investigation.model_id}`  ",
                f"**Reasoning effort:** `{investigation.requested_effort}`  ",
                f"**Classification:** {assessment.classification.upper()}  ",
                f"**Confidence:** {assessment.confidence:.0%}  ",
                f"**Tokens:** {usage.total_tokens or 0}  ",
                f"**Estimated cost:** ${usage.cost_usd:.6f}  ",
                f"**Latency:** {usage.latency_ms} ms",
                "",
                assessment.summary,
                "",
                "### Rationale",
                "",
                rationale,
                "",
                "### Recommended actions",
                "",
                actions,
                "",
            ]
        )
    return redact_secrets("\n".join(sections), secrets).rstrip() + "\n"
