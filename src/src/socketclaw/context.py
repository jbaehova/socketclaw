"""Bounded, inspectable incident evidence and deterministic local guidance."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .domain import Assessment, SecurityEvent
from .redaction import redact_data
from .response_actions import incident_runbook

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .storage import IncidentReport


class IncidentContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    incident: dict[str, JsonValue]
    evidence: tuple[dict[str, JsonValue], ...]
    history: dict[str, JsonValue]
    maintenance: tuple[dict[str, JsonValue], ...] = ()
    actions: tuple[dict[str, JsonValue], ...] = ()
    omissions: tuple[str, ...] = ()
    collection_gaps: tuple[str, ...] = ()
    local_summary: tuple[str, ...] = ()
    runbook: tuple[str, ...] = ()
    selection_policy: str = (
        "Selected observation first, then latest recovery and normal context, then "
        "newest observations; "
        "oldest evidence and historical detail omitted first to meet the byte budget. "
        "Addresses and account identities are included explicitly for correlation. "
        "Credential fields and recognized secret patterns are redacted; arbitrary "
        "secrets may remain."
    )

    def preview(self, *, secrets: Sequence[str] = ()) -> str:
        return json.dumps(
            redact_data(self.model_dump(mode="json"), secrets), ensure_ascii=False, indent=2
        )


class EvidenceFact(BaseModel):
    """A factual assertion is an exact quoted scalar at an evidence JSON path."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    evidence_id: str = Field(min_length=1, max_length=100)
    field: str = Field(min_length=1, max_length=500)
    value: str = Field(max_length=2000)


class ContextAssessment(Assessment):
    observed_facts: tuple[EvidenceFact, ...] = Field(min_length=1, max_length=12)
    possible_explanations: tuple[str, ...] = Field(max_length=6)
    missing_evidence: tuple[str, ...] = Field(max_length=6)
    next_checks: tuple[str, ...] = Field(max_length=6)


def grounded_assessment(value: object, context: IncidentContext) -> Assessment:
    """Reject missing/fabricated citations and retain facts separately from hypotheses.

    Only exact scalar evidence is accepted as an observed fact. This deliberately
    does not claim to validate the truth of model hypotheses or detect all prose
    hallucinations; model-written summary/rationale are replaced with grounded facts.
    """
    result = ContextAssessment.model_validate(value)
    evidence = {str(item.get("id")): item for item in context.evidence}
    facts: list[str] = []
    for fact in result.observed_facts:
        node: object = evidence.get(fact.evidence_id)
        if node is None:
            raise ValueError("observed fact cites evidence not supplied to the model")
        for key in fact.field.split("."):
            if isinstance(node, dict):
                node = cast(dict[str, object], node).get(key)
            elif (
                isinstance(node, list)
                and key.isdigit()
                and int(key) < len(cast(list[object], node))
            ):
                node = cast(list[object], node)[int(key)]
            else:
                raise ValueError("observed fact cites a nonexistent evidence field")
        if isinstance(node, dict | list) or node is None:
            raise ValueError("observed facts must cite a present scalar evidence field")
        expected = node if isinstance(node, str) else json.dumps(node, ensure_ascii=False)
        if fact.value != expected:
            raise ValueError("observed fact does not match its cited evidence")
        facts.append(f"[{fact.evidence_id}] {fact.field}: {fact.value}"[:500])
    explanations = [
        f"Possible explanation (unverified): {s}"[:500] for s in result.possible_explanations
    ]
    gaps = [f"Missing evidence: {s}"[:500] for s in result.missing_evidence]
    return Assessment(
        classification=result.classification,
        confidence=result.confidence,
        summary="Observed facts: " + " | ".join(facts)[:1980],
        rationale=tuple((facts + explanations + gaps)[:12]),
        recommended_actions=tuple(s[:500] for s in result.next_checks),
        response_proposal=result.response_proposal,
    )


def build_incident_context(
    report: IncidentReport | None,
    focus_event: SecurityEvent | None = None,
    *,
    max_events: int = 24,
    max_bytes: int = 48 * 1024,
) -> IncidentContext:
    """Build a deterministic context with explicit count and byte omissions."""
    if max_events < 1 or max_bytes < 4096:
        raise ValueError("context requires at least one event and a 4096-byte budget")
    observations = list(report.observations) if report is not None else []
    if focus_event is not None and all(item.id != focus_event.id for item in observations):
        observations.insert(0, focus_event)  # type: ignore[arg-type]
    links = {str(link.event_id): link.kind for link in report.history.links} if report else {}
    ordered = sorted(
        observations,
        key=lambda item: (item.correlation_at or item.source_at or item.observed_at, str(item.id)),
        reverse=True,
    )
    selected: list[SecurityEvent] = []
    if focus_event is not None:
        selected.append(focus_event)
    for item in ordered:
        if links.get(str(item.id)) in {"observed_recovery", "context"} and item not in selected:
            selected.append(item)
            break
    selected.extend(item for item in ordered if item not in selected)
    selected = selected[:max_events]
    omissions: list[str] = []
    if len(observations) > len(selected):
        omissions.append(
            f"{len(observations) - len(selected)} observations omitted by event count limit."
        )
    if report is not None:
        omitted = getattr(report, "omitted_observations", 0)
        if omitted:
            omissions.append(f"{omitted} observations omitted by repository report limit.")
        omissions.extend(str(item) for item in getattr(report, "omissions", ()))
        incident = cast(dict[str, JsonValue], report.history.incident.model_dump(mode="json"))
        family = report.history.incident.family
        history = cast(dict[str, JsonValue], report.history.model_dump(mode="json"))
        history.pop("incident", None)
        # History may be large even when observation evidence is bounded.
        for key in ("links", "notes", "transitions", "occurrences"):
            value = history.get(key)
            if isinstance(value, list) and len(value) > max_events:
                history[key] = value[-max_events:]
                omissions.append(f"{len(value) - max_events} older {key} omitted.")
        maintenance = tuple(
            item.model_dump(mode="json")
            for item in getattr(report, "suppressions", ())[-max_events:]
        )
        maintenance += tuple(
            item.model_dump(mode="json") for item in report.maintenance_rules[:max_events]
        )
        actions = tuple(
            item.model_dump(mode="json")
            for item in getattr(report, "action_records", ())[-max_events:]
        )
    else:
        incident, history, family, maintenance, actions = {}, {}, "unknown", (), ()
        omissions.append(
            "No incident history is available; context contains only the selected observation."
        )
    evidence = [cast(dict[str, JsonValue], item.model_dump(mode="json")) for item in selected]
    gaps = [
        "Evidence describes collected sources only; uncollected processes, "
        "sessions and network paths are unknown."
    ]
    if report is not None:
        gaps.extend(
            f"[{gap.id}] {gap.probe_id}: {gap.reason} at {gap.detected_at.isoformat()}"
            for gap in report.collection_gaps[:max_events]
        )
    for item in selected:
        if item.evidence.get("error") or item.evidence.get("status") in {
            "unknown",
            "unsupported",
            "partial",
        }:
            gaps.append(f"[{item.id}] Collection incomplete: {item.summary[:300]}")
    local_summary = _local_summary(report, selected)
    context = IncidentContext(
        incident=incident,
        evidence=tuple(evidence),
        history=history,
        maintenance=maintenance,
        actions=actions,
        omissions=tuple(omissions),
        collection_gaps=tuple(gaps),
        local_summary=local_summary,
        runbook=incident_runbook(family),
    )

    def size(item: IncidentContext) -> int:
        return len(item.model_dump_json().encode("utf-8"))

    if size(context) > max_bytes:
        omissions.append(
            "Byte budget applied: older evidence and history details omitted; "
            "request original local evidence by ID."
        )
    while size(context) > max_bytes and len(evidence) > 1:
        evidence.pop()
        context = context.model_copy(
            update={"evidence": tuple(evidence), "omissions": tuple(omissions)}
        )
    if size(context) > max_bytes:
        context = context.model_copy(
            update={"history": {}, "maintenance": (), "actions": (), "omissions": tuple(omissions)}
        )
    if size(context) > max_bytes and evidence:
        event = selected[0]
        compact: dict[str, JsonValue] = {
            "id": str(event.id),
            "observed_at": event.observed_at.isoformat(),
            "source": event.source.value,
            "target": event.target,
            "score": event.score,
            "title": event.title,
            "summary": event.summary[:500],
        }
        omissions.append(
            "Selected observation evidence payload omitted because it exceeds the byte budget."
        )
        context = context.model_copy(update={"evidence": (compact,), "omissions": tuple(omissions)})
    if size(context) > max_bytes:
        context = context.model_copy(
            update={
                "local_summary": context.local_summary[:1],
                "collection_gaps": context.collection_gaps[:1],
                "incident": {
                    k: v
                    for k, v in incident.items()
                    if k in {"id", "status", "family", "current_occurrence_id"}
                },
                "omissions": (
                    "Context shortened to meet byte budget; inspect full local "
                    "incident report for omitted history and evidence.",
                ),
            }
        )
    if size(context) > max_bytes:
        raise ValueError("context metadata exceeds the configured byte budget")
    return context


def _local_summary(report: IncidentReport | None, events: list[SecurityEvent]) -> tuple[str, ...]:
    lines: list[str] = []
    if report:
        item = report.history.incident
        lines.append(
            f"{item.family}: {item.status}; occurrence {item.occurrence_count}; "
            f"{item.observation_count} observations."
        )
        current = next(
            (o for o in report.history.occurrences if o.id == item.current_occurrence_id), None
        )
        lines.append(
            f"Measured recovery: {current.recovered_at.isoformat()}"
            if current and current.recovered_at
            else "Recovery has not been observed for the current occurrence."
        )
        lines.append(
            "Maintenance decisions and operator notes are recorded separately from measured facts."
        )
    for event in events[:4]:
        lines.append(
            f"[{event.id}] {event.observed_at.isoformat()} {event.title}: {event.summary[:240]}"
        )
    if not events:
        lines.append(
            "No observations available. The absence of evidence does not establish safety."
        )
    return tuple(lines)
