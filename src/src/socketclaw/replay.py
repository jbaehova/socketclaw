"""Deterministic, read-only candidate-policy evaluation over retained evidence."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from .detection import CorrelationIndex, Detector, correlation_key, correlation_time
from .domain import SecurityEvent
from .rules import RuleConfig


@dataclass(frozen=True)
class ReplayChange:
    event_id: str
    before_score: int
    after_score: int
    before_severity: str
    after_severity: str
    signal_codes: tuple[str, ...]


@dataclass(frozen=True)
class ReplayReport:
    evidence_fingerprint: str
    candidate_fingerprint: str
    observation_count: int
    baseline_alert_count: int
    candidate_alert_count: int
    baseline_incident_estimate: int
    candidate_incident_estimate: int
    before_severities: dict[str, int]
    after_severities: dict[str, int]
    added_candidates: tuple[str, ...]
    missed_candidates: tuple[str, ...]
    changes: tuple[ReplayChange, ...]
    limitations: tuple[str, ...] = (
        "Only retained observations are evaluated; discarded normal log lines cannot be restored.",
        "Incident counts estimate grouped alerts; "
        "operator decisions and suppression are not replayed.",
        "Added alerts need review, not all are false positives; "
        "removed alerts are not proven misses.",
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def replay_events(
    observations: Sequence[SecurityEvent],
    config: RuleConfig,
    *,
    after: datetime | None = None,
    before: datetime | None = None,
    sources: Sequence[str] | None = None,
) -> ReplayReport:
    """Re-score a stable snapshot without mutating its records or any database.

    Time filters use persisted correlation time, inclusive at both boundaries.
    Evidence outside the selected range is intentionally not included in counts.
    """
    for boundary in (after, before):
        if boundary is not None and boundary.tzinfo is None:
            raise ValueError("Replay boundaries require timezones")
    if after is not None and before is not None and after > before:
        raise ValueError("Replay start must not exceed its end")
    selected = sorted(
        (
            event
            for event in observations
            if (after is None or correlation_time(event) >= after)
            and (before is None or correlation_time(event) <= before)
            and (sources is None or event.source.value in sources)
        ),
        key=lambda event: (correlation_time(event), str(event.id)),
    )
    evidence_json = json.dumps(
        [event.model_dump(mode="json") for event in selected],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    version: UUID = uuid5(NAMESPACE_URL, config.fingerprint)
    candidates = [event.model_copy(update={"rule_version": version}) for event in selected]
    detector = Detector(config)
    changes: list[ReplayChange] = []
    scored: list[SecurityEvent] = []
    index = CorrelationIndex(config)
    for event in candidates:
        detection = detector.score(event, index)
        index.append(event)
        scored.append(
            event.model_copy(update={"score": detection.score, "severity": detection.severity})
        )
        changes.append(
            ReplayChange(
                str(event.id),
                event.score,
                detection.score,
                event.severity.value,
                detection.severity.value,
                tuple(signal.code for signal in detection.signals),
            )
        )
    return ReplayReport(
        evidence_fingerprint=hashlib.sha256(evidence_json.encode()).hexdigest(),
        candidate_fingerprint=config.fingerprint,
        observation_count=len(selected),
        baseline_alert_count=sum(event.score >= 40 for event in selected),
        candidate_alert_count=sum(event.score >= 40 for event in scored),
        baseline_incident_estimate=_incident_estimate(selected, config.window_seconds),
        candidate_incident_estimate=_incident_estimate(scored, config.window_seconds),
        before_severities=dict(sorted(Counter(event.severity.value for event in selected).items())),
        after_severities=dict(sorted(Counter(event.severity.value for event in scored).items())),
        added_candidates=tuple(
            item.event_id for item in changes if item.before_score < 40 <= item.after_score
        ),
        missed_candidates=tuple(
            item.event_id for item in changes if item.after_score < 40 <= item.before_score
        ),
        changes=tuple(item for item in changes if item.before_score != item.after_score),
    )


def _incident_estimate(events: Sequence[SecurityEvent], window_seconds: int) -> int:
    last: dict[tuple[str, ...], datetime] = {}
    count = 0
    for event in events:
        if event.score < 40:
            continue
        key = (event.source.value, event.event_type, *(correlation_key(event) or (str(event.id),)))
        at = correlation_time(event)
        previous = last.get(key)
        if previous is None or (at - previous).total_seconds() > window_seconds:
            count += 1
        last[key] = at
    return count
