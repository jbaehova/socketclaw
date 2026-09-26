"""Explainable, deterministic security event scoring."""

from __future__ import annotations

import math
import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from .domain import DetectionResult, DetectionSignal, SecurityEvent, severity_for_score
from .rules import RuleConfig

_SENSITIVE_PORTS = {
    21,
    22,
    23,
    25,
    53,
    110,
    135,
    139,
    445,
    1433,
    2375,
    3306,
    3389,
    5432,
    5900,
    6379,
    9200,
    11211,
    27017,
}
_MALWARE_TERMS = ("malware", "ransomware", "trojan", "rootkit", "cryptominer")
_AUTH_FAILURE_TERMS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "login failed",
)
_FIREWALL_DENIAL = re.compile(r"(?:firewall.*den(?:y|ied)|\bDROP\b|\bREJECT\b)", re.I)


class Detector:
    """Score normalized events without requiring an AI or network connection."""

    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()
        self.window = timedelta(seconds=self.config.window_seconds)

    def score(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent] | CorrelationIndex,
    ) -> DetectionResult:
        signals: list[DetectionSignal] = []

        if event.source == "ping":
            self._score_ping(event, recent, signals)
        elif event.source == "port_scan":
            self._score_ports(event, signals)
        elif event.source == "log":
            self._score_log(event, recent, signals)

        elif (
            event.source == "system"
            and event.evidence.get("confirmed") is True
            and event.evidence.get("required", True)
        ):
            if event.event_type == "service.failed":
                signals.append(
                    _signal(
                        "service.failed",
                        "Required service failed",
                        70,
                        "The required endpoint failed its configured consecutive checks.",
                    )
                )
            elif event.event_type == "service.unknown":
                signals.append(
                    _signal(
                        "service.unknown",
                        "Service measurement unavailable",
                        40,
                        "The required endpoint could not be measured across consecutive checks.",
                    )
                )

        signals = [
            signal.model_copy(update={"points": self.config.points.for_code(signal.code)})
            for signal in signals
        ]
        score = min(100, sum(signal.points for signal in signals))
        return DetectionResult(
            score=score,
            severity=severity_for_score(score),
            signals=tuple(signals),
        )

    def _score_ping(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent] | CorrelationIndex,
        signals: list[DetectionSignal],
    ) -> None:
        if event.evidence.get("outcome") in {"error", "unknown"}:
            return
        loss = _number(event.evidence.get("packet_loss"))
        if loss >= 100:
            signals.append(
                _signal(
                    "ping.total_loss",
                    "No ICMP replies",
                    70,
                    "ICMP packet loss reached 100%; service availability is not established.",
                )
            )
        elif loss >= self.config.ping_high_loss_percent:
            signals.append(
                _signal(
                    "ping.high_loss",
                    "Severe packet loss",
                    45,
                    f"Packet loss reached {loss:g}%.",
                )
            )
        elif loss >= self.config.ping_degraded_percent:
            signals.append(
                _signal(
                    "ping.degraded",
                    "Connection degraded",
                    25,
                    f"Packet loss reached {loss:g}%.",
                )
            )

        if (
            loss >= self.config.ping_high_loss_percent
            and self._related_count(
                event, recent, "ping", limit=self.config.ping_sustained_count - 1
            )
            >= self.config.ping_sustained_count - 1
        ):
            signals.append(
                _signal(
                    "ping.sustained_loss",
                    "Packet loss is sustained",
                    25,
                    f"At least {self.config.ping_sustained_count} high-loss observations occurred "
                    f"within {self.config.window_seconds} seconds.",
                )
            )

    def _score_ports(
        self,
        event: SecurityEvent,
        signals: list[DetectionSignal],
    ) -> None:
        violations = event.evidence.get("exposure_violations")
        if isinstance(violations, list) and violations:
            signals.append(
                _signal(
                    "port.unexpected_exposure",
                    "Unexpected local binding",
                    55,
                    "A measured local listener exceeds its configured exposure scope. "
                    "Binding and process evidence are retained; "
                    "internet reachability is unknown.",
                )
            )
        initial_sensitive = sorted(
            set(_ports(event.evidence.get("initial_open_ports"))) & _SENSITIVE_PORTS
        )
        if initial_sensitive:
            signals.append(
                _signal(
                    "port.sensitive_exposure",
                    "Sensitive service observed",
                    35,
                    f"First confirmed exposure of TCP ports: {_port_list(initial_sensitive)}. "
                    "No prior closed state was established.",
                )
            )
        opened = _ports(event.evidence.get("newly_opened"))
        closed = _ports(event.evidence.get("newly_closed"))
        if opened:
            signals.append(
                _signal(
                    "port.newly_opened",
                    "New listening port",
                    20,
                    f"Newly opened TCP ports: {_port_list(opened)}.",
                )
            )
            sensitive = sorted(set(opened) & _SENSITIVE_PORTS)
            if sensitive:
                signals.append(
                    _signal(
                        "port.sensitive_opened",
                        "Sensitive service exposed",
                        35,
                        f"Sensitive TCP ports opened: {_port_list(sensitive)}.",
                    )
                )
            if len(opened) >= self.config.port_open_count:
                signals.append(
                    _signal(
                        "port.open_burst",
                        "Many ports opened together",
                        60,
                        f"{len(opened)} TCP ports appeared in one scan.",
                    )
                )
        if closed:
            signals.append(
                _signal(
                    "port.closed",
                    "Listening port closed",
                    0,
                    f"Closed TCP ports: {_port_list(closed)}.",
                )
            )

    def _score_log(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent] | CorrelationIndex,
        signals: list[DetectionSignal],
    ) -> None:
        message = str(event.evidence.get("message", "")).casefold()
        if (
            event.evidence.get("action") == "malware_detected"
            and event.evidence.get("parser") == "clamav"
        ):
            signals.append(
                _signal(
                    "log.malware_indicator",
                    "Security tool detection",
                    80,
                    "ClamAV reported FOUND. Signature and affected path are retained in evidence.",
                )
            )
        elif event.event_type == "log.unverified_indicator" or any(
            re.search(r"\b" + term + r"\b", message) for term in _MALWARE_TERMS
        ):
            signals.append(
                _signal(
                    "log.unverified_indicator",
                    "Unverified security keyword",
                    10,
                    "A security-related term is present. This is not a confirmed malware finding.",
                )
            )
        if event.event_type == "log.sudo_execution":
            signals.append(
                _signal(
                    "log.sudo_execution",
                    "Approved sudo execution",
                    0,
                    "A sudo command was recorded. This alone does not establish malicious intent.",
                )
            )
        if event.event_type == "log.auth_success" and event.evidence.get("user"):
            failures = self._related_count(
                event, recent, "auth", before_only=True, limit=self.config.auth_failure_count
            )
            if failures >= self.config.auth_failure_count:
                signals.append(
                    _signal(
                        "log.auth_after_failures",
                        "Login after repeated failures",
                        60,
                        "This account and source authenticated after repeated failures "
                        "on the same asset.",
                    )
                )
        is_auth_failure = event.event_type == "log.auth_failure" or any(
            term in message for term in _AUTH_FAILURE_TERMS
        )
        if is_auth_failure:
            signals.append(
                _signal(
                    "log.auth_failure",
                    "Authentication failure",
                    25,
                    "The log records a failed authentication attempt.",
                )
            )
            matching = self._related_count(
                event, recent, "auth", limit=self.config.auth_failure_count - 1
            )
            if matching >= self.config.auth_failure_count - 1:
                signals.append(
                    _signal(
                        "log.auth_burst",
                        "Authentication failure burst",
                        75,
                        f"At least {self.config.auth_failure_count} failures from the same target "
                        f"or log source occurred within {self.config.window_seconds} seconds.",
                    )
                )
        if event.event_type == "log.privilege_escalation":
            signals.append(
                _signal(
                    "log.privilege_escalation",
                    "Privilege escalation",
                    45,
                    "An explicitly classified privilege escalation event was recorded.",
                )
            )
        denial_count = _firewall_denial_count(event)
        is_firewall_denial = denial_count > 0
        if is_firewall_denial:
            signals.append(
                _signal(
                    "log.firewall_denial",
                    "Firewall denial",
                    15,
                    "The log records a denied network connection.",
                )
            )
        if denial_count:
            denial_count += self._related_count(
                event, recent, "firewall", limit=self.config.firewall_denial_count
            )
        if denial_count >= self.config.firewall_denial_count:
            signals.append(
                _signal(
                    "log.firewall_denial_burst",
                    "Firewall denial burst",
                    40,
                    f"At least {denial_count} firewall denials occurred "
                    "within the correlation window.",
                )
            )

    def _related_count(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent] | CorrelationIndex,
        kind: str,
        *,
        before_only: bool = False,
        limit: int,
    ) -> int:
        if isinstance(recent, CorrelationIndex):
            return recent.count(event, self.window, kind, before_only=before_only, limit=limit)
        selected = [
            candidate
            for candidate in recent
            if _sample_weight(candidate, kind, self.config) > 0
            and (not before_only or correlation_time(candidate) <= correlation_time(event))
        ]
        return sum(
            _sample_weight(candidate, kind, self.config)
            for candidate in self._related(event, selected)
        )

    def _related(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent],
        *,
        minimum_loss: float | None = None,
    ) -> list[SecurityEvent]:
        at = correlation_time(event)
        earliest = at - self.window
        latest = (
            at + self.window
            if event.source == "log" and correlation_basis(event) in {"source", "delayed_source"}
            else at
        )
        key = correlation_key(event)
        if key is None:
            return []
        related = [
            candidate
            for candidate in recent
            if candidate.id != event.id
            and candidate.source == event.source
            and correlation_key(candidate) == key
            and candidate.rule_version == event.rule_version
            and earliest <= correlation_time(candidate) <= latest
        ]
        if event.source == "log" and related:
            # Pick one genuine window containing this event, not a 2-window union.
            related.sort(key=lambda candidate: (correlation_time(candidate), str(candidate.id)))
            best: list[SecurityEvent] = []
            right = 0
            for left, candidate in enumerate(related):
                start = min(at, correlation_time(candidate))
                end = start + self.window
                while right < len(related) and correlation_time(related[right]) <= end:
                    right += 1
                if len(best) < right - left:
                    best = related[left:right]
                if correlation_time(candidate) >= at:
                    break
            related = best
        if minimum_loss is not None:
            related = [
                candidate
                for candidate in related
                if candidate.evidence.get("outcome") not in {"error", "unknown"}
                and _number(candidate.evidence.get("packet_loss")) >= minimum_loss
            ]
        return related


def _signal(
    code: str,
    label: str,
    points: int,
    detail: str,
) -> DetectionSignal:
    return DetectionSignal(code=code, label=label, points=points, detail=detail)


def _number(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int | float):
        number = float(value)
        return number if math.isfinite(number) else 0.0
    try:
        number = float(str(value))
        return number if math.isfinite(number) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _ports(value: object) -> list[int]:
    if not isinstance(value, list | tuple | set):
        return []
    ports: list[int] = []
    for item in cast(Iterable[object], value):
        if isinstance(item, bool):
            continue
        if not isinstance(item, int | float | str):
            continue
        try:
            numeric = float(item)
            if not math.isfinite(numeric) or not numeric.is_integer():
                continue
            port = int(numeric)
        except (TypeError, ValueError, OverflowError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return sorted(ports)


def _port_list(ports: list[int]) -> str:
    shown = ", ".join(str(port) for port in ports[:24])
    return (
        shown if len(ports) <= 24 else f"{shown} (+{len(ports) - 24} more; full list in evidence)"
    )


def correlation_time(event: SecurityEvent) -> datetime:
    """Use trusted event time while preserving the historical ingestion field."""
    recorded = getattr(event, "correlation_at", None)
    if recorded is not None:
        return recorded
    collected = getattr(event, "collected_at", None) or event.ingested_at or event.observed_at
    if (
        event.source == "log"
        and event.source_at is not None
        and event.evidence.get("source_time_quality") == "explicit_timezone"
        and event.source_at <= collected
    ):
        return event.source_at
    return collected


def correlation_basis(event: SecurityEvent) -> str:
    collected = getattr(event, "collected_at", None) or event.ingested_at or event.observed_at
    if (
        event.source == "log"
        and event.source_at is not None
        and event.evidence.get("source_time_quality") == "explicit_timezone"
    ):
        if event.source_at > collected:
            return "future_source_fallback"
        return "delayed_source" if collected - event.source_at > timedelta(minutes=5) else "source"
    return "collected"


def correlation_key(event: SecurityEvent) -> tuple[str, ...] | None:
    if event.source == "log" and isinstance(event.evidence.get("asset"), str):
        return (
            "asset",
            str(event.evidence["asset"]).casefold(),
            str(event.evidence.get("user") or ""),
            str(event.evidence.get("actor_ip") or event.evidence.get("source_ip") or ""),
        )
    if event.target is not None:
        return ("target", event.target.casefold())
    path = event.evidence.get("path")
    if event.source == "log" and isinstance(path, str) and path:
        return ("path", path)
    return None


def _firewall_denial_count(event: SecurityEvent) -> int:
    reported = max(0, int(_number(event.evidence.get("denial_count"))))
    message = str(event.evidence.get("message", ""))
    if (
        event.event_type == "log.firewall_denial"
        or reported > 0
        or _FIREWALL_DENIAL.search(message) is not None
    ):
        return max(1, reported)
    return 0


# Compatibility for integrations which used the former private helper.
_correlation_key = correlation_key


@dataclass
class _Samples:
    times: list[datetime] = field(default_factory=lambda: list[datetime]())
    weights: list[int] = field(default_factory=lambda: list[int]())
    cumulative: list[int] = field(default_factory=lambda: [0])
    ids: dict[UUID, tuple[datetime, int]] = field(
        default_factory=lambda: dict[UUID, tuple[datetime, int]]()
    )

    def append(self, event: SecurityEvent, weight: int) -> None:
        if event.id in self.ids:
            return
        at = correlation_time(event)
        index = bisect_right(self.times, at)
        self.times.insert(index, at)
        self.weights.insert(index, weight)
        self.ids[event.id] = (at, weight)
        self.cumulative.insert(index + 1, self.cumulative[index] + weight)
        for position in range(index + 2, len(self.cumulative)):
            self.cumulative[position] += weight

    def total(self, start: datetime, end: datetime, event: SecurityEvent) -> int:
        left, right = bisect_left(self.times, start), bisect_right(self.times, end)
        value = self.cumulative[right] - self.cumulative[left]
        own = self.ids.get(event.id)
        return value - own[1] if own is not None and start <= own[0] <= end else value


class CorrelationIndex:
    """Prepared numeric history, isolated by rule activation and correlation identity.

    Construct once per batch history and append each committed candidate. Ordinary
    forward windows use two binary searches. Reordered source events examine exact
    windows containing the candidate and stop once the configured threshold is met.
    The index owns no database connection and never mutates evidence.
    """

    def __init__(self, config: RuleConfig, observations: Iterable[SecurityEvent] = ()) -> None:
        self.config = config
        self._groups: dict[tuple[object, ...], _Samples] = {}
        for event in sorted(observations, key=correlation_time):
            self.append(event)

    def _key(self, event: SecurityEvent, kind: str) -> tuple[object, ...] | None:
        identity = correlation_key(event)
        if identity is None:
            return None
        return (event.source.value, event.rule_version, identity, kind)

    def append(self, event: SecurityEvent) -> None:
        for kind in ("auth", "firewall", "ping"):
            weight = _sample_weight(event, kind, self.config)
            key = self._key(event, kind)
            if weight > 0 and key is not None:
                self._groups.setdefault(key, _Samples()).append(event, weight)

    def count(
        self,
        event: SecurityEvent,
        window: timedelta,
        kind: str,
        *,
        before_only: bool = False,
        limit: int,
    ) -> int:
        key = self._key(event, kind)
        samples = self._groups.get(key) if key is not None else None
        if samples is None:
            return 0
        at = correlation_time(event)
        earliest = at - window
        best = samples.total(earliest, at, event)
        symmetric = (
            event.source == "log"
            and not before_only
            and correlation_basis(event) in {"source", "delayed_source"}
        )
        if not symmetric or best >= limit:
            return best
        index = bisect_left(samples.times, earliest)
        while index < len(samples.times) and samples.times[index] <= at:
            start = samples.times[index]
            best = max(best, samples.total(start, start + window, event))
            if best >= limit:
                return best
            index = bisect_right(samples.times, start)
        return max(best, samples.total(at, at + window, event))


def _sample_weight(event: SecurityEvent, kind: str, config: RuleConfig) -> int:
    if kind == "ping":
        return int(
            event.source == "ping"
            and event.evidence.get("outcome") not in {"error", "unknown"}
            and _number(event.evidence.get("packet_loss")) >= config.ping_high_loss_percent
        )
    if event.source != "log":
        return 0
    if kind == "firewall":
        return _firewall_denial_count(event)
    return int(
        event.event_type == "log.auth_failure"
        or any(
            term in str(event.evidence.get("message", "")).casefold()
            for term in _AUTH_FAILURE_TERMS
        )
    )
