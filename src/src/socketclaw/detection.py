"""Explainable, deterministic security event scoring."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import cast

from .domain import DetectionResult, DetectionSignal, SecurityEvent, severity_for_score

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

    window = timedelta(minutes=5)

    def score(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent],
    ) -> DetectionResult:
        signals: list[DetectionSignal] = []

        if event.source == "ping":
            self._score_ping(event, recent, signals)
        elif event.source == "port_scan":
            self._score_ports(event, signals)
        elif event.source == "log":
            self._score_log(event, recent, signals)

        score = min(100, sum(signal.points for signal in signals))
        return DetectionResult(
            score=score,
            severity=severity_for_score(score),
            signals=tuple(signals),
        )

    def _score_ping(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent],
        signals: list[DetectionSignal],
    ) -> None:
        loss = _number(event.evidence.get("packet_loss"))
        if loss >= 100:
            signals.append(
                _signal(
                    "ping.total_loss",
                    "Target stopped responding",
                    70,
                    "Packet loss reached 100%.",
                )
            )
        elif loss >= 50:
            signals.append(
                _signal(
                    "ping.high_loss",
                    "Severe packet loss",
                    45,
                    f"Packet loss reached {loss:g}%.",
                )
            )
        elif loss >= 20:
            signals.append(
                _signal(
                    "ping.degraded",
                    "Connection degraded",
                    25,
                    f"Packet loss reached {loss:g}%.",
                )
            )

        if loss >= 50 and len(self._related(event, recent, minimum_loss=50)) >= 3:
            signals.append(
                _signal(
                    "ping.sustained_loss",
                    "Packet loss is sustained",
                    25,
                    "At least four high-loss observations occurred within five minutes.",
                )
            )

    def _score_ports(
        self,
        event: SecurityEvent,
        signals: list[DetectionSignal],
    ) -> None:
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
            if len(opened) >= 5:
                signals.append(
                    _signal(
                        "port.open_burst",
                        "Many ports opened together",
                        60,
                        f"{len(opened)} TCP ports appeared in one scan.",
                    )
                )
        elif closed:
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
        recent: Sequence[SecurityEvent],
        signals: list[DetectionSignal],
    ) -> None:
        message = str(event.evidence.get("message", "")).casefold()
        if event.event_type == "log.malware_indicator" or any(
            term in message for term in _MALWARE_TERMS
        ):
            signals.append(
                _signal(
                    "log.malware_indicator",
                    "Malware indicator",
                    80,
                    "The log entry contains a known malware indicator.",
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
            matching = [
                candidate
                for candidate in self._related(event, recent)
                if candidate.event_type == "log.auth_failure"
                or any(
                    term in str(candidate.evidence.get("message", "")).casefold()
                    for term in _AUTH_FAILURE_TERMS
                )
            ]
            if len(matching) >= 5:
                signals.append(
                    _signal(
                        "log.auth_burst",
                        "Authentication failure burst",
                        75,
                        "At least six failures from the same target or log source occurred "
                        "within five minutes.",
                    )
                )
        if event.event_type == "log.privilege_escalation" or (
            "privilege escalation" in message or "sudo:" in message
        ):
            signals.append(
                _signal(
                    "log.privilege_escalation",
                    "Privilege escalation",
                    45,
                    "The log records a privileged execution event.",
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
            denial_count += sum(
                _firewall_denial_count(candidate) for candidate in self._related(event, recent)
            )
        if denial_count >= 10:
            signals.append(
                _signal(
                    "log.firewall_denial_burst",
                    "Firewall denial burst",
                    40,
                    f"{denial_count} firewall denials were grouped in this event.",
                )
            )

    def _related(
        self,
        event: SecurityEvent,
        recent: Sequence[SecurityEvent],
        *,
        minimum_loss: float | None = None,
    ) -> list[SecurityEvent]:
        earliest = event.observed_at - self.window
        correlation_key = _correlation_key(event)
        if correlation_key is None:
            return []
        related = [
            candidate
            for candidate in recent
            if candidate.id != event.id
            and candidate.source == event.source
            and _correlation_key(candidate) == correlation_key
            and earliest <= candidate.observed_at <= event.observed_at
        ]
        if minimum_loss is not None:
            related = [
                candidate
                for candidate in related
                if _number(candidate.evidence.get("packet_loss")) >= minimum_loss
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
    return ", ".join(str(port) for port in ports)


def _correlation_key(event: SecurityEvent) -> tuple[str, str] | None:
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
