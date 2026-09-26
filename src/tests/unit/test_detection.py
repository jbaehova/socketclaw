from __future__ import annotations

from datetime import UTC, datetime, timedelta

from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent, Severity

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def event(
    *,
    source: str,
    event_type: str,
    evidence: dict[str, object],
    target: str | None = "1.1.1.1",
    observed_at: datetime = NOW,
) -> SecurityEvent:
    return SecurityEvent(
        observed_at=observed_at,
        source=source,
        event_type=event_type,
        title=event_type,
        summary=event_type,
        target=target,
        evidence=evidence,
    )


def test_total_ping_loss_is_high_with_explanation() -> None:
    current = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": 100.0},
    )

    result = Detector().score(current, [])

    assert result.severity is Severity.HIGH
    assert result.score == 70
    assert [signal.code for signal in result.signals] == ["ping.total_loss"]


def test_sustained_total_loss_escalates_to_critical() -> None:
    recent = [
        event(
            source="ping",
            event_type="ping.result",
            evidence={"packet_loss": 100.0},
            observed_at=NOW - timedelta(seconds=offset),
        )
        for offset in (90, 60, 30)
    ]
    current = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": 100.0},
    )

    result = Detector().score(current, recent)

    assert result.severity is Severity.CRITICAL
    assert result.score == 95
    assert {signal.code for signal in result.signals} == {
        "ping.total_loss",
        "ping.sustained_loss",
    }


def test_partial_packet_loss_has_proportional_severity() -> None:
    high_loss = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": 75.0},
    )
    degraded = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": 25.0},
    )

    high_result = Detector().score(high_loss, [])
    degraded_result = Detector().score(degraded, [])

    assert (high_result.score, high_result.severity) == (45, Severity.MEDIUM)
    assert [signal.code for signal in high_result.signals] == ["ping.high_loss"]
    assert (degraded_result.score, degraded_result.severity) == (25, Severity.LOW)
    assert [signal.code for signal in degraded_result.signals] == ["ping.degraded"]


def test_new_sensitive_port_is_medium_and_named() -> None:
    current = event(
        source="port_scan",
        event_type="port_scan.result",
        evidence={"newly_opened": [6379], "newly_closed": [], "open_ports": [6379]},
    )

    result = Detector().score(current, [])

    assert result.severity is Severity.MEDIUM
    assert result.score == 55
    assert [signal.code for signal in result.signals] == [
        "port.newly_opened",
        "port.sensitive_opened",
    ]


def test_many_new_ports_are_critical_without_exceeding_score_limit() -> None:
    current = event(
        source="port_scan",
        event_type="port_scan.result",
        evidence={
            "newly_opened": [21, 22, 23, 25, 80, 443, 6379],
            "newly_closed": [],
            "open_ports": [21, 22, 23, 25, 80, 443, 6379],
        },
    )

    result = Detector().score(current, [])

    assert result.severity is Severity.CRITICAL
    assert result.score == 100
    assert "port.open_burst" in {signal.code for signal in result.signals}


def test_closed_ports_are_informational_recovery() -> None:
    current = event(
        source="port_scan",
        event_type="port_scan.result",
        evidence={"newly_opened": [], "newly_closed": [22], "open_ports": []},
    )

    result = Detector().score(current, [])

    assert result.severity is Severity.INFO
    assert result.score == 0
    assert [signal.code for signal in result.signals] == ["port.closed"]


def test_repeated_auth_failures_escalate_to_critical() -> None:
    recent = [
        event(
            source="log",
            event_type="log.auth_failure",
            target="10.0.0.8",
            evidence={"message": "Failed password for admin from 10.0.0.8"},
            observed_at=NOW - timedelta(seconds=offset),
        )
        for offset in (240, 180, 120, 60, 30)
    ]
    current = event(
        source="log",
        event_type="log.auth_failure",
        target="10.0.0.8",
        evidence={"message": "Failed password for root from 10.0.0.8"},
    )

    result = Detector().score(current, recent)

    assert result.severity is Severity.CRITICAL
    assert result.score == 100
    assert "log.auth_burst" in {signal.code for signal in result.signals}


def test_old_or_unrelated_auth_failures_do_not_form_burst() -> None:
    recent = [
        event(
            source="log",
            event_type="log.auth_failure",
            target="10.0.0.9",
            evidence={"message": "Failed password"},
            observed_at=NOW - timedelta(minutes=10),
        ),
        event(
            source="log",
            event_type="log.auth_failure",
            target="10.0.0.8",
            evidence={"message": "Failed password"},
            observed_at=NOW - timedelta(minutes=6),
        ),
    ]
    current = event(
        source="log",
        event_type="log.auth_failure",
        target="10.0.0.8",
        evidence={"message": "Failed password"},
    )

    result = Detector().score(current, recent)

    assert result.severity is Severity.LOW
    assert result.score == 25
    assert [signal.code for signal in result.signals] == ["log.auth_failure"]


def test_generic_malware_keyword_is_unverified() -> None:
    current = event(
        source="log",
        event_type="log.match",
        evidence={"message": "Endpoint quarantined ransomware payload"},
    )

    result = Detector().score(current, [])

    assert result.severity is Severity.INFO
    assert result.score == 10
    assert [signal.code for signal in result.signals] == ["log.unverified_indicator"]


def test_sudo_substring_does_not_prove_privilege_escalation() -> None:
    current = event(
        source="log",
        event_type="log.match",
        evidence={"message": "sudo: operator executed /usr/bin/id"},
    )

    result = Detector().score(current, [])

    assert result.score == 0
    assert result.severity is Severity.INFO
    assert not result.signals


def test_firewall_denial_burst_is_medium() -> None:
    current = event(
        source="log",
        event_type="log.firewall_denial",
        evidence={"message": "Firewall denied connections", "denial_count": 18},
    )

    result = Detector().score(current, [])

    assert result.score == 55
    assert result.severity is Severity.MEDIUM
    assert [signal.code for signal in result.signals] == [
        "log.firewall_denial",
        "log.firewall_denial_burst",
    ]


def test_single_firewall_denial_is_low() -> None:
    current = event(
        source="log",
        event_type="log.firewall_denial",
        evidence={"message": "DROP connection"},
    )

    result = Detector().score(current, [])

    assert result.score == 15
    assert result.severity is Severity.LOW
    assert [signal.code for signal in result.signals] == ["log.firewall_denial"]


def test_individual_firewall_denials_form_a_path_scoped_burst() -> None:
    recent = [
        event(
            source="log",
            event_type="log.firewall_denial",
            target=None,
            evidence={"message": "DROP connection", "path": "/var/log/firewall.log"},
            observed_at=NOW - timedelta(seconds=offset),
        )
        for offset in range(10, 100, 10)
    ]
    current = event(
        source="log",
        event_type="log.firewall_denial",
        target=None,
        evidence={"message": "DROP connection", "path": "/var/log/firewall.log"},
    )

    result = Detector().score(current, recent)

    assert result.score == 55
    assert [signal.code for signal in result.signals] == [
        "log.firewall_denial",
        "log.firewall_denial_burst",
    ]


def test_no_ip_auth_failures_are_correlated_only_within_one_log_path() -> None:
    recent = [
        event(
            source="log",
            event_type="log.auth_failure",
            target=None,
            evidence={"message": "Failed password", "path": f"/var/log/auth-{index}.log"},
            observed_at=NOW - timedelta(seconds=index),
        )
        for index in range(1, 6)
    ]
    current = event(
        source="log",
        event_type="log.auth_failure",
        target=None,
        evidence={"message": "Failed password", "path": "/var/log/auth-current.log"},
    )

    result = Detector().score(current, recent)

    assert result.score == 25
    assert [signal.code for signal in result.signals] == ["log.auth_failure"]


def test_log_line_can_emit_multiple_independent_signals() -> None:
    current = event(
        source="log",
        event_type="log.auth_failure",
        evidence={"message": "Failed password followed by sudo: cryptominer detected"},
    )

    result = Detector().score(current, [])

    assert result.score == 35
    assert {signal.code for signal in result.signals} == {
        "log.unverified_indicator",
        "log.auth_failure",
    }


def test_correlation_excludes_other_sources_and_the_current_event() -> None:
    current = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": 100},
    )
    recent = [
        current,
        event(source="log", event_type="log.match", evidence={"packet_loss": 100}),
        event(source="manual", event_type="manual.ping", evidence={"packet_loss": 100}),
    ]

    result = Detector().score(current, recent)

    assert result.score == 70
    assert [signal.code for signal in result.signals] == ["ping.total_loss"]


def test_malformed_numeric_evidence_is_safely_ignored() -> None:
    ping = event(
        source="ping",
        event_type="ping.result",
        evidence={"packet_loss": "NaN"},
    )
    ports = event(
        source="port_scan",
        event_type="port_scan.result",
        evidence={"newly_opened": ["Infinity", 22.5, "6379", True]},
    )
    log = event(
        source="log",
        event_type="log.match",
        evidence={"message": "ordinary", "denial_count": "Infinity"},
    )

    assert Detector().score(ping, []).score == 0
    assert Detector().score(log, []).score == 0
    port_result = Detector().score(ports, [])
    assert port_result.score == 55
    assert "6379" in port_result.signals[0].detail


def test_private_address_is_not_malicious_by_itself() -> None:
    current = event(
        source="manual",
        event_type="manual.lookup",
        target="192.168.1.2",
        evidence={},
    )

    result = Detector().score(current, [])

    assert result.score == 0
    assert result.severity is Severity.INFO
    assert result.signals == ()
