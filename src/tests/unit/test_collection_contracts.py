"""Last-phase collection regressions: measured facts versus collection failures."""

from __future__ import annotations

import pytest

from socketclaw.detection import Detector
from socketclaw.probes.ping import CommandResult, PingProbe
from socketclaw.probes.ports import PortProbe


@pytest.mark.parametrize(
    ("result", "outcome", "reason"),
    [
        (CommandResult(2, "", "ping: permission denied"), "error", "permission"),
        (CommandResult(2, "", "ping: unknown host example.invalid"), "error", "dns"),
        (CommandResult(1, "Ping request could not find host x", ""), "error", "dns"),
        (CommandResult(2, "unexpected failure", ""), "error", "command_failed"),
        (CommandResult(0, "localized output", ""), "unknown", "unparsed_statistics"),
        (CommandResult(1, "localized output", ""), "unknown", "unparsed_statistics"),
        (
            CommandResult(2, "3 packets transmitted, 0 received, 100% packet loss", ""),
            "error",
            "command_failed",
        ),
    ],
)
async def test_ping_failure_is_not_measured_host_loss(
    result: CommandResult, outcome: str, reason: str
) -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return result

    event = await PingProbe(runner=runner, platform_name="Linux").collect("example.invalid")
    assert event.evidence["outcome"] == outcome
    assert event.evidence["reason"] == reason
    assert event.evidence["returncode"] == result.returncode
    assert event.evidence.get("packet_loss") is None
    assert event.evidence.get("received") is None
    assert "unreachable" not in event.title
    assert Detector().score(event, []).score == 0


@pytest.mark.parametrize("error", [PermissionError("denied"), FileNotFoundError("ping")])
async def test_ping_execution_error_preserves_unknown_loss(error: OSError) -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        raise error

    event = await PingProbe(runner=runner).collect("example.com")
    assert event.evidence["outcome"] == "error"
    assert event.evidence["returncode"] is None
    assert event.evidence.get("packet_loss") is None
    assert Detector().score(event, []).score == 0


async def test_ping_verified_total_loss_remains_high() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return CommandResult(1, "3 packets transmitted, 0 received, 100% packet loss", "")

    event = await PingProbe(runner=runner).collect("example.com")
    assert event.evidence["outcome"] == "unreachable"
    assert event.evidence["reason"] == "measured_statistics"
    assert Detector().score(event, []).score == 70
    assert "ICMP" in event.title


async def test_port_scope_changes_are_not_network_changes() -> None:
    states = {22: True, 80: True, 443: True}

    async def connector(_host: str, port: int, _timeout: float) -> bool:
        return states[port]

    probe = PortProbe(connector=connector)
    await probe.collect("example.com", [22, 80])
    states[80] = False
    event = await probe.collect("example.com", [80, 443])
    assert event.evidence["newly_closed"] == [80]
    assert event.evidence["scope_removed"] == [22]
    assert event.evidence["scope_added"] == [443]
    assert event.evidence["newly_opened"] == []
    assert event.evidence["initial_open_ports"] == [443]
    assert event.evidence["open_ports"] == [443]

    retained = probe.retained_for_targets(["example.com"])
    event = await retained.collect("example.com", [22, 80, 443])
    assert event.evidence["scope_added"] == [22]
    assert event.evidence["newly_opened"] == []


async def test_unknown_port_does_not_count_as_current_open_or_invent_a_change() -> None:
    state: bool | None = None

    async def connector(_host: str, _port: int, _timeout: float) -> bool | None:
        return state

    probe = PortProbe(connector=connector)
    await probe.collect("example.com", [22])
    state = True
    first_known = await probe.collect("example.com", [22])
    assert first_known.evidence["newly_opened"] == []
    assert first_known.evidence["initial_open_ports"] == [22]
    state = None
    unknown = await probe.collect("example.com", [22])
    assert unknown.evidence["open_ports"] == []
    assert unknown.evidence["last_known_open_ports"] == [22]
    assert unknown.evidence["newly_closed"] == []
    state = False
    closed = await probe.collect("example.com", [22])
    assert closed.evidence["newly_closed"] == [22]


async def test_first_sensitive_exposure_is_not_a_newly_opened_port() -> None:
    async def connector(_host: str, _port: int, _timeout: float) -> bool:
        return True

    event = await PortProbe(connector=connector).collect("example.com", [22])
    assert event.evidence["newly_opened"] == []
    assert event.evidence["initial_open_ports"] == [22]
    assert [signal.code for signal in Detector().score(event, []).signals] == [
        "port.sensitive_exposure"
    ]


async def test_macos_exit_two_with_statistics_is_measured_no_reply() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return CommandResult(2, "3 packets transmitted, 0 packets received, 100.0% packet loss", "")

    event = await PingProbe(runner=runner, platform_name="Darwin").collect("example.com")
    assert event.evidence["outcome"] == "unreachable"
    assert event.evidence["returncode"] == 2
    assert Detector().score(event, []).score == 70
