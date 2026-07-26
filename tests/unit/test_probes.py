from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from socketclaw.probes.logs import LogProbe
from socketclaw.probes.ping import CommandResult, PingProbe
from socketclaw.probes.ports import PortProbe


@pytest.mark.asyncio
async def test_ping_probe_parses_macos_packet_loss_and_latency() -> None:
    commands: list[tuple[list[str], float]] = []

    async def runner(command: list[str], timeout: float) -> CommandResult:
        commands.append((command, timeout))
        return CommandResult(
            returncode=0,
            stdout=(
                "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
                "round-trip min/avg/max/stddev = 12.100/18.250/30.800/2.100 ms\n"
            ),
            stderr="",
        )

    result = await PingProbe(runner=runner, platform_name="Darwin").collect(
        "1.1.1.1",
        count=3,
        timeout=2.0,
    )

    assert commands == [(["ping", "-c", "3", "-W", "2000", "1.1.1.1"], 8.0)]
    assert result.evidence["packet_loss"] == 0.0
    assert result.evidence["rtt_min_ms"] == 12.1
    assert result.evidence["rtt_avg_ms"] == 18.25
    assert result.evidence["rtt_max_ms"] == 30.8
    assert result.title == "1.1.1.1 is reachable"


@pytest.mark.asyncio
async def test_ping_probe_parses_linux_partial_loss() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return CommandResult(
            returncode=0,
            stdout=(
                "3 packets transmitted, 2 received, 33.3333% packet loss, time 2002ms\n"
                "rtt min/avg/max/mdev = 9.000/10.500/12.000/1.500 ms\n"
            ),
            stderr="",
        )

    result = await PingProbe(runner=runner, platform_name="Linux").collect("example.com")

    assert result.evidence["packet_loss"] == pytest.approx(33.3333)
    assert result.evidence["received"] == 2
    assert result.evidence["rtt_avg_ms"] == 10.5
    assert result.title == "example.com has packet loss"


@pytest.mark.asyncio
async def test_ping_probe_uses_windows_arguments_and_parses_summary() -> None:
    commands: list[list[str]] = []

    async def runner(command: list[str], _timeout: float) -> CommandResult:
        commands.append(command)
        return CommandResult(
            returncode=0,
            stdout=(
                "Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),\n"
                "Minimum = 10ms, Maximum = 20ms, Average = 15ms\n"
            ),
            stderr="",
        )

    result = await PingProbe(runner=runner, platform_name="Windows").collect(
        "1.1.1.1",
        count=3,
        timeout=2.0,
    )

    assert commands == [["ping", "-n", "3", "-w", "2000", "1.1.1.1"]]
    assert result.evidence["received"] == 3
    assert result.evidence["packet_loss"] == 0.0
    assert result.evidence["rtt_min_ms"] == 10.0
    assert result.evidence["rtt_avg_ms"] == 15.0
    assert result.evidence["rtt_max_ms"] == 20.0


@pytest.mark.asyncio
async def test_ping_timeout_becomes_complete_loss_event() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        raise TimeoutError("ping command exceeded deadline")

    result = await PingProbe(runner=runner).collect("1.1.1.1")

    assert result.event_type == "ping.result"
    assert result.evidence["packet_loss"] == 100.0
    assert result.evidence["error"] == "ping command exceeded deadline"
    assert result.title == "1.1.1.1 is unreachable"


@pytest.mark.asyncio
async def test_port_probe_reports_newly_opened_and_closed() -> None:
    states = {22: True, 443: False}

    async def connector(_host: str, port: int, _timeout: float) -> bool:
        return states[port]

    probe = PortProbe(connector=connector)
    first = await probe.collect("127.0.0.1", [22, 443])
    states.update({22: False, 443: True})
    second = await probe.collect("127.0.0.1", [22, 443])

    assert first.evidence["open_ports"] == [22]
    assert first.evidence["newly_opened"] == [22]
    assert first.evidence["newly_closed"] == []
    assert second.evidence["open_ports"] == [443]
    assert second.evidence["newly_opened"] == [443]
    assert second.evidence["newly_closed"] == [22]


@pytest.mark.asyncio
async def test_port_probe_limits_parallel_connections() -> None:
    active = 0
    maximum = 0

    async def connector(_host: str, _port: int, _timeout: float) -> bool:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0)
        active -= 1
        return False

    await PortProbe(connector=connector, concurrency=7).collect(
        "127.0.0.1",
        range(1, 41),
    )

    assert maximum == 7


@pytest.mark.asyncio
async def test_log_probe_reads_only_appended_matching_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("historical failed password from 10.0.0.1\n")
    probe = LogProbe([log_path])

    assert await probe.poll() == []
    with log_path.open("a") as stream:
        stream.write("normal service message\n")
        stream.write("Jul 27 sshd[42]: Failed password for root from 10.0.0.8 port 50122\n")

    events = await probe.poll()

    assert len(events) == 1
    assert events[0].event_type == "log.auth_failure"
    assert events[0].target == "10.0.0.8"
    assert "Failed password" in events[0].summary


@pytest.mark.asyncio
async def test_log_probe_detects_rotation_and_reads_new_file(tmp_path: Path) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()

    rotated = tmp_path / "security.log.1"
    log_path.rename(rotated)
    log_path.write_text("endpoint detected ransomware activity\n")
    assert os.stat(log_path).st_ino != os.stat(rotated).st_ino

    events = await probe.poll()

    assert len(events) == 1
    assert events[0].event_type == "log.malware_indicator"
    assert events[0].evidence["rotated"] is True


@pytest.mark.asyncio
async def test_log_probe_detects_in_place_truncation(tmp_path: Path) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("x" * 200)
    probe = LogProbe([log_path])
    await probe.poll()

    log_path.write_text("authentication failure from 10.0.0.11\n")
    events = await probe.poll()

    assert len(events) == 1
    assert events[0].target == "10.0.0.11"
    assert events[0].evidence["rotated"] is True


@pytest.mark.asyncio
async def test_missing_log_path_is_reported_once_when_it_appears(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "later.log"
    probe = LogProbe([log_path])

    assert await probe.poll() == []
    log_path.write_text("authentication failure from 10.0.0.9\n")
    events = await probe.poll()

    assert len(events) == 1
    assert events[0].event_type == "log.auth_failure"
