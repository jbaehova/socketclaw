from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path

import pytest

import socketclaw.probes.logs as log_module
from socketclaw.probes.logs import LogProbe
from socketclaw.probes.ping import CommandResult, PingProbe, _run_command
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
async def test_ping_probe_uses_the_explicit_resolved_executable() -> None:
    commands: list[list[str]] = []

    async def runner(command: list[str], _timeout: float) -> CommandResult:
        commands.append(command)
        return CommandResult(returncode=0, stdout="localized success", stderr="")

    await PingProbe(
        runner=runner,
        platform_name="Linux",
        executable="/trusted/bin/ping",
    ).collect("example.com", count=1)

    assert commands == [["/trusted/bin/ping", "-c", "1", "-W", "2", "example.com"]]


@pytest.mark.asyncio
async def test_ping_probe_limits_parallel_processes_across_targets() -> None:
    active = 0
    maximum = 0

    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.001)
        active -= 1
        return CommandResult(returncode=0, stdout="localized success", stderr="")

    probe = PingProbe(runner=runner, concurrency=4)
    await asyncio.gather(*(probe.collect(f"host-{index}.example") for index in range(20)))

    assert maximum == 4


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
async def test_ping_deadline_is_unknown_not_measured_packet_loss() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        raise TimeoutError("ping command exceeded deadline")

    result = await PingProbe(runner=runner).collect("1.1.1.1")

    assert result.event_type == "ping.result"
    assert result.evidence.get("packet_loss") is None
    assert result.evidence["outcome"] == "unknown"
    assert result.evidence["reason"] == "deadline_exceeded"
    assert result.evidence["error"] == "ping command exceeded deadline"
    assert result.title == "Ping result unknown for 1.1.1.1"


@pytest.mark.asyncio
async def test_ping_preserves_explicit_partial_loss_on_nonzero_exit() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return CommandResult(
            returncode=1,
            stdout="3 packets transmitted, 2 received, 33% packet loss\n",
            stderr="",
        )

    result = await PingProbe(runner=runner, platform_name="Linux").collect("example.com")

    assert result.evidence["packet_loss"] == 33.0
    assert result.evidence["returncode"] == 1
    assert result.evidence["statistics_parsed"] is True


@pytest.mark.asyncio
async def test_ping_success_with_localized_statistics_is_not_false_total_loss() -> None:
    async def runner(_command: list[str], _timeout: float) -> CommandResult:
        return CommandResult(returncode=0, stdout="localized ping output", stderr="")

    result = await PingProbe(runner=runner).collect("example.com")

    assert result.evidence.get("packet_loss") is None
    assert result.evidence["statistics_parsed"] is False
    assert result.evidence["outcome"] == "unknown"
    assert result.title == "Ping result unknown for example.com"


@pytest.mark.asyncio
async def test_ping_probe_rejects_non_integer_count() -> None:
    with pytest.raises(ValueError, match="ping count"):
        await PingProbe().collect("example.com", count=1.5)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ping_subprocess_is_killed_and_reaped_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.started = asyncio.Event()
            self.killed = False
            self.communicate_calls = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            self.communicate_calls += 1
            if self.killed:
                self.returncode = -9
                return b"", b""
            self.started.set()
            await asyncio.Event().wait()
            return b"", b""

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()

    async def create_subprocess(*_args: object, **_kwargs: object) -> FakeProcess:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess)
    task = asyncio.create_task(_run_command(["ping", "example.com"], 60.0))
    await process.started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.killed is True
    assert process.communicate_calls == 2


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
    assert first.evidence["newly_opened"] == []
    assert first.evidence["newly_closed"] == []
    assert first.evidence["baseline"] is True
    assert second.evidence["open_ports"] == [443]
    assert second.evidence["newly_opened"] == [443]
    assert second.evidence["newly_closed"] == [22]
    assert second.evidence["baseline"] is False


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
async def test_port_probe_limits_parallel_connections_across_targets() -> None:
    active = 0
    maximum = 0

    async def connector(_host: str, _port: int, _timeout: float) -> bool:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.001)
        active -= 1
        return False

    probe = PortProbe(connector=connector, concurrency=7)
    await asyncio.gather(
        *(probe.collect(f"host-{index}.example", range(1, 21)) for index in range(5))
    )

    assert maximum == 7


@pytest.mark.asyncio
async def test_concurrent_port_scans_do_not_duplicate_state_changes() -> None:
    opened = False

    async def connector(_host: str, _port: int, _timeout: float) -> bool:
        await asyncio.sleep(0)
        return opened

    probe = PortProbe(connector=connector)
    await probe.collect("127.0.0.1", [22])
    opened = True

    first, second = await asyncio.gather(
        probe.collect("127.0.0.1", [22]),
        probe.collect("127.0.0.1", [22]),
    )

    assert [first.evidence["newly_opened"], second.evidence["newly_opened"]] == [
        [22],
        [],
    ]


@pytest.mark.asyncio
async def test_port_probe_rejects_empty_or_invalid_scan_inputs() -> None:
    probe = PortProbe()

    with pytest.raises(ValueError, match="at least one"):
        await probe.collect("127.0.0.1", [])
    with pytest.raises(ValueError, match="invalid TCP port"):
        await probe.collect("127.0.0.1", [True])
    with pytest.raises(ValueError, match="invalid TCP port"):
        await probe.collect("127.0.0.1", [22.5])  # type: ignore[list-item]


def test_port_probe_rejects_non_integer_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        PortProbe(concurrency=1.5)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_indeterminate_port_result_does_not_report_false_closure() -> None:
    state: bool | None = True

    async def connector(_host: str, _port: int, _timeout: float) -> bool | None:
        return state

    probe = PortProbe(connector=connector)
    baseline = await probe.collect("127.0.0.1", [22])
    state = None

    result = await probe.collect("127.0.0.1", [22])

    assert baseline.evidence["open_ports"] == [22]
    assert result.evidence["open_ports"] == []
    assert result.evidence["last_known_open_ports"] == [22]
    assert result.evidence["newly_closed"] == []
    assert result.evidence["unresolved_ports"] == [22]
    assert result.title == "Port scan incomplete on 127.0.0.1"


@pytest.mark.asyncio
async def test_log_probe_reads_only_appended_matching_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("historical failed password from 10.0.0.1\n")
    probe = LogProbe([log_path])

    assert await probe.poll() == []
    with log_path.open("a") as stream:
        stream.write("normal service message\n")
        stream.write(
            "Jul 27 12:00:00 server sshd[42]: Failed password for root from 10.0.0.8 port 50122\n"
        )

    events = await probe.poll()

    assert len(events) == 2
    assert events[0].event_type == "log.context"
    assert events[0].evidence["context_for"] == str(events[1].id)
    assert events[1].event_type == "log.auth_failure"
    assert events[1].evidence["actor_ip"] == "10.0.0.8"
    assert "Failed password" in events[1].summary


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
    assert events[0].event_type == "log.unverified_indicator"
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
    assert events[0].evidence["actor_ip"] == "10.0.0.11"
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


@pytest.mark.asyncio
async def test_log_probe_keeps_partial_line_until_it_is_complete(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()
    with log_path.open("a") as stream:
        stream.write("authentication fail")

    assert await probe.poll() == []
    with log_path.open("a") as stream:
        stream.write("ure from 2001:db8::7\n")

    events = await probe.poll()

    assert len(events) == 1
    assert events[0].event_type == "log.auth_failure"
    assert events[0].evidence["actor_ip"] == "2001:db8::7"


@pytest.mark.asyncio
async def test_cancelled_log_poll_replays_events_on_the_next_poll(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()
    with log_path.open("a") as stream:
        stream.write("authentication failure from 10.0.0.42\n")

    started = threading.Event()
    release = threading.Event()
    original_poll = probe._poll_sync

    def delayed_poll():
        started.set()
        assert release.wait(timeout=1.0)
        return original_poll()

    monkeypatch.setattr(probe, "_poll_sync", delayed_poll)
    task = asyncio.create_task(probe.poll())
    assert await asyncio.to_thread(started.wait, 1.0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    monkeypatch.setattr(probe, "_poll_sync", original_poll)
    events = await probe.poll()

    assert len(events) == 1
    assert events[0].evidence["actor_ip"] == "10.0.0.42"


@pytest.mark.asyncio
async def test_log_reconfigure_preserves_intersecting_path_cursor(tmp_path: Path) -> None:
    retained = tmp_path / "retained.log"
    removed = tmp_path / "removed.log"
    added = tmp_path / "added.log"
    for path in (retained, removed, added):
        path.write_text("startup\n")
    probe = LogProbe([retained, removed])
    await probe.poll()
    with retained.open("a") as stream:
        stream.write("authentication failure from 10.0.0.43\n")

    await probe.reconfigure([retained, added])
    events = await probe.poll()

    assert len(events) == 1
    assert events[0].evidence["actor_ip"] == "10.0.0.43"
    assert probe.paths == [retained, added]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX-only")
@pytest.mark.asyncio
async def test_log_probe_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "auth.pipe"
    os.mkfifo(fifo)
    probe = LogProbe([fifo])

    events = await asyncio.wait_for(probe.poll(), timeout=1.0)

    assert len(events) == 1
    assert events[0].event_type == "system.log_probe_error"
    assert "regular file" in events[0].summary


@pytest.mark.asyncio
async def test_log_probe_detects_copytruncate_regrowth_past_old_size(tmp_path: Path) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("old content marker\n")
    probe = LogProbe([log_path])
    await probe.poll()

    log_path.write_text("authentication failure from 10.0.0.20\n" + "x" * 100)
    events = await probe.poll()

    assert len(events) == 1
    assert events[0].evidence["actor_ip"] == "10.0.0.20"
    assert events[0].evidence["rotated"] is True


@pytest.mark.asyncio
async def test_log_probe_reads_recreated_path_after_it_was_missing(tmp_path: Path) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()
    log_path.unlink()
    await probe.poll()
    log_path.write_text("authentication failure from 10.0.0.21\n")

    events = await probe.poll()

    assert len(events) == 1
    assert events[0].evidence["actor_ip"] == "10.0.0.21"
    assert events[0].evidence["rotated"] is True


@pytest.mark.asyncio
async def test_one_unreadable_log_does_not_block_other_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = tmp_path / "unreadable.log"
    readable = tmp_path / "readable.log"
    unreadable.write_text("startup\n")
    readable.write_text("startup\n")
    original_open = os.open

    def selective_open(path: str | bytes | os.PathLike[str], flags: int) -> int:
        if Path(path) == unreadable:
            raise PermissionError("permission denied")
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", selective_open)
    probe = LogProbe([unreadable, readable])
    first = await probe.poll()
    with readable.open("a") as stream:
        stream.write("Failed password for root from 10.0.0.22\n")

    second = await probe.poll()

    assert [event.event_type for event in first] == ["system.log_probe_error"]
    assert [event.event_type for event in second] == ["log.auth_failure"]
    assert second[0].evidence["actor_ip"] == "10.0.0.22"


@pytest.mark.asyncio
async def test_oversized_log_line_is_bounded_and_following_line_is_processed(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()
    with log_path.open("a") as stream:
        stream.write("malware " + "x" * 70_000 + "\n")
        stream.write("authentication failure from 999.999.999.999\n")

    events = await probe.poll()

    assert [event.event_type for event in events] == [
        "log.unverified_indicator",
        "log.auth_failure",
    ]
    assert events[0].evidence["truncated"] is True
    assert len(str(events[0].evidence["message"])) == 4000
    assert events[1].evidence["actor_ip"] is None
    assert events[1].target.startswith("log:")


@pytest.mark.asyncio
async def test_log_probe_caps_lines_and_continues_from_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    await probe.poll()
    with log_path.open("a") as stream:
        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            stream.write(f"authentication failure from {address}\n")
    monkeypatch.setattr(log_module, "_MAX_POLL_LINES", 2)

    first = await probe.poll()
    second = await probe.poll()

    assert [event.evidence["actor_ip"] for event in first] == ["10.0.0.1", "10.0.0.2"]
    assert [event.evidence["actor_ip"] for event in second] == ["10.0.0.3"]


@pytest.mark.asyncio
async def test_cancelled_log_poll_cannot_race_a_followup_cursor_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_path = tmp_path / "security.log"
    log_path.write_text("startup\n")
    probe = LogProbe([log_path])
    original_poll = probe._poll_sync
    started = threading.Event()
    release = threading.Event()
    state_lock = threading.Lock()
    active = 0
    maximum = 0

    def blocked_poll():
        nonlocal active, maximum
        with state_lock:
            active += 1
            maximum = max(maximum, active)
        started.set()
        release.wait(timeout=2.0)
        try:
            return original_poll()
        finally:
            with state_lock:
                active -= 1

    monkeypatch.setattr(probe, "_poll_sync", blocked_poll)
    first = asyncio.create_task(probe.poll())
    await asyncio.to_thread(started.wait, 1.0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    second = asyncio.create_task(probe.poll())
    await asyncio.sleep(0.05)

    assert maximum == 1
    assert not second.done()
    release.set()
    await asyncio.wait_for(second, timeout=1.0)
    assert maximum == 1
