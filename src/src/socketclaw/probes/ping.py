"""Cross-platform subprocess ping collection without shell execution."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import platform
import re
import shutil
import socket
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass

from pydantic import JsonValue

from ..domain import EventSource, ObservationOutcome, SecurityEvent


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[list[str], float], Awaitable[CommandResult]]


class PingProbe:
    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        platform_name: str | None = None,
        executable: str = "ping",
        concurrency: int = 16,
        ipv6_executable: str | None = None,
    ) -> None:
        if not executable or executable != executable.strip() or "\x00" in executable:
            raise ValueError("ping executable must be a non-empty path")
        if type(concurrency) is not int or concurrency < 1:
            raise ValueError("ping concurrency must be positive")
        self._runner = runner or _run_command
        self._platform = platform_name or platform.system()
        self._executable = executable
        self._ipv6_executable = ipv6_executable
        self._slots = asyncio.Semaphore(concurrency)

    async def collect(
        self,
        target: str,
        *,
        count: int = 3,
        timeout: float = 2.0,
    ) -> SecurityEvent:
        _validate_request(target, count, timeout)
        selected = target
        is_v6 = ":" in target
        if self._platform == "Darwin" and not is_v6:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                try:
                    addresses = await asyncio.wait_for(
                        asyncio.get_running_loop().getaddrinfo(
                            target, None, type=socket.SOCK_DGRAM
                        ),
                        timeout=timeout,
                    )
                    # Prefer IPv4 on dual-stack names, use ping6 for IPv6-only names.
                    if addresses and not any(item[0] == socket.AF_INET for item in addresses):
                        selected = str(addresses[0][4][0])
                        is_v6 = True
                except (OSError, TimeoutError):
                    pass
        executable = self._executable
        if self._platform == "Darwin" and is_v6:
            executable = self._ipv6_executable or shutil.which("ping6") or "ping6"
        command = _ping_command(executable, self._platform, selected, count, timeout)
        deadline = count * timeout + 2.0
        evidence: dict[str, JsonValue]
        try:
            async with self._slots:
                result = await self._runner(command, deadline)
            evidence = _normalize_result(result, count, self._platform)
        except (TimeoutError, OSError) as exc:
            is_timeout = isinstance(exc, TimeoutError)
            evidence = {
                "requested_count": count,
                "outcome": "unknown" if is_timeout else "error",
                "reason": "deadline_exceeded"
                if is_timeout
                else "unsupported"
                if isinstance(exc, FileNotFoundError)
                else "execution_failed",
                "statistics_parsed": False,
                "returncode": None,
                "error": (str(exc).strip() or type(exc).__name__)[:2000],
            }

        evidence["target"] = target
        evidence["address_family"] = "ipv6" if is_v6 else "ipv4_or_dns"
        evidence["resolved_target"] = selected
        outcome = evidence["outcome"]
        if outcome == "unreachable":
            title = f"{target}: no ICMP replies"
        elif outcome == "partial":
            title = f"{target} has packet loss"
        elif outcome == "ok":
            title = f"{target} is reachable"
        elif outcome == "error":
            title = f"Ping collection failed for {target}"
        else:
            title = f"Ping result unknown for {target}"
        return SecurityEvent(
            source=EventSource.PING,
            event_type="ping.result",
            title=title if len(title) <= 200 else title[:197] + "...",
            summary=_ping_summary(target, evidence),
            target=target,
            evidence=evidence,
            outcome=ObservationOutcome(str(evidence["outcome"])),
        )


def _normalize_result(
    result: CommandResult, count: int, platform_name: str
) -> dict[str, JsonValue]:
    parsed = _parse_ping(result.stdout, count)
    output = f"{result.stdout}\n{result.stderr}".casefold()
    reason = None
    if any(
        term in output for term in ("permission denied", "operation not permitted", "access denied")
    ):
        reason = "permission"
    elif any(
        term in output
        for term in (
            "unknown host",
            "could not find host",
            "name or service not known",
            "cannot resolve",
            "temporary failure in name resolution",
            "nodename nor servname",
        )
    ):
        reason = "dns"
    elif result.returncode not in ({0, 1, 2} if platform_name == "Darwin" else {0, 1}):
        # BSD ping uses 2 for a measured no-reply result; Linux uses 2 for errors.
        reason = "command_failed"
    statistics_parsed = "packet_loss" in parsed
    if reason is not None or not statistics_parsed:
        evidence: dict[str, JsonValue] = {
            "requested_count": count,
            "outcome": "error" if reason is not None else "unknown",
            "reason": reason or "unparsed_statistics",
        }
    else:
        evidence = parsed
        loss = _as_float(parsed["packet_loss"])
        evidence["outcome"] = "unreachable" if loss >= 100 else "partial" if loss else "ok"
        evidence["reason"] = "measured_statistics"
    evidence["statistics_parsed"] = statistics_parsed
    evidence["returncode"] = result.returncode
    evidence["stdout"] = result.stdout.strip()[:2000]
    if result.stderr.strip():
        evidence["stderr"] = result.stderr.strip()[:1000]
    return evidence


def _ping_command(
    executable: str,
    platform_name: str,
    target: str,
    count: int,
    timeout: float,
) -> list[str]:
    if platform_name == "Windows":
        return [
            executable,
            "-n",
            str(count),
            "-w",
            str(max(1, round(timeout * 1000))),
            target,
        ]
    if platform_name == "Darwin" and ":" in target:
        # macOS ping6 -W is a flag, not the millisecond timeout accepted by ping.
        # The async subprocess deadline bounds the entire measurement.
        return [executable, "-c", str(count), target]
    if platform_name == "Darwin":
        return [
            executable,
            "-c",
            str(count),
            "-W",
            str(max(1, round(timeout * 1000))),
            target,
        ]
    if platform_name == "Linux":
        return [
            executable,
            *(["-6"] if ":" in target else []),
            "-c",
            str(count),
            "-W",
            str(max(1, math.ceil(timeout))),
            target,
        ]
    return [executable, "-c", str(count), target]


async def _run_command(command: list[str], timeout: float) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        await _kill_and_reap(process)
        raise TimeoutError("ping command exceeded deadline") from None
    except asyncio.CancelledError:
        await _kill_and_reap(process)
        raise
    return CommandResult(
        returncode=process.returncode or 0,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


def _parse_ping(output: str, requested_count: int) -> dict[str, JsonValue]:
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output, re.IGNORECASE)
    if loss_match is None:
        loss_match = re.search(r"\((\d+(?:\.\d+)?)%\s*loss\)", output, re.IGNORECASE)
    loss = min(100.0, max(0.0, float(loss_match.group(1)))) if loss_match else None

    transmitted = re.search(r"(\d+)\s+packets transmitted", output, re.IGNORECASE)
    if transmitted is None:
        transmitted = re.search(r"Sent\s*=\s*(\d+)", output, re.IGNORECASE)
    received = re.search(
        r"(\d+)\s+(?:packets\s+)?received",
        output,
        re.IGNORECASE,
    )
    if received is None:
        received = re.search(r"Received\s*=\s*(\d+)", output, re.IGNORECASE)

    evidence: dict[str, JsonValue] = {"requested_count": requested_count}
    if transmitted is not None:
        evidence["sent"] = int(transmitted.group(1))
    if received is not None:
        evidence["received"] = int(received.group(1))
    if loss is not None:
        evidence["packet_loss"] = loss

    unix_rtt = re.search(
        r"(?:round-trip|rtt)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
        output,
        re.IGNORECASE,
    )
    windows_rtt = re.search(
        r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
        output,
        re.IGNORECASE,
    )
    if unix_rtt:
        evidence.update(
            {
                "rtt_min_ms": float(unix_rtt.group(1)),
                "rtt_avg_ms": float(unix_rtt.group(2)),
                "rtt_max_ms": float(unix_rtt.group(3)),
            }
        )
    elif windows_rtt:
        evidence.update(
            {
                "rtt_min_ms": float(windows_rtt.group(1)),
                "rtt_avg_ms": float(windows_rtt.group(3)),
                "rtt_max_ms": float(windows_rtt.group(2)),
            }
        )
    return evidence


def _ping_summary(target: str, evidence: Mapping[str, JsonValue]) -> str:
    if evidence.get("outcome") in {"error", "unknown"}:
        return f"{target}: ICMP response state unknown ({evidence['reason']})"
    loss = _as_float(evidence["packet_loss"])
    average = evidence.get("rtt_avg_ms")
    if average is not None:
        return f"{target}: {loss:g}% packet loss, {_as_float(average):.2f} ms average RTT"
    return f"{target}: {loss:g}% packet loss"


def _as_float(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int | float | str):
        number = float(value)
        if math.isfinite(number):
            return number
    raise TypeError(f"expected numeric ping evidence, got {type(value).__name__}")


async def _kill_and_reap(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    with suppress(ProcessLookupError, OSError, RuntimeError):
        await process.communicate()


def _validate_request(target: str, count: int, timeout: float) -> None:
    if not target or target != target.strip() or len(target) > 253 or target.startswith("-"):
        raise ValueError("ping target must be a non-empty host or address")
    if "\x00" in target:
        raise ValueError("ping target contains a null byte")
    if type(count) is not int or not 1 <= count <= 100:
        raise ValueError("ping count must be between 1 and 100")
    if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("ping timeout must be finite and between 0 and 60 seconds")
