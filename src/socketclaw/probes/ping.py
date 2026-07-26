"""Cross-platform subprocess ping collection without shell execution."""

from __future__ import annotations

import asyncio
import math
import platform
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from ..domain import EventSource, SecurityEvent


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
    ) -> None:
        self._runner = runner or _run_command
        self._platform = platform_name or platform.system()

    async def collect(
        self,
        target: str,
        *,
        count: int = 3,
        timeout: float = 2.0,
    ) -> SecurityEvent:
        command = _ping_command(self._platform, target, count, timeout)
        deadline = count * timeout + 2.0
        try:
            result = await self._runner(command, deadline)
            evidence = _parse_ping(result.stdout, count)
            if result.returncode != 0 and _as_float(evidence["packet_loss"]) < 100:
                evidence["packet_loss"] = 100.0
            if result.stderr.strip():
                evidence["stderr"] = result.stderr.strip()[:1000]
        except (TimeoutError, OSError) as exc:
            evidence = {
                "sent": count,
                "received": 0,
                "packet_loss": 100.0,
                "error": str(exc),
            }

        loss = _as_float(evidence["packet_loss"])
        if loss >= 100:
            title = f"{target} is unreachable"
        elif loss > 0:
            title = f"{target} has packet loss"
        else:
            title = f"{target} is reachable"
        return SecurityEvent(
            source=EventSource.PING,
            event_type="ping.result",
            title=title,
            summary=_ping_summary(target, evidence),
            target=target,
            evidence=evidence,
        )


def _ping_command(
    platform_name: str,
    target: str,
    count: int,
    timeout: float,
) -> list[str]:
    if platform_name == "Windows":
        return [
            "ping",
            "-n",
            str(count),
            "-w",
            str(round(timeout * 1000)),
            target,
        ]
    if platform_name == "Darwin":
        return [
            "ping",
            "-c",
            str(count),
            "-W",
            str(round(timeout * 1000)),
            target,
        ]
    return [
        "ping",
        "-c",
        str(count),
        "-W",
        str(max(1, math.ceil(timeout))),
        target,
    ]


async def _run_command(command: list[str], timeout: float) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise TimeoutError("ping command exceeded deadline") from None
    return CommandResult(
        returncode=process.returncode or 0,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


def _parse_ping(output: str, requested_count: int) -> dict[str, object]:
    loss_match = re.search(r"([\d.]+)%\s*packet loss", output, re.IGNORECASE)
    if loss_match is None:
        loss_match = re.search(r"\(([\d.]+)%\s*loss\)", output, re.IGNORECASE)
    loss = float(loss_match.group(1)) if loss_match else 100.0

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

    evidence: dict[str, object] = {
        "sent": int(transmitted.group(1)) if transmitted else requested_count,
        "received": (
            int(received.group(1)) if received else round(requested_count * (1 - loss / 100))
        ),
        "packet_loss": loss,
    }

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


def _ping_summary(target: str, evidence: Mapping[str, object]) -> str:
    loss = _as_float(evidence["packet_loss"])
    average = evidence.get("rtt_avg_ms")
    if average is not None:
        return f"{target}: {loss:g}% packet loss, {_as_float(average):.2f} ms average RTT"
    return f"{target}: {loss:g}% packet loss"


def _as_float(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int | float | str):
        return float(value)
    raise TypeError(f"expected numeric ping evidence, got {type(value).__name__}")
