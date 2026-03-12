"""PingProbe — raw socket ICMP ping probe.

Directly implements ICMP echo request/reply to measure RTT and packet loss.
Requires root privileges; falls back to subprocess ping if unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import struct
import time
from typing import Any

from .base import BaseProbe

logger = logging.getLogger(__name__)

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_HEADER_FMT = "!BBHHH"  # type, code, checksum, id, seq
ICMP_HEADER_SIZE = struct.calcsize(ICMP_HEADER_FMT)


def _internet_checksum(data: bytes) -> int:
    """Compute RFC 1071 internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_icmp_packet(seq: int, ident: int, payload_size: int = 56) -> bytes:
    """Build an ICMP echo request packet."""
    payload = bytes(range(payload_size))
    # Build header with checksum=0
    header = struct.pack(ICMP_HEADER_FMT, ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chksum = _internet_checksum(header + payload)
    header = struct.pack(ICMP_HEADER_FMT, ICMP_ECHO_REQUEST, 0, chksum, ident, seq)
    return header + payload


class PingProbe(BaseProbe):
    """ICMP ping probe.

    Args:
        targets: List of hosts to monitor.
        queue: Event delivery queue.
        interval: Ping interval (seconds).
        timeout: Response wait timeout (seconds).
        count: Number of packets to send per measurement.
        loss_threshold: Loss ratio above this triggers severity=warning.
    """

    def __init__(
        self,
        targets: list[str],
        queue: asyncio.Queue[dict[str, Any]],
        interval: float = 5.0,
        timeout: float = 2.0,
        count: int = 3,
        loss_threshold: float = 0.5,
    ) -> None:
        super().__init__(name="ping", queue=queue, interval=interval)
        self.targets = targets
        self.timeout = timeout
        self.count = count
        self.loss_threshold = loss_threshold
        self._ident = os.getpid() & 0xFFFF
        self._seq = 0
        self._use_raw = self._check_raw_socket()

    @staticmethod
    def _check_raw_socket() -> bool:
        """Check whether raw socket is available."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            s.close()
            return True
        except PermissionError:
            logger.info("No raw socket permission — using subprocess ping fallback")
            return False

    async def _collect(self) -> dict[str, Any] | None:
        results = []
        for target in self.targets:
            result = await self._ping_host(target)
            results.append(result)
        return {
            "type": "ping_result",
            "results": results,
            "timestamp": time.time(),
        }

    async def _ping_host(self, host: str) -> dict[str, Any]:
        """Perform a ping to a single host."""
        if self._use_raw:
            return await self._raw_ping(host)
        return await self._subprocess_ping(host)

    async def _raw_ping(self, host: str) -> dict[str, Any]:
        """ICMP ping using raw socket."""
        import socket

        rtt_list: list[float] = []
        lost = 0

        for _ in range(self.count):
            self._seq = (self._seq + 1) & 0xFFFF
            packet = _build_icmp_packet(self._seq, self._ident)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
                sock.settimeout(self.timeout)
                sock.setblocking(False)

                loop = asyncio.get_event_loop()
                start = time.monotonic()
                await loop.run_in_executor(None, sock.sendto, packet, (host, 0))

                # Wait for response
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recv(1024)),
                        timeout=self.timeout,
                    )
                    elapsed = (time.monotonic() - start) * 1000  # ms
                    # Skip IP header (20 bytes) and parse ICMP header
                    icmp_header = data[20:20 + ICMP_HEADER_SIZE]
                    icmp_type, _, _, recv_id, recv_seq = struct.unpack(ICMP_HEADER_FMT, icmp_header)
                    if icmp_type == ICMP_ECHO_REPLY and recv_id == self._ident:
                        rtt_list.append(elapsed)
                    else:
                        lost += 1
                except (asyncio.TimeoutError, TimeoutError):
                    lost += 1
                finally:
                    sock.close()
            except Exception as exc:
                logger.debug("Raw ping to %s failed: %s", host, exc)
                lost += 1

        return self._build_result(host, rtt_list, lost)

    async def _subprocess_ping(self, host: str) -> dict[str, Any]:
        """Subprocess-based ping fallback."""
        flag = "-c" if platform.system() != "Windows" else "-n"
        timeout_flag = "-W" if platform.system() != "Windows" else "-w"
        cmd = ["ping", flag, str(self.count), timeout_flag, str(int(self.timeout * 1000)), host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout * self.count + 5)
            output = stdout.decode(errors="replace")
            return self._parse_ping_output(host, output)
        except (asyncio.TimeoutError, Exception) as exc:
            logger.debug("Subprocess ping to %s failed: %s", host, exc)
            return self._build_result(host, [], self.count)

    def _parse_ping_output(self, host: str, output: str) -> dict[str, Any]:
        """Parse ping command output."""
        import re

        rtt_list: list[float] = []
        lost = self.count

        # Extract RTT (macOS/Linux: "time=X.XXX ms")
        for match in re.finditer(r"time[=<]([\d.]+)\s*ms", output):
            rtt_list.append(float(match.group(1)))

        lost = self.count - len(rtt_list)
        return self._build_result(host, rtt_list, lost)

    def _build_result(self, host: str, rtt_list: list[float], lost: int) -> dict[str, Any]:
        total = self.count
        loss_pct = lost / total if total > 0 else 0.0
        severity = "normal"
        if loss_pct >= 1.0:
            severity = "critical"
        elif loss_pct >= self.loss_threshold:
            severity = "warning"

        avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0.0
        min_rtt = min(rtt_list) if rtt_list else 0.0
        max_rtt = max(rtt_list) if rtt_list else 0.0

        return {
            "host": host,
            "sent": total,
            "received": total - lost,
            "loss_pct": round(loss_pct * 100, 1),
            "rtt_min": round(min_rtt, 2),
            "rtt_avg": round(avg_rtt, 2),
            "rtt_max": round(max_rtt, 2),
            "severity": severity,
        }
