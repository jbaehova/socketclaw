"""PortScanProbe — asyncio-based async TCP port scanner.

Scans the specified ports of a target host and detects diffs from the previous state.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .base import BaseProbe

logger = logging.getLogger(__name__)

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017,
]


class PortScanProbe(BaseProbe):
    """Async TCP connect port scan probe.

    Args:
        targets: List of hosts to scan.
        queue: Event delivery queue.
        ports: List of ports to scan.
        interval: Scan interval (seconds).
        connect_timeout: TCP connect timeout (seconds).
    """

    def __init__(
        self,
        targets: list[str],
        queue: asyncio.Queue[dict[str, Any]],
        ports: list[int] | None = None,
        interval: float = 60.0,
        connect_timeout: float = 1.0,
    ) -> None:
        super().__init__(name="port_scan", queue=queue, interval=interval)
        self.targets = targets
        self.ports = ports or DEFAULT_PORTS
        self.connect_timeout = connect_timeout
        # host → set of open ports (previous state)
        self._prev_state: dict[str, set[int]] = {}

    async def _collect(self) -> dict[str, Any] | None:
        results = []
        for target in self.targets:
            result = await self._scan_host(target)
            results.append(result)
        return {
            "type": "port_scan_result",
            "results": results,
            "timestamp": time.time(),
        }

    async def _scan_host(self, host: str) -> dict[str, Any]:
        """Async scan all ports of a single host."""
        tasks = [self._check_port(host, port) for port in self.ports]
        port_results = await asyncio.gather(*tasks)

        open_ports: set[int] = set()
        scan_details: list[dict[str, Any]] = []

        for port, is_open in port_results:
            scan_details.append({"port": port, "open": is_open})
            if is_open:
                open_ports.add(port)

        # Diff with previous state
        prev = self._prev_state.get(host, set())
        newly_opened = open_ports - prev
        newly_closed = prev - open_ports
        self._prev_state[host] = open_ports

        severity = "normal"
        if newly_opened:
            severity = "warning"
        if len(newly_opened) >= 3:
            severity = "critical"

        return {
            "host": host,
            "open_ports": sorted(open_ports),
            "newly_opened": sorted(newly_opened),
            "newly_closed": sorted(newly_closed),
            "total_scanned": len(self.ports),
            "severity": severity,
        }

    async def _check_port(self, host: str, port: int) -> tuple[int, bool]:
        """Attempt TCP connect to a single port."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.connect_timeout,
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False
