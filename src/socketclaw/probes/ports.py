"""Bounded asynchronous TCP reachability scanning."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable

from ..domain import EventSource, SecurityEvent

Connector = Callable[[str, int, float], Awaitable[bool]]


class PortProbe:
    def __init__(
        self,
        *,
        connector: Connector | None = None,
        concurrency: int = 100,
        timeout: float = 0.75,
    ) -> None:
        if concurrency < 1:
            raise ValueError("port scan concurrency must be positive")
        self.connector = connector or _tcp_connect
        self.concurrency = concurrency
        self.timeout = timeout
        self._previous: dict[str, set[int]] = {}

    async def collect(
        self,
        target: str,
        ports: Iterable[int],
    ) -> SecurityEvent:
        candidates = sorted({port for port in ports if 1 <= port <= 65535})
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check(port: int) -> tuple[int, bool]:
            async with semaphore:
                try:
                    opened = await self.connector(target, port, self.timeout)
                except (OSError, TimeoutError):
                    opened = False
                return port, opened

        results = await asyncio.gather(*(check(port) for port in candidates))
        current = {port for port, opened in results if opened}
        previous = self._previous.get(target, set())
        newly_opened = sorted(current - previous)
        newly_closed = sorted(previous - current)
        self._previous[target] = current

        if newly_opened:
            title = f"{len(newly_opened)} new port(s) on {target}"
        elif newly_closed:
            title = f"{len(newly_closed)} port(s) closed on {target}"
        else:
            title = f"Port state unchanged on {target}"
        evidence = {
            "scanned_ports": candidates,
            "open_ports": sorted(current),
            "newly_opened": newly_opened,
            "newly_closed": newly_closed,
        }
        return SecurityEvent(
            source=EventSource.PORT_SCAN,
            event_type="port_scan.result",
            title=title,
            summary=(f"{target}: {len(current)} open of {len(candidates)} scanned TCP ports"),
            target=target,
            evidence=evidence,
        )


async def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except (OSError, TimeoutError):
        return False
    writer.close()
    await writer.wait_closed()
    return True
