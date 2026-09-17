"""Bounded asynchronous TCP reachability scanning."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable, Iterable
from contextlib import suppress
from typing import cast

from pydantic import JsonValue

from ..domain import EventSource, SecurityEvent

Connector = Callable[[str, int, float], Awaitable[bool | None]]


class PortProbe:
    def __init__(
        self,
        *,
        connector: Connector | None = None,
        concurrency: int = 100,
        timeout: float = 0.75,
    ) -> None:
        if type(concurrency) is not int or concurrency < 1:
            raise ValueError("port scan concurrency must be positive")
        if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("port scan timeout must be finite and between 0 and 60 seconds")
        self.connector = connector or _tcp_connect
        self.concurrency = concurrency
        self.timeout = timeout
        self._connection_slots = asyncio.Semaphore(concurrency)
        self._previous: dict[str, set[int]] = {}
        self._target_locks: dict[str, asyncio.Lock] = {}

    def retained_for_targets(self, targets: Iterable[str]) -> PortProbe:
        """Clone retained baselines for one new active target set."""
        active = set(targets)
        replacement = PortProbe(
            connector=self.connector,
            concurrency=self.concurrency,
            timeout=self.timeout,
        )
        replacement._previous = {
            target: set(ports) for target, ports in self._previous.items() if target in active
        }
        return replacement

    async def collect(
        self,
        target: str,
        ports: Iterable[int],
    ) -> SecurityEvent:
        if not target or target != target.strip() or len(target) > 253 or target.startswith("-"):
            raise ValueError("port scan target must be a non-empty host or address")
        candidates = _validated_ports(ports)
        target_lock = self._target_locks.setdefault(target, asyncio.Lock())
        async with target_lock:
            return await self._collect_locked(target, candidates)

    async def _collect_locked(
        self,
        target: str,
        candidates: list[int],
    ) -> SecurityEvent:
        queue = asyncio.Queue[int]()
        for port in candidates:
            queue.put_nowait(port)

        async def check(port: int) -> tuple[int, bool | None]:
            try:
                async with self._connection_slots:
                    opened = _port_state(
                        await asyncio.wait_for(
                            self.connector(target, port, self.timeout),
                            timeout=self.timeout,
                        )
                    )
            except (OSError, TimeoutError):
                opened = None
            return port, opened

        results: list[tuple[int, bool | None]] = []

        async def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                results.append(await check(port))

        async with asyncio.TaskGroup() as group:
            for _ in range(min(self.concurrency, len(candidates))):
                group.create_task(worker())

        current = {port for port, opened in results if opened}
        unresolved = {port for port, opened in results if opened is None}
        previous = self._previous.get(target)
        if previous is not None:
            current.update(previous & unresolved)
        baseline = previous is None
        newly_opened = [] if previous is None else sorted(current - previous)
        newly_closed = [] if previous is None else sorted(previous - current)
        self._previous[target] = current

        if newly_opened:
            title = f"{len(newly_opened)} new port(s) on {target}"
        elif newly_closed:
            title = f"{len(newly_closed)} port(s) closed on {target}"
        elif unresolved:
            title = f"Port scan incomplete on {target}"
        else:
            title = f"Port state unchanged on {target}"
        evidence: dict[str, JsonValue] = {
            "scanned_ports": cast(list[JsonValue], candidates),
            "open_ports": cast(list[JsonValue], sorted(current)),
            "newly_opened": cast(list[JsonValue], newly_opened),
            "newly_closed": cast(list[JsonValue], newly_closed),
            "unresolved_ports": cast(list[JsonValue], sorted(unresolved)),
            "baseline": baseline,
        }
        return SecurityEvent(
            source=EventSource.PORT_SCAN,
            event_type="port_scan.result",
            title=title,
            summary=(f"{target}: {len(current)} open of {len(candidates)} scanned TCP ports"),
            target=target,
            evidence=evidence,
        )


async def _tcp_connect(host: str, port: int, timeout: float) -> bool | None:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except ConnectionRefusedError:
        return False
    except (OSError, TimeoutError):
        return None
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()
    return True


def _validated_ports(ports: Iterable[int]) -> list[int]:
    candidates: set[int] = set()
    for port in ports:
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"invalid TCP port: {port!r}")
        candidates.add(port)
    if not candidates:
        raise ValueError("at least one TCP port is required")
    return sorted(candidates)


def _port_state(value: object) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise TypeError("port connector must return bool or None")
