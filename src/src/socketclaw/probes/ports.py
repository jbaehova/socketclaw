"""Bounded asynchronous TCP reachability scanning."""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Awaitable, Callable, Iterable
from contextlib import suppress
from typing import cast

from pydantic import JsonValue

from ..collection import PortBaselineState, ProbeBatch
from ..domain import EventSource, ObservationOutcome, SecurityEvent, utc_now
from ..storage import Repository

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
        self._scopes: dict[str, set[int]] = {}
        self._known: dict[str, set[int]] = {}
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
        replacement._scopes = {
            target: set(ports) for target, ports in self._scopes.items() if target in active
        }
        replacement._known = {
            target: set(ports) for target, ports in self._known.items() if target in active
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

    async def collect_batch(
        self,
        target: str,
        ports: Iterable[int],
        repository: Repository,
        *,
        baseline_ttl: float = 86400.0,
    ) -> ProbeBatch:
        """Prepare a scan without advancing its last committed baseline."""
        if not target or target != target.strip() or len(target) > 253 or target.startswith("-"):
            raise ValueError("port scan target must be a non-empty host or address")
        if not math.isfinite(baseline_ttl) or baseline_ttl <= 0:
            raise ValueError("baseline TTL must be finite and positive")
        candidates = _validated_ports(ports)
        async with self._target_locks.setdefault(target, asyncio.Lock()):
            checkpoint = await repository.load_checkpoint(port_probe_id(target))
            baseline = PortBaselineState.model_validate(checkpoint.state)
            now = utc_now()
            stale = {
                port
                for port, confirmed in baseline.confirmed_at.items()
                if not 0 <= (now - confirmed).total_seconds() <= baseline_ttl
            }
            maps = self._previous, self._scopes, self._known
            previous = tuple(mapping.get(target) for mapping in maps)
            try:
                for mapping in maps:
                    mapping.pop(target, None)
                if checkpoint.expected_revision:
                    self._previous[target] = set(baseline.opened)
                    self._scopes[target] = set(baseline.scope)
                    self._known[target] = set(baseline.confirmed_at)
                event = await self._collect_locked(target, candidates, stale_ports=stale)
                unresolved = set(cast(list[int], event.evidence["unresolved_ports"]))
                confirmed_at = {
                    port: baseline.confirmed_at[port] if port in unresolved else event.observed_at
                    for port in self._known[target]
                }
                candidate = PortBaselineState(
                    scope=tuple(candidates),
                    opened=tuple(sorted(self._previous[target])),
                    confirmed_at=confirmed_at,
                )
                evidence = dict(event.evidence)
                evidence.update(
                    baseline_stale=bool(stale & set(candidates)),
                    baseline_stale_ports=cast(list[JsonValue], sorted(stale & set(candidates))),
                    baseline_ttl_seconds=baseline_ttl,
                    baseline_revision=checkpoint.expected_revision,
                    baseline_oldest_confirmation_at=(
                        min(baseline.confirmed_at.values()).isoformat()
                        if baseline.confirmed_at
                        else None
                    ),
                    scope_revision=hashlib.sha256(
                        ",".join(str(port) for port in candidates).encode()
                    ).hexdigest(),
                )
                event = event.model_copy(update={"evidence": evidence})
                return ProbeBatch(
                    observations=(event,),
                    checkpoints=(
                        checkpoint.model_copy(update={"state": candidate.model_dump(mode="json")}),
                    ),
                )
            finally:
                for mapping, value in zip(maps, previous, strict=True):
                    if value is None:
                        mapping.pop(target, None)
                    else:
                        mapping[target] = value

    async def _collect_locked(
        self,
        target: str,
        candidates: list[int],
        *,
        stale_ports: set[int] | None = None,
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
        previous = self._previous.get(target, set())
        scope = set(candidates)
        previous_scope = self._scopes.get(target, set())
        known = self._known.get(target, set()) & scope & previous_scope
        comparable = known - (stale_ports or set())
        closed = {port for port, opened in results if opened is False}
        baseline = target not in self._scopes
        newly_opened = sorted((current - previous) & comparable)
        newly_closed = sorted(closed & previous & comparable)
        initial_open = sorted(current - comparable)
        self._previous[target] = current | (previous & unresolved & known)
        self._known[target] = known | current | closed
        self._scopes[target] = scope

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
            "scope_added": cast(list[JsonValue], sorted(scope - previous_scope)),
            "scope_removed": cast(list[JsonValue], sorted(previous_scope - scope)),
            "initial_open_ports": cast(list[JsonValue], initial_open),
            "last_known_open_ports": cast(list[JsonValue], sorted(self._previous[target])),
            "outcome": "unknown"
            if len(unresolved) == len(candidates)
            else "partial"
            if unresolved
            else "ok",
        }
        return SecurityEvent(
            source=EventSource.PORT_SCAN,
            event_type="port_scan.result",
            title=title,
            summary=(f"{target}: {len(current)} open of {len(candidates)} scanned TCP ports"),
            target=target,
            evidence=evidence,
            outcome=ObservationOutcome(str(evidence["outcome"])),
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


def port_probe_id(target: str) -> str:
    return "ports:" + hashlib.sha256(target.casefold().encode()).hexdigest()
