"""Resilient in-process monitoring orchestration and event fan-out."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from .detection import Detector
from .domain import EventSource, SecurityEvent, utc_now
from .storage import Repository, StoredEvent

Collector = Callable[[], Awaitable[Sequence[SecurityEvent]]]
Diagnostic = Callable[[str], Awaitable[SecurityEvent]]


@dataclass(frozen=True, slots=True)
class ProbeJob:
    name: str
    interval: float
    collect: Collector

    def __post_init__(self) -> None:
        if self.interval <= 0:
            raise ValueError("probe interval must be positive")


class MonitorStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    running: bool
    paused: bool
    started_at: datetime | None
    active_jobs: int
    last_error: str | None


class MonitorService:
    """Run independent probe jobs while isolating and persisting failures."""

    def __init__(
        self,
        repository: Repository,
        detector: Detector,
        *,
        jobs: Sequence[ProbeJob] = (),
        diagnostics: dict[str, Diagnostic] | None = None,
        subscriber_queue_size: int = 500,
    ) -> None:
        if subscriber_queue_size < 1:
            raise ValueError("subscriber queue size must be positive")
        self.repository = repository
        self.detector = detector
        self.jobs = tuple(jobs)
        self.diagnostics = dict(diagnostics or {})
        self.subscriber_queue_size = subscriber_queue_size
        self._subscribers: set[asyncio.Queue[SecurityEvent]] = set()
        self._recent: deque[SecurityEvent] = deque(maxlen=500)
        self._stop_event = asyncio.Event()
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._runner: asyncio.Task[None] | None = None
        self._running = False
        self._paused = False
        self._started_at: datetime | None = None
        self._last_error: str | None = None

    @property
    def status(self) -> MonitorStatus:
        return MonitorStatus(
            running=self._running,
            paused=self._paused,
            started_at=self._started_at,
            active_jobs=len(self.jobs) if self._running else 0,
            last_error=self._last_error,
        )

    async def start(self) -> None:
        if self._running:
            return
        self._stop_event.clear()
        self._resume_event.set()
        self._paused = False
        self._running = True
        self._started_at = utc_now()
        self._runner = asyncio.create_task(
            self._run_jobs(),
            name="socketclaw-monitor",
        )

    def pause(self) -> None:
        if not self._running:
            return
        self._paused = True
        self._resume_event.clear()

    def resume(self) -> None:
        if not self._running:
            return
        self._paused = False
        self._resume_event.set()

    async def stop(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self._resume_event.set()
        if self._runner is not None:
            await self._runner
        self._runner = None
        self._running = False
        self._paused = False

    async def events(self) -> AsyncIterator[SecurityEvent]:
        queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=self.subscriber_queue_size)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    async def run_diagnostic(
        self,
        kind: str,
        target: str,
    ) -> StoredEvent:
        handler = self.diagnostics.get(kind)
        if handler is None:
            raise ValueError(f"Unknown diagnostic: {kind}")
        return await self.process_event(await handler(target))

    async def process_event(self, event: SecurityEvent) -> StoredEvent:
        detection = self.detector.score(event, tuple(self._recent))
        normalized = event.model_copy(
            update={
                "score": detection.score,
                "severity": detection.severity,
            }
        )
        stored = await self.repository.save_event(normalized, detection)
        self._recent.append(stored)
        self._broadcast(stored)
        return stored

    async def _run_jobs(self) -> None:
        try:
            async with asyncio.TaskGroup() as group:
                for job in self.jobs:
                    group.create_task(
                        self._run_job(job),
                        name=f"socketclaw-probe-{job.name}",
                    )
        finally:
            self._running = False

    async def _run_job(self, job: ProbeJob) -> None:
        while not self._stop_event.is_set():
            await self._resume_event.wait()
            if self._stop_event.is_set():
                break
            try:
                for event in await job.collect():
                    await self.process_event(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_error = str(exc)
                await self.process_event(
                    SecurityEvent(
                        source=EventSource.SYSTEM,
                        event_type="system.probe_error",
                        title=f"{job.name} probe failed",
                        summary=str(exc),
                        evidence={
                            "probe": job.name,
                            "error": str(exc),
                        },
                    )
                )
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=job.interval,
                )

    def _broadcast(self, event: SecurityEvent) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                with suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)
