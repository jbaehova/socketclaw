"""Resilient in-process monitoring orchestration and event fan-out."""

from __future__ import annotations

import asyncio
import math
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from pydantic import BaseModel, ConfigDict

from .detection import Detector
from .domain import EventSource, SecurityEvent, utc_now
from .storage import EventQuery, Repository, StoredEvent

Collector = Callable[[], Awaitable[Sequence[SecurityEvent]]]
Diagnostic = Callable[[str], Awaitable[SecurityEvent]]


@dataclass(frozen=True, slots=True)
class ProbeJob:
    name: str
    interval: float
    collect: Collector

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("probe name must not be empty")
        if (
            isinstance(self.interval, bool)
            or not math.isfinite(self.interval)
            or self.interval <= 0
        ):
            raise ValueError("probe interval must be finite and positive")


class MonitorStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    running: bool
    paused: bool
    started_at: datetime | None
    active_jobs: int
    last_error: str | None
    diagnostics: frozenset[str] = frozenset()


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
        if type(subscriber_queue_size) is not int or subscriber_queue_size < 1:
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
        self._lifecycle_lock = asyncio.Lock()
        self._process_lock = asyncio.Lock()
        self._runner: asyncio.Task[None] | None = None
        self._running = False
        self._paused = False
        self._started_at: datetime | None = None
        self._job_errors: dict[str, str] = {}
        self._runner_error: str | None = None

    @property
    def status(self) -> MonitorStatus:
        if self._runner is not None and self._runner.done():
            self._runner_done(self._runner)
        runner_alive = self._runner is not None and not self._runner.done()
        running = self._running and runner_alive
        return MonitorStatus(
            running=running,
            paused=self._paused if running else False,
            started_at=self._started_at,
            active_jobs=len(self.jobs) if running else 0,
            last_error=self._active_error(),
            diagnostics=frozenset(self.diagnostics),
        )

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self.status.running:
                return
            recent = await self.repository.list_events(
                EventQuery(
                    after=utc_now() - self.detector.window,
                    limit=self._recent.maxlen or 500,
                )
            )
            self._recent.clear()
            self._recent.extend(reversed(recent))
            self._job_errors.clear()
            self._runner_error = None
            self._stop_event.clear()
            self._resume_event.set()
            self._paused = False
            self._running = True
            self._started_at = utc_now()
            self._runner = self._create_runner()

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
        async with self._lifecycle_lock:
            if not self._running and self._runner is None:
                return
            self._stop_event.set()
            self._resume_event.set()
            try:
                await self._cancel_runner()
            finally:
                self._running = False
                self._paused = False

    async def reconfigure(
        self,
        *,
        jobs: Sequence[ProbeJob],
        diagnostics: dict[str, Diagnostic],
    ) -> None:
        """Replace probe definitions without disrupting event subscribers."""
        replacement_jobs = tuple(jobs)
        replacement_diagnostics = dict(diagnostics)
        async with self._lifecycle_lock:
            previous_jobs = self.jobs
            previous_diagnostics = self.diagnostics
            was_running = self.status.running
            was_paused = self._paused
            if was_running:
                try:
                    await self._cancel_runner()
                except asyncio.CancelledError:
                    self.jobs = previous_jobs
                    self.diagnostics = previous_diagnostics
                    self._restore_runner(paused=was_paused)
                    raise

            self.jobs = replacement_jobs
            self.diagnostics = replacement_diagnostics
            self._job_errors.clear()
            self._runner_error = None

            if was_running:
                self._stop_event.clear()
                if was_paused:
                    self._resume_event.clear()
                else:
                    self._resume_event.set()
                self._runner = self._create_runner()
                self._running = True
                self._paused = was_paused

    def _restore_runner(self, *, paused: bool) -> None:
        """Synchronously restore a runner after reconfiguration is cancelled."""
        self._stop_event.clear()
        if paused:
            self._resume_event.clear()
        else:
            self._resume_event.set()
        self._runner = self._create_runner()
        self._running = True
        self._paused = paused

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
        async with self._process_lock:
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
        async with asyncio.TaskGroup() as group:
            for job in self.jobs:
                group.create_task(
                    self._run_job(job),
                    name=f"socketclaw-probe-{job.name}",
                )
            await asyncio.Event().wait()

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
                error = _error_message(exc)
                self._job_errors[job.name] = error
                try:
                    await self.process_event(
                        SecurityEvent(
                            source=EventSource.SYSTEM,
                            event_type="system.probe_error",
                            title=f"{job.name[:175]} probe failed",
                            summary=error,
                            evidence={
                                "probe": job.name[:1000],
                                "error": error,
                            },
                        )
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as persistence_error:
                    self._job_errors[job.name] = (
                        f"{error}; could not persist probe error: "
                        f"{_error_message(persistence_error)}"
                    )[:2000]
            else:
                self._job_errors.pop(job.name, None)
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=job.interval,
                )

    def _create_runner(self) -> asyncio.Task[None]:
        runner = asyncio.create_task(
            self._run_jobs(),
            name="socketclaw-monitor",
        )
        runner.add_done_callback(self._runner_done)
        return runner

    async def _cancel_runner(self) -> None:
        runner = self._runner
        self._runner = None
        if runner is None:
            return
        runner.cancel()
        try:
            await runner
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
        except Exception as exc:
            self._runner_error = _error_message(exc)

    def _runner_done(self, runner: asyncio.Task[None]) -> None:
        if not runner.cancelled():
            exception = runner.exception()
            if exception is not None:
                self._runner_error = _error_message(exception)
            elif runner is self._runner:
                self._runner_error = "monitor runner stopped unexpectedly"
        if runner is self._runner:
            self._runner = None
            self._running = False
            self._paused = False

    def _active_error(self) -> str | None:
        if self._runner_error is not None:
            return self._runner_error
        return next(reversed(self._job_errors.values()), None)

    def _broadcast(self, event: SecurityEvent) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                with suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)


def _error_message(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        group = cast(BaseExceptionGroup[BaseException], exc)
        exceptions = cast(tuple[BaseException, ...], group.exceptions)
        details = "; ".join(_error_message(nested) for nested in exceptions)
        return details[:2000]
    message = str(exc).strip() or type(exc).__name__
    return message[:2000]
