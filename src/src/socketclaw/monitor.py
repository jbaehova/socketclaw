"""Resilient in-process monitoring orchestration and event fan-out."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast

from pydantic import BaseModel, ConfigDict

from .collection import ProbeBatch
from .detection import Detector
from .domain import EventSource, ObservationOutcome, SecurityEvent, utc_now
from .health import ProbeHealth, initial_jitter, next_tick
from .storage import Repository, StoredEvent

Collector = Callable[[], Awaitable[Sequence[SecurityEvent] | ProbeBatch]]
Diagnostic = Callable[[str], Awaitable[SecurityEvent | ProbeBatch]]


@dataclass(frozen=True, slots=True)
class ProbeJob:
    name: str
    interval: float
    collect: Collector

    def __post_init__(self) -> None:
        if not self.name.strip() or len(self.name) > 300:
            raise ValueError("probe name must contain 1 to 300 characters")
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
    probe_health: tuple[ProbeHealth, ...] = ()
    dropped_notifications: int = 0
    pending_batches: int = 0


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
        collection_concurrency: int = 8,
    ) -> None:
        if type(subscriber_queue_size) is not int or subscriber_queue_size < 1:
            raise ValueError("subscriber queue size must be positive")
        if type(collection_concurrency) is not int or not 1 <= collection_concurrency <= 64:
            raise ValueError("collection concurrency must be between 1 and 64")
        self._collection_slots = asyncio.Semaphore(collection_concurrency)
        self.repository = repository
        self.detector = detector
        self.jobs = tuple(jobs)
        if len({job.name for job in self.jobs}) != len(self.jobs):
            raise ValueError("probe job names must be unique")
        self.diagnostics = dict(diagnostics or {})
        self.subscriber_queue_size = subscriber_queue_size
        self._subscribers: set[asyncio.Queue[SecurityEvent]] = set()
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
        self._pending_batches: dict[str, ProbeBatch] = {}
        self._collection_locks: dict[str, asyncio.Lock] = {}
        self._runner_error: str | None = None
        self._health_write_error: str | None = None
        self._health: dict[str, ProbeHealth] = {}
        self._reported_errors: dict[str, str] = {}
        self._schedule_wakes: dict[str, asyncio.Event] = {}
        self._schedule_revision = 0
        self._dropped_notifications = 0

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
            probe_health=tuple(
                item.model_copy(update={"next_due_at": None})
                if self._paused or not running
                else item
                for item in self._health.values()
            ),
            dropped_notifications=self._dropped_notifications,
            pending_batches=len(self._pending_batches),
        )

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self.status.running:
                return
            restored = await self.repository.list_probe_health([job.name for job in self.jobs])
            self._health.update({item.probe_id: item for item in restored})
            for job in self.jobs:
                previous = self._health.get(job.name)
                if previous is not None and previous.activity in {"scheduled", "manual"}:
                    self._health[job.name] = previous.model_copy(
                        update={
                            "activity": "interrupted",
                            "state": "degraded",
                            "error_kind": "interrupted",
                            "next_due_at": None,
                            "error": (
                                "Previous collection was interrupted. "
                                "This attempt has no confirmed completion."
                            ),
                            "updated_at": utc_now(),
                        }
                    )
                    await self._persist_health(job.name)
                elif previous is None:
                    self._health[job.name] = ProbeHealth(
                        probe_id=job.name, interval_seconds=job.interval
                    )
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
        self._wake_schedule()

    def resume(self) -> None:
        if not self._running:
            return
        self._paused = False
        self._resume_event.set()
        self._wake_schedule()

    def _wake_schedule(self) -> None:
        self._schedule_revision += 1
        for wake in self._schedule_wakes.values():
            wake.set()

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
                for name, health in self._health.items():
                    self._health[name] = health.model_copy(update={"next_due_at": None})
                    await self._persist_health(name)

    async def reconfigure(
        self,
        *,
        jobs: Sequence[ProbeJob],
        diagnostics: dict[str, Diagnostic],
        detector: Detector | None = None,
    ) -> None:
        """Replace probe definitions without disrupting event subscribers."""
        replacement_jobs = tuple(jobs)
        replacement_names = {job.name for job in replacement_jobs}
        if len(replacement_names) != len(replacement_jobs):
            raise ValueError("probe job names must be unique")
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

            try:
                # Removing a target must not silently discard a measured result.
                for name in tuple(self._pending_batches):
                    if name not in replacement_names or (
                        detector is not None and detector.config != self.detector.config
                    ):
                        async with self._collection_locks.setdefault(name, asyncio.Lock()):
                            pending = self._pending_batches.get(name)
                            if pending is not None:
                                await self.process_batch(pending)
                                self._pending_batches.pop(name, None)
            except BaseException:
                if was_running:
                    self._restore_runner(paused=was_paused)
                raise
            self._health = {
                name: health
                for name, health in self._health.items()
                if name in replacement_names
                or (name in self._collection_locks and self._collection_locks[name].locked())
            }
            self._schedule_wakes = {
                name: wake
                for name, wake in self._schedule_wakes.items()
                if name in replacement_names
            }
            self._reported_errors = {
                name: error
                for name, error in self._reported_errors.items()
                if name in replacement_names
            }
            self._collection_locks = {
                name: lock
                for name, lock in self._collection_locks.items()
                if name in replacement_names or lock.locked()
            }
            if detector is not None:
                async with self._process_lock:
                    self.detector = detector
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
        key = f"{kind}:{target}"
        async with self._collection_locks.setdefault(key, asyncio.Lock()), self._collection_slots:
            pending = self._pending_batches.get(key)
            if pending is not None:
                await self.process_batch(pending)
                self._pending_batches.pop(key, None)
            interval = next((job.interval for job in self.jobs if job.name == key), 60.0)

            async def collect() -> ProbeBatch:
                result = await handler(target)
                return (
                    result if isinstance(result, ProbeBatch) else ProbeBatch(observations=(result,))
                )

            job = ProbeJob(key, interval, collect)
            try:
                stored = await self._execute_job(job, due=time.monotonic(), manual=True)
            finally:
                await self._persist_health(key)
            if len(stored) != 1:
                raise RuntimeError("A diagnostic must produce exactly one new observation")
            return stored[0]

    async def process_event(self, event: SecurityEvent) -> StoredEvent:
        stored = await self.process_batch(ProbeBatch(observations=(event,)))
        if not stored:
            raise ValueError("Observation was already ingested")
        return stored[0]

    async def process_batch(self, batch: ProbeBatch) -> list[StoredEvent]:
        async with self._process_lock:
            stored = await self.repository.ingest_batch(batch, self.detector)
        for observation in stored:
            self._broadcast(observation)
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
        due = time.monotonic() + initial_jitter(job.name, job.interval)
        revision = self._schedule_revision
        wake = self._schedule_wakes.setdefault(job.name, asyncio.Event())
        while not self._stop_event.is_set():
            await self._resume_event.wait()
            if self._stop_event.is_set():
                break
            if revision != self._schedule_revision:
                revision = self._schedule_revision
                due = time.monotonic() + initial_jitter(job.name, job.interval)
            self._set_next_due(job, due)
            delay = due - time.monotonic()
            if delay > 0:
                with suppress(TimeoutError):
                    await asyncio.wait_for(wake.wait(), timeout=delay)
                wake.clear()
                continue
            async with (
                self._collection_locks.setdefault(job.name, asyncio.Lock()),
                self._collection_slots,
            ):
                # Pausing also holds jobs that were waiting for another operation's lock.
                if self._paused:
                    continue
                try:
                    await self._execute_job(job, due=due)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass  # _execute_job recorded the failure without stopping other jobs.
                due, skipped = next_tick(due, job.interval, time.monotonic())
                self._set_next_due(job, due, skipped=skipped)
                await self._persist_health(job.name)

    def _set_next_due(self, job: ProbeJob, due: float, *, skipped: int = 0) -> None:
        health = self._health.get(
            job.name, ProbeHealth(probe_id=job.name, interval_seconds=job.interval)
        )
        self._health[job.name] = health.model_copy(
            update={
                "interval_seconds": job.interval,
                "next_due_at": utc_now() + timedelta(seconds=max(0, due - time.monotonic())),
                "skipped_ticks": health.skipped_ticks + skipped,
            }
        )

    async def _execute_job(
        self, job: ProbeJob, *, due: float, manual: bool = False
    ) -> list[StoredEvent]:
        started = time.monotonic()
        previous = self._health.get(
            job.name, ProbeHealth(probe_id=job.name, interval_seconds=job.interval)
        )
        self._health[job.name] = previous.model_copy(
            update={
                "activity": "manual" if manual else "scheduled",
                "last_attempt_at": utc_now(),
                "updated_at": utc_now(),
                "lag_ms": max(0, started - due) * 1000,
            }
        )
        await self._persist_health(job.name)
        stage = "collection"
        try:
            batch = self._pending_batches.get(job.name)
            if batch is None:
                result = await job.collect()
                batch = (
                    result
                    if isinstance(result, ProbeBatch)
                    else ProbeBatch(observations=tuple(result))
                )
                self._pending_batches[job.name] = batch
            stage = "storage"
            stored = await self.process_batch(batch)
            self._pending_batches.pop(job.name, None)
        except asyncio.CancelledError:
            self._health[job.name] = self._health[job.name].model_copy(
                update={
                    "activity": "interrupted",
                    "state": "degraded",
                    "error_kind": "interrupted",
                    "error": "Collection was canceled before confirmed completion.",
                    "next_due_at": None,
                    "updated_at": utc_now(),
                }
            )
            await self._persist_health(job.name)
            raise
        except Exception as exc:
            error = _error_message(exc)
            self._job_errors[job.name] = error
            self._health[job.name] = self._health[job.name].model_copy(
                update={
                    "state": "degraded",
                    "activity": "idle",
                    "error_kind": stage,
                    "error": error,
                    "consecutive_errors": previous.consecutive_errors + 1,
                    "updated_at": utc_now(),
                    "duration_ms": (time.monotonic() - started) * 1000,
                    "pending_observations": len(self._pending_batches[job.name].observations)
                    if job.name in self._pending_batches
                    else 0,
                }
            )
            if self._reported_errors.get(job.name) != error:
                try:
                    await self.process_event(
                        SecurityEvent(
                            source=EventSource.SYSTEM,
                            event_type="system.probe_error",
                            title=f"{job.name[:175]} probe failed",
                            summary=error,
                            evidence={"probe": job.name[:1000], "error": error},
                        )
                    )
                    self._reported_errors[job.name] = error
                except asyncio.CancelledError:
                    raise
                except Exception as persistence_error:
                    self._job_errors[job.name] = (
                        f"{error}; could not persist probe error: "
                        f"{_error_message(persistence_error)}"
                    )[:2000]
            raise
        error_kind, error = _batch_problem(batch)
        now = utc_now()
        self._health[job.name] = self._health[job.name].model_copy(
            update={
                "state": "degraded" if error_kind else "healthy",
                "activity": "idle",
                "error_kind": error_kind,
                "error": error,
                "updated_at": now,
                "consecutive_errors": previous.consecutive_errors + 1 if error_kind else 0,
                "last_success_at": previous.last_success_at if error_kind else batch.collected_at,
                "last_observation_at": max(item.observed_at for item in batch.observations)
                if batch.observations
                else previous.last_observation_at,
                "duration_ms": (time.monotonic() - started) * 1000,
                "pending_observations": 0,
            }
        )
        self._job_errors.pop(job.name, None)
        self._reported_errors.pop(job.name, None)
        return stored

    async def _persist_health(self, probe_id: str) -> None:
        try:
            await self.repository.save_probe_health(self._health[probe_id])
        except Exception as exc:
            self._health_write_error = f"Health state could not be saved: {_error_message(exc)}"[
                :2000
            ]
        else:
            self._health_write_error = None

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
        if self._health_write_error is not None:
            return self._health_write_error
        return next(reversed(self._job_errors.values()), None) or next(
            (
                item.error
                for item in self._health.values()
                if item.state == "degraded" and item.error
            ),
            None,
        )

    def _broadcast(self, event: SecurityEvent) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                with suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                    self._dropped_notifications += 1
            queue.put_nowait(event)


def _error_message(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        group = cast(BaseExceptionGroup[BaseException], exc)
        exceptions = cast(tuple[BaseException, ...], group.exceptions)
        details = "; ".join(_error_message(nested) for nested in exceptions)
        return details[:2000]
    message = str(exc).strip() or type(exc).__name__
    return message[:2000]


def _batch_problem(batch: ProbeBatch) -> tuple[str | None, str | None]:
    if batch.gaps:
        return "ingestion_gap", (
            "A log generation could not be recovered completely. Inspect log source gaps."
        )
    for signal in batch.health:
        if signal.state == "degraded":
            return signal.error_kind or "collector", signal.detail or "Collector is degraded"
    for observation in batch.observations:
        if observation.outcome in {ObservationOutcome.ERROR, ObservationOutcome.UNKNOWN}:
            return observation.outcome.value, observation.summary[:2000]
        if (
            observation.source == EventSource.PORT_SCAN
            and observation.outcome == ObservationOutcome.PARTIAL
        ):
            return "partial_scan", observation.summary[:2000]
    return None, None
