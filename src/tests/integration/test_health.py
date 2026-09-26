"""Collector health distinguishes observation failures from target observations."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest

from socketclaw.collection import ProbeBatch
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent, utc_now
from socketclaw.health import ProbeHealth, initial_jitter, next_tick
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.probes.logs import LogProbe
from socketclaw.storage import EventQuery, Repository


@pytest.fixture
async def repository(tmp_path: Path):
    repo = Repository(tmp_path / "socketclaw.db")
    await repo.initialize()
    try:
        yield repo
    finally:
        await repo.close()


async def until(predicate, *, timeout: float = 2) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.005)


def test_schedule_uses_start_grid_and_counts_skipped_ticks() -> None:
    assert next_tick(100, 5, 101) == (105, 0)
    assert next_tick(100, 5, 113) == (115, 2)
    assert next_tick(100, 5, 115) == (120, 3)
    assert 0 <= initial_jitter("ports:server", 60) < 0.1
    assert initial_jitter("ports:server", 60) != initial_jitter("ping:server", 60)


def test_health_staleness_uses_last_success_and_documented_grace() -> None:
    now = utc_now()
    assert ProbeHealth(probe_id="ping:a", interval_seconds=5).is_stale(now)
    health = ProbeHealth(probe_id="ping:a", interval_seconds=5, last_success_at=now)
    assert not health.is_stale(now + timedelta(seconds=15))
    assert health.is_stale(now + timedelta(seconds=15.01))
    assert health.is_stale(now - timedelta(seconds=1))


async def test_replayed_old_measurement_does_not_look_fresh_after_storage_recovers(
    repository: Repository,
) -> None:
    measured = utc_now() - timedelta(hours=2)
    batch = ProbeBatch(
        collected_at=measured,
        observations=(
            SecurityEvent(
                source="ping",
                event_type="ping.result",
                title="Old measurement",
                summary="Old",
                outcome="ok",
                observed_at=measured,
            ),
        ),
    )

    async def collect():
        raise AssertionError("The pending measurement must be committed first")

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("ping:a", 60, collect)])
    monitor._pending_batches["ping:a"] = batch
    try:
        await monitor.start()
        await until(
            lambda: (
                bool(monitor.status.probe_health)
                and monitor.status.probe_health[0].last_success_at is not None
            )
        )
        health = monitor.status.probe_health[0]
        assert health.last_success_at == measured
        assert health.is_stale(utc_now())
        assert health.last_observation_at == measured
    finally:
        await monitor.stop()


async def test_repeated_exception_updates_count_without_event_flood_and_audits_recovery(
    repository: Repository,
) -> None:
    failures = True

    async def collect():
        if failures:
            raise OSError("probe permission denied")
        # Stop scheduling after recovery so shutdown cannot cancel the next
        # 15 ms probe and legitimately record a new interrupted transition.
        monitor.pause()
        return []

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("broken", 0.015, collect)])
    try:
        await monitor.start()
        await until(lambda: monitor.status.probe_health[0].consecutive_errors >= 3)
        assert len(await repository.list_events()) == 1
        health = monitor.status.probe_health[0]
        assert health.state == "degraded"
        assert health.last_success_at is None
        assert health.last_attempt_at is not None
        failures = False
        await until(lambda: monitor.status.probe_health[0].state == "healthy")
        assert monitor.status.probe_health[0].consecutive_errors == 0
        assert monitor.status.last_error is None
    finally:
        await monitor.stop()
    transitions = await repository.list_health_transitions("broken")
    assert [item.state for item in transitions].count("degraded") == 1
    assert transitions[0].state == "healthy"
    restored = (await repository.list_probe_health(["broken"]))[0]
    assert restored.last_success_at is not None
    assert restored.next_due_at is None


async def test_missing_log_signal_persists_one_gap_and_recovery(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "missing.log"
    probe = LogProbe([path], repository=repository)
    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("logs", 0.015, probe.collect)])
    try:
        await monitor.start()
        await until(
            lambda: (
                bool(monitor.status.probe_health)
                and monitor.status.probe_health[0].consecutive_errors >= 3
            )
        )
        health = monitor.status.probe_health[0]
        assert health.error_kind == "missing_source"
        assert "Missing log" in str(monitor.status.last_error)
        failures = await repository.list_events()
        assert len(failures) == 1
        assert failures[0].event_type == "system.probe_error"
        path.write_text("sshd[123]: Accepted publickey for alice from 192.0.2.9 port 54321 ssh2\n")
        await until(lambda: monitor.status.probe_health[0].state == "healthy")
        assert monitor.status.last_error is None
    finally:
        await monitor.stop()


async def test_measured_unreachable_target_is_successful_collection(repository: Repository) -> None:
    async def collect():
        return [
            SecurityEvent(
                source="ping",
                event_type="ping.result",
                title="No reply",
                summary="100% loss",
                outcome="unreachable",
                evidence={"packet_loss": 100.0},
            )
        ]

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("ping:a", 60, collect)])
    try:
        await monitor.start()
        await until(
            lambda: (
                bool(monitor.status.probe_health)
                and monitor.status.probe_health[0].last_success_at is not None
            )
        )
        assert monitor.status.probe_health[0].state == "healthy"
        assert monitor.status.last_error is None
    finally:
        await monitor.stop()


async def test_slow_job_skips_elapsed_ticks_without_overlap(repository: Repository) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def collect():
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return []

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("slow", 0.02, collect)])
    try:
        await monitor.start()
        await entered.wait()
        await asyncio.sleep(0.075)
        assert calls == 1
        monitor.pause()
        release.set()
        await until(lambda: monitor.status.probe_health[0].skipped_ticks >= 3)
        assert monitor.status.probe_health[0].duration_ms >= 70
    finally:
        await monitor.stop()


async def test_pause_finishes_inflight_but_holds_queued_jobs(repository: Repository) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls: list[str] = []

    async def collect_a():
        calls.append("a")
        entered.set()
        await release.wait()
        return []

    async def collect_b():
        calls.append("b")
        return []

    monitor = MonitorService(
        repository,
        Detector(),
        collection_concurrency=1,
        jobs=[ProbeJob("a", 0.03, collect_a), ProbeJob("b", 60, collect_b)],
    )
    try:
        await monitor.start()
        await entered.wait()
        monitor.pause()
        release.set()
        await until(
            lambda: any(
                item.last_success_at is not None
                for item in monitor.status.probe_health
                if item.probe_id == "a"
            )
        )
        await asyncio.sleep(0.04)
        assert calls == ["a"]
        assert all(item.next_due_at is None for item in monitor.status.probe_health)
        monitor.resume()
        await until(lambda: "b" in calls)
    finally:
        await monitor.stop()


async def test_removed_job_flushes_pending_measurement_before_reconfiguration(
    repository: Repository,
) -> None:
    monitor = MonitorService(repository, Detector())
    batch = ProbeBatch(
        observations=(
            SecurityEvent(
                source="ping",
                event_type="ping.result",
                title="Retained",
                summary="Retained",
                outcome="ok",
            ),
        )
    )
    monitor._pending_batches["ping:removed"] = batch
    await monitor.reconfigure(jobs=[], diagnostics={})
    assert monitor.status.pending_batches == 0
    assert len(await repository.list_events(EventQuery(source="ping"))) == 1


async def test_interrupted_attempt_is_audited_before_restart_collection(
    repository: Repository,
) -> None:
    previous = ProbeHealth(
        probe_id="ping:a",
        interval_seconds=60,
        activity="scheduled",
        state="healthy",
        last_attempt_at=utc_now(),
    )
    await repository.save_probe_health(previous)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def collect():
        entered.set()
        await release.wait()
        return []

    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("ping:a", 60, collect)])
    try:
        await monitor.start()
        await entered.wait()
        records = await repository.list_health_transitions("ping:a")
        assert any(item.error_kind == "interrupted" for item in records)
        assert monitor.status.probe_health[0].last_success_at is None
    finally:
        release.set()
        await monitor.stop()


async def test_manual_and_scheduled_operations_share_lock_and_report_manual_activity(
    repository: Repository,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    manual_entered = asyncio.Event()
    release_manual = asyncio.Event()

    async def collect():
        entered.set()
        await release.wait()
        return []

    async def manual(target: str):
        manual_entered.set()
        await release_manual.wait()
        return SecurityEvent(
            source="ping",
            event_type="ping.result",
            title="Manual",
            summary="Manual",
            target=target,
            outcome="ok",
        )

    monitor = MonitorService(
        repository, Detector(), jobs=[ProbeJob("ping:a", 60, collect)], diagnostics={"ping": manual}
    )
    task = None
    try:
        await monitor.start()
        await entered.wait()
        task = asyncio.create_task(monitor.run_diagnostic("ping", "a"))
        await asyncio.sleep(0.025)
        assert not manual_entered.is_set()
        release.set()
        await manual_entered.wait()
        assert monitor.status.probe_health[0].activity == "manual"
        release_manual.set()
        await task
        assert monitor.status.probe_health[0].activity == "idle"
    finally:
        release.set()
        release_manual.set()
        if task is not None:
            await task
        await monitor.stop()


async def test_shutdown_joins_inflight_observation_write(repository, monkeypatch):
    monitor = MonitorService(repository, Detector())
    await monitor.start()
    started = asyncio.Event()
    release = asyncio.Event()
    original = repository.ingest_batch

    async def gated_write(*args, **kwargs):
        started.set()
        await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(repository, "ingest_batch", gated_write)
    event = SecurityEvent(source="system", event_type="test", title="Committed", summary="Test")
    writing = asyncio.create_task(monitor.process_event(event))
    await asyncio.wait_for(started.wait(), 5)
    stopping = asyncio.create_task(monitor.stop())
    try:
        await asyncio.sleep(0)
        assert not stopping.done()
    finally:
        release.set()
        await asyncio.gather(writing, stopping)
    assert await repository.get_event(event.id) is not None
    await repository.save_probe_health(ProbeHealth(probe_id="logs", interval_seconds=1))


async def test_cancellation_joins_health_write_before_shutdown(repository, monkeypatch):
    monitor = MonitorService(repository, Detector())
    started = asyncio.Event()
    release = asyncio.Event()
    original = repository.save_probe_health

    async def gated_write(health):
        started.set()
        await release.wait()
        await original(health)

    monkeypatch.setattr(repository, "save_probe_health", gated_write)
    health = ProbeHealth(probe_id="logs", interval_seconds=1, state="healthy")
    monitor._health["logs"] = health
    writing = asyncio.create_task(monitor._persist_health("logs"))
    try:
        await asyncio.wait_for(started.wait(), 5)
        writing.cancel()
        await asyncio.sleep(0)
        assert not writing.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await writing
    assert (await repository.list_probe_health(["logs"]))[0].state == "healthy"
    await repository.save_probe_health(health.model_copy(update={"state": "degraded"}))
