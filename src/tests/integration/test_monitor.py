from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.storage import Repository


def ping_event(target: str = "1.1.1.1") -> SecurityEvent:
    return SecurityEvent(
        source="ping",
        event_type="ping.result",
        title=f"{target} is unreachable",
        summary="The ping probe received no replies.",
        target=target,
        evidence={"packet_loss": 100.0},
        outcome="unreachable",
    )


@pytest.fixture
async def repository(tmp_path: Path):
    repo = Repository(tmp_path / "socketclaw.db")
    await repo.initialize()
    yield repo
    await repo.close()


async def take(stream: AsyncIterator[SecurityEvent], count: int) -> list[SecurityEvent]:
    return [await asyncio.wait_for(anext(stream), timeout=1.0) for _ in range(count)]


@pytest.mark.asyncio
async def test_probe_failure_becomes_system_event_and_other_jobs_continue(
    repository: Repository,
) -> None:
    async def fail() -> list[SecurityEvent]:
        raise RuntimeError("synthetic probe failure")

    async def succeed() -> list[SecurityEvent]:
        return [ping_event()]

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[
            ProbeJob("broken", 60.0, fail),
            ProbeJob("ping", 60.0, succeed),
        ],
    )
    stream = monitor.events()
    collecting = asyncio.create_task(take(stream, 2))
    await asyncio.sleep(0)

    await monitor.start()
    events = await collecting
    await monitor.stop()
    await stream.aclose()

    assert {event.event_type for event in events} == {
        "system.probe_error",
        "ping.result",
    }
    error = next(event for event in events if event.event_type == "system.probe_error")
    assert error.evidence == {
        "probe": "broken",
        "error": "synthetic probe failure",
    }
    stored = await repository.list_events()
    assert len(stored) == 2
    assert next(item for item in stored if item.event_type == "ping.result").score == 70


@pytest.mark.asyncio
async def test_pause_resume_and_idempotent_stop(repository: Repository) -> None:
    calls = 0

    async def collect() -> list[SecurityEvent]:
        nonlocal calls
        calls += 1
        return [ping_event()]

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[ProbeJob("ping", 0.05, collect)],
    )
    stream = monitor.events()
    first = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await monitor.start()
    await asyncio.wait_for(first, timeout=1.0)

    monitor.pause()
    paused_calls = calls
    await asyncio.sleep(0.12)
    assert calls == paused_calls
    assert monitor.status.paused is True

    next_event = asyncio.create_task(anext(stream))
    monitor.resume()
    await asyncio.wait_for(next_event, timeout=1.0)
    assert calls > paused_calls
    assert monitor.status.paused is False

    await monitor.stop()
    await monitor.stop()
    await stream.aclose()
    assert monitor.status.running is False


@pytest.mark.asyncio
async def test_manual_diagnostic_uses_named_handler_and_persists(
    repository: Repository,
) -> None:
    seen: list[str] = []

    async def ping(target: str) -> SecurityEvent:
        seen.append(target)
        return ping_event(target)

    monitor = MonitorService(
        repository,
        Detector(),
        diagnostics={"ping": ping},
    )
    stream = monitor.events()
    waiting = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)

    result = await monitor.run_diagnostic("ping", "8.8.8.8")
    published = await asyncio.wait_for(waiting, timeout=1.0)
    await stream.aclose()

    assert seen == ["8.8.8.8"]
    assert result.target == "8.8.8.8"
    assert published.id == result.id
    assert (await repository.list_events())[0].target == "8.8.8.8"


@pytest.mark.asyncio
async def test_unknown_manual_diagnostic_is_rejected(
    repository: Repository,
) -> None:
    monitor = MonitorService(repository, Detector())

    with pytest.raises(ValueError, match="Unknown diagnostic"):
        await monitor.run_diagnostic("who-knows", "1.1.1.1")


def test_monitor_rejects_non_integer_subscriber_queue_size(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "unused.db")
    with pytest.raises(ValueError, match="subscriber queue size"):
        MonitorService(
            repository,
            Detector(),
            subscriber_queue_size=1.5,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_slow_subscriber_keeps_newest_events_without_blocking_monitor(
    repository: Repository,
) -> None:
    monitor = MonitorService(
        repository,
        Detector(),
        subscriber_queue_size=2,
    )
    stream = monitor.events()
    first_waiter = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    first = await monitor.process_event(ping_event("1.1.1.1"))
    assert (await first_waiter).id == first.id

    second = await monitor.process_event(ping_event("2.2.2.2"))
    await monitor.process_event(ping_event("3.3.3.3"))
    fourth = await monitor.process_event(ping_event("4.4.4.4"))

    queued = [await anext(stream), await anext(stream)]
    assert monitor.status.dropped_notifications == 1
    await stream.aclose()
    assert [item.target for item in queued] == ["3.3.3.3", "4.4.4.4"]
    assert second.target not in {item.target for item in queued}
    assert fourth.id == queued[-1].id


@pytest.mark.asyncio
async def test_stop_cancels_an_in_flight_collector(repository: Repository) -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def collect() -> list[SecurityEvent]:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        return []

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[ProbeJob("blocked", 60.0, collect)],
    )
    await monitor.start()
    await asyncio.wait_for(started.wait(), timeout=1.0)

    await asyncio.wait_for(monitor.stop(), timeout=1.0)

    assert cancelled.is_set()
    assert monitor.status.running is False


@pytest.mark.asyncio
async def test_reconfigure_restarts_jobs_preserving_pause_and_subscribers(
    repository: Repository,
) -> None:
    old_started = asyncio.Event()
    old_cancelled = asyncio.Event()
    new_called = asyncio.Event()

    async def old_collect() -> list[SecurityEvent]:
        old_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            old_cancelled.set()
        return []

    async def new_collect() -> list[SecurityEvent]:
        new_called.set()
        return [ping_event("8.8.4.4")]

    async def diagnostic(target: str) -> SecurityEvent:
        return ping_event(target)

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[ProbeJob("old", 60.0, old_collect)],
    )
    stream = monitor.events()
    subscriber = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await monitor.start()
    await asyncio.wait_for(old_started.wait(), timeout=1.0)
    monitor.pause()

    await monitor.reconfigure(
        jobs=[ProbeJob("new", 60.0, new_collect)],
        diagnostics={"ping": diagnostic},
    )

    assert old_cancelled.is_set()
    assert monitor.status.running is True
    assert monitor.status.paused is True
    assert monitor.status.active_jobs == 1
    await asyncio.sleep(0)
    assert not new_called.is_set()

    monitor.resume()
    published = await asyncio.wait_for(subscriber, timeout=1.0)
    diagnosed = await monitor.run_diagnostic("ping", "9.9.9.9")
    await monitor.stop()
    await stream.aclose()

    assert published.target == "8.8.4.4"
    assert diagnosed.target == "9.9.9.9"


@pytest.mark.asyncio
async def test_cancelled_reconfigure_restores_the_previous_running_plan(
    repository: Repository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()
    restarted = asyncio.Event()
    cancel_finished = asyncio.Event()
    hold_reconfigure = asyncio.Event()
    starts = 0

    async def old_collect() -> list[SecurityEvent]:
        nonlocal starts
        starts += 1
        if starts == 1:
            first_started.set()
        else:
            restarted.set()
        try:
            await asyncio.Event().wait()
        finally:
            first_cancelled.set()
        return []

    old_job = ProbeJob("old", 60.0, old_collect)
    monitor = MonitorService(repository, Detector(), jobs=[old_job])
    await monitor.start()
    await asyncio.wait_for(first_started.wait(), timeout=1.0)

    original_cancel_runner = monitor._cancel_runner

    async def controlled_cancel_runner() -> None:
        await original_cancel_runner()
        cancel_finished.set()
        await hold_reconfigure.wait()

    monkeypatch.setattr(monitor, "_cancel_runner", controlled_cancel_runner)

    task = asyncio.create_task(monitor.reconfigure(jobs=[], diagnostics={}))
    await asyncio.wait_for(cancel_finished.wait(), timeout=1.0)
    assert first_cancelled.is_set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.wait_for(restarted.wait(), timeout=1.0)
    assert monitor.jobs == (old_job,)
    assert monitor.status.running is True
    assert monitor.status.active_jobs == 1
    monkeypatch.setattr(monitor, "_cancel_runner", original_cancel_runner)
    await monitor.stop()


@pytest.mark.asyncio
async def test_concurrent_processing_preserves_burst_history(
    repository: Repository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_save = repository.ingest_batch
    first_save_started = asyncio.Event()
    release_first_save = asyncio.Event()
    save_calls = 0

    async def delayed_save(*args: object, **kwargs: object):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 1:
            first_save_started.set()
            await release_first_save.wait()
        return await original_save(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(repository, "ingest_batch", delayed_save)
    monitor = MonitorService(repository, Detector())
    tasks = [asyncio.create_task(monitor.process_event(ping_event("4.4.4.4"))) for _ in range(4)]
    await asyncio.wait_for(first_save_started.wait(), timeout=1.0)
    await asyncio.sleep(0)
    release_first_save.set()

    events = await asyncio.gather(*tasks)

    assert [event.score for event in events] == [70, 70, 70, 95]


@pytest.mark.asyncio
async def test_start_hydrates_recent_history_for_bursts_across_restart(
    repository: Repository,
) -> None:
    first = MonitorService(repository, Detector())
    for _ in range(3):
        await first.process_event(ping_event("4.4.4.4"))

    restarted = MonitorService(repository, Detector())
    await restarted.start()
    event = await restarted.process_event(ping_event("4.4.4.4"))
    await restarted.stop()

    assert event.score == 95
    assert any(signal.code == "ping.sustained_loss" for signal in event.signals)


@pytest.mark.asyncio
async def test_unexpected_runner_failure_updates_status_and_stop_is_safe(
    repository: Repository,
) -> None:
    async def collect() -> list[SecurityEvent]:
        return []

    class BrokenMonitor(MonitorService):
        async def _run_job(self, job: ProbeJob) -> None:
            raise RuntimeError(f"unexpected failure in {job.name}")

    monitor = BrokenMonitor(
        repository,
        Detector(),
        jobs=[ProbeJob("broken", 60.0, collect)],
    )
    await monitor.start()
    for _ in range(10):
        if not monitor.status.running:
            break
        await asyncio.sleep(0)

    assert monitor.status.running is False
    assert monitor.status.active_jobs == 0
    assert "unexpected failure" in str(monitor.status.last_error)
    await monitor.stop()


@pytest.mark.asyncio
async def test_probe_warning_clears_after_that_job_recovers(
    repository: Repository,
) -> None:
    attempts = 0
    recovered = asyncio.Event()

    async def flaky() -> list[SecurityEvent]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary probe outage")
        recovered.set()
        return []

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[ProbeJob("flaky", 0.01, flaky)],
    )
    await monitor.start()
    await asyncio.wait_for(recovered.wait(), timeout=1.0)
    await asyncio.sleep(0)

    assert monitor.status.running is True
    assert monitor.status.last_error is None
    await monitor.stop()


@pytest.mark.asyncio
async def test_healthy_job_does_not_clear_another_jobs_warning(
    repository: Repository,
) -> None:
    broken_called = asyncio.Event()
    healthy_called = asyncio.Event()

    async def broken() -> list[SecurityEvent]:
        broken_called.set()
        raise RuntimeError("broken probe")

    async def healthy() -> list[SecurityEvent]:
        healthy_called.set()
        return []

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=[
            ProbeJob("broken", 60.0, broken),
            ProbeJob("healthy", 60.0, healthy),
        ],
    )
    await monitor.start()
    await asyncio.wait_for(broken_called.wait(), timeout=1.0)
    await asyncio.wait_for(healthy_called.wait(), timeout=1.0)
    await asyncio.sleep(0)

    assert monitor.status.last_error == "broken probe"
    await monitor.stop()


@pytest.mark.parametrize("kind", ["ping", "auth", "auth-path"])
@pytest.mark.parametrize("restart", [False, True])
async def test_correlation_survives_ten_thousand_unrelated_observations(
    repository: Repository, restart: bool, kind: str
) -> None:
    from uuid import uuid4

    from sqlalchemy import insert, select, update

    from socketclaw.storage import EventRow, SchemaMetaRow

    monitor = MonitorService(repository, Detector())

    def observation() -> SecurityEvent:
        if kind == "ping":
            return ping_event("important.example")
        return SecurityEvent(
            source="log",
            event_type="log.auth_failure",
            title="Authentication failure",
            summary="Failed password",
            target="important.example" if kind == "auth" else None,
            evidence={"message": "Failed password", "path": "/var/log/auth.log"},
        )

    for _ in range(3 if kind == "ping" else 5):
        await monitor.process_event(observation())
    seed = await monitor.process_event(ping_event("unrelated.example"))
    # Populate real durable history without paying 10,000 separate commits in a fixture.
    async with repository._engine.begin() as connection:
        row = (
            (
                await connection.execute(
                    select(EventRow.__table__).where(EventRow.id == str(seed.id))
                )
            )
            .mappings()
            .one()
        )
        await connection.execute(
            insert(EventRow),
            [
                dict(row, id=str(uuid4()), ingest_seq=row["ingest_seq"] + index)
                for index in range(1, 10_001)
            ],
        )
        await connection.execute(
            update(SchemaMetaRow)
            .where(SchemaMetaRow.key == "ingest_sequence")
            .values(value=str(row["ingest_seq"] + 10_000))
        )
    if restart:
        monitor = MonitorService(repository, Detector())
        await monitor.start()
    else:
        # Exercise live cache eviction as well as durable restart recovery.
        for index in range(501):
            await monitor.process_event(ping_event(f"live-{index}.example"))
    try:
        event = await monitor.process_event(observation())
        assert event.score == (95 if kind == "ping" else 100)
        assert ("ping.sustained_loss" if kind == "ping" else "log.auth_burst") in {
            signal.code for signal in event.signals
        }
    finally:
        await monitor.stop()
