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
    await stream.aclose()
    assert [item.target for item in queued] == ["3.3.3.3", "4.4.4.4"]
    assert second.target not in {item.target for item in queued}
    assert fourth.id == queued[-1].id
