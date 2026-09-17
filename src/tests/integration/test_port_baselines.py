"""Committed network baselines survive restarts without inventing changes."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from socketclaw.cli import _build_monitor, _ProbePlanner
from socketclaw.collection import PortBaselineState, ProbeBatch
from socketclaw.config import AppConfig
from socketclaw.detection import Detector
from socketclaw.domain import EventSource, SecurityEvent, utc_now
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.probes.ports import PortProbe, port_probe_id
from socketclaw.storage import EventQuery, Repository


@pytest.fixture
async def repository(tmp_path: Path):
    repo = Repository(tmp_path / "socketclaw.db")
    await repo.initialize()
    try:
        yield repo
    finally:
        await repo.close()


async def test_restart_compares_only_confirmed_common_scope(repository: Repository) -> None:
    states: dict[int, bool | None] = {22: True, 80: False}

    async def connect(_target: str, port: int, _timeout: float) -> bool | None:
        return states[port]

    probe = PortProbe(connector=connect)
    batch = await probe.collect_batch("server", [22, 80], repository)
    assert not probe._previous  # Candidates never advance the live baseline.
    await repository.ingest_batch(batch, Detector())
    states.update({22: None, 80: True, 443: True})
    restarted = PortProbe(connector=connect)
    batch = await restarted.collect_batch("server", [22, 80, 443], repository)
    event = (await repository.ingest_batch(batch, Detector()))[0]
    assert event.evidence["baseline"] is False
    assert event.evidence["newly_opened"] == [80]
    assert event.evidence["newly_closed"] == []
    assert event.evidence["scope_added"] == [443]
    assert event.evidence["open_ports"] == [80, 443]
    assert event.evidence["last_known_open_ports"] == [22, 80, 443]
    removed = await restarted.collect_batch("server", [443], repository)
    assert removed.observations[0].evidence["scope_removed"] == [22, 80]
    assert removed.observations[0].evidence["newly_closed"] == []


async def test_failed_scan_commit_preserves_baseline_and_replays_once(
    repository: Repository,
) -> None:
    opened = False

    async def connect(_target: str, _port: int, _timeout: float) -> bool:
        return opened

    probe = PortProbe(connector=connect)
    await repository.ingest_batch(await probe.collect_batch("server", [22], repository), Detector())
    before = await repository.load_checkpoint(port_probe_id("server"))
    opened = True
    batch = await probe.collect_batch("server", [22], repository)
    async with repository._engine.begin() as connection:
        await connection.execute(
            text(
                "CREATE TRIGGER fail_baseline BEFORE UPDATE ON probe_checkpoints "
                "BEGIN SELECT RAISE(ABORT, 'injected baseline failure'); END"
            )
        )
    with pytest.raises(IntegrityError, match="injected baseline failure"):
        await repository.ingest_batch(batch, Detector())
    assert await repository.load_checkpoint(port_probe_id("server")) == before
    assert len(await repository.list_events()) == 1
    async with repository._engine.begin() as connection:
        await connection.execute(text("DROP TRIGGER fail_baseline"))
    event = (await repository.ingest_batch(batch, Detector()))[0]
    assert event.evidence["newly_opened"] == [22]
    assert event.ingest_seq == 2
    assert await repository.ingest_batch(batch, Detector()) == []


async def test_unknown_results_do_not_refresh_expired_confirmation(repository: Repository) -> None:
    checkpoint = await repository.load_checkpoint(port_probe_id("server"))
    old = utc_now() - timedelta(days=2)
    state = PortBaselineState(scope=(22, 80), opened=(22,), confirmed_at={22: old, 80: old})
    await repository.ingest_batch(
        ProbeBatch(
            checkpoints=(checkpoint.model_copy(update={"state": state.model_dump(mode="json")}),)
        ),
        Detector(),
    )
    results: dict[int, bool | None] = {22: None, 80: True}

    async def connect(_target: str, port: int, _timeout: float) -> bool | None:
        return results[port]

    probe = PortProbe(connector=connect)
    first = (
        await repository.ingest_batch(
            await probe.collect_batch("server", [22, 80], repository), Detector()
        )
    )[0]
    assert first.evidence["baseline_stale"] is True
    assert first.evidence["newly_opened"] == []
    assert first.evidence["initial_open_ports"] == [80]
    restored = PortBaselineState.model_validate(
        (await repository.load_checkpoint(port_probe_id("server"))).state
    )
    assert restored.confirmed_at[22] == old
    assert restored.confirmed_at[80] > old
    results[22] = False
    second = await probe.collect_batch("server", [22, 80], repository)
    assert second.observations[0].evidence["baseline_stale_ports"] == [22]
    assert second.observations[0].evidence["newly_closed"] == []


async def test_corrupt_baseline_is_rejected_before_network_scan(repository: Repository) -> None:
    calls = 0

    async def connect(_target: str, _port: int, _timeout: float) -> bool:
        nonlocal calls
        calls += 1
        return True

    checkpoint = await repository.load_checkpoint(port_probe_id("server"))
    await repository.ingest_batch(
        ProbeBatch(
            checkpoints=(
                checkpoint.model_copy(
                    update={"state": {"scope": [22], "opened": [80], "confirmed_at": {}}}
                ),
            )
        ),
        Detector(),
    )
    with pytest.raises(ValueError, match="confirmed watch scope"):
        await PortProbe(connector=connect).collect_batch("server", [22], repository)
    assert calls == 0


async def test_production_scheduled_and_manual_scans_share_committed_baseline(
    repository: Repository,
) -> None:
    opened = False

    async def connect(_target: str, _port: int, _timeout: float) -> bool:
        return opened

    planner = _ProbePlanner(which=lambda _: None, repository=repository)
    monitor = _build_monitor(AppConfig(targets=["server"], ports=[22]), repository, planner=planner)
    assert planner._committed is not None
    planner._committed.port_probe.connector = connect
    batch = await monitor.jobs[0].collect()
    assert isinstance(batch, ProbeBatch)
    await monitor.process_batch(batch)
    opened = True
    diagnostic = await monitor.run_diagnostic("ports", "server")
    assert diagnostic.evidence["newly_opened"] == [22]
    following = await monitor.jobs[0].collect()
    assert isinstance(following, ProbeBatch)
    assert following.observations[0].evidence["newly_opened"] == []


async def test_network_write_failure_retries_measurement_without_recollecting(
    repository: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    retried = asyncio.Event()
    original = repository.ingest_batch
    retained_id = None

    async def collect():
        nonlocal calls
        calls += 1
        return (
            SecurityEvent(
                source=EventSource.PING,
                event_type="ping.result",
                title="Measured",
                summary="Measured",
            ),
        )

    async def fail_once(batch: ProbeBatch, detector: Detector):
        nonlocal retained_id
        if retained_id is None:
            retained_id = batch.batch_id
            raise OSError("storage unavailable")
        assert batch.batch_id == retained_id
        result = await original(batch, detector)
        retried.set()
        return result

    monkeypatch.setattr(repository, "ingest_batch", fail_once)
    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("ping:server", 0.01, collect)])
    try:
        await monitor.start()
        await asyncio.wait_for(retried.wait(), 2)
        monitor.pause()
        assert calls == 1
        assert len(await repository.list_events(EventQuery(source=EventSource.PING))) == 1
    finally:
        await monitor.stop()
