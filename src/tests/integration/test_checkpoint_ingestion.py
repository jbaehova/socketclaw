"""Fault-injected log transactions and durable restart/replay semantics."""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from socketclaw.cli import _build_monitor
from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig
from socketclaw.detection import Detector
from socketclaw.domain import EventSource
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.probes.logs import LogProbe, _probe_id, preview_log
from socketclaw.storage import EventQuery, Repository


@pytest.fixture
async def repository(tmp_path: Path):
    repo = Repository(tmp_path / "home" / "socketclaw.db")
    await repo.initialize()
    try:
        yield repo
    finally:
        await repo.close()


async def candidate(probe: LogProbe) -> ProbeBatch:
    result = await probe.collect()
    assert isinstance(result, ProbeBatch)
    return result


def append(path: Path, value: str) -> None:
    with path.open("a") as stream:
        stream.write(value)


async def attached(repository: Repository, path: Path) -> LogProbe:
    path.write_text("historic failed password skipped on first attachment\n")
    probe = LogProbe([path], repository=repository)
    first = await candidate(probe)
    assert first.observations == ()
    assert first.checkpoints[0].expected_revision == 0
    assert probe._cursors == {}
    await repository.ingest_batch(first, Detector())
    return probe


async def test_restart_resumes_committed_cursor_and_nonmatches_advance_it(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    await attached(repository, path)
    append(path, "ordinary line\n")
    probe = LogProbe([path], repository=repository)
    nonmatches = await candidate(probe)
    assert not nonmatches.observations
    await repository.ingest_batch(nonmatches, Detector())
    before = await repository.load_checkpoint(_probe_id(path))
    assert before.state["offset"] == path.stat().st_size
    append(path, "Failed password for root from 10.0.0.8\n")
    restarted = LogProbe([path], repository=repository)
    events = await repository.ingest_batch(await candidate(restarted), Detector())
    assert len(events) == 2
    assert events[0].event_type == "log.context"
    assert events[0].evidence["context_for"] == str(events[1].id)
    assert events[1].evidence["actor_ip"] == "10.0.0.8"
    assert events[1].target.startswith("log:")
    assert events[0].source_key is not None
    assert events[1].evidence["byte_start"] == before.state["offset"]
    assert (await candidate(LogProbe([path], repository=repository))).observations == ()


async def test_mid_batch_failure_rolls_back_events_counter_and_checkpoint(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    before = await repository.load_checkpoint(_probe_id(path))
    append(path, "Failed password first\nFailed password second\n")
    batch = await candidate(probe)
    async with repository._engine.begin() as connection:
        await connection.execute(
            text(
                "CREATE TRIGGER fail_second BEFORE INSERT ON events "
                "WHEN NEW.summary LIKE '%second%' BEGIN "
                "SELECT RAISE(ABORT, 'injected write failure'); END"
            )
        )
    with pytest.raises(IntegrityError, match="injected write failure"):
        await repository.ingest_batch(batch, Detector())
    assert await repository.list_events() == []
    assert await repository.load_checkpoint(_probe_id(path)) == before
    async with repository._engine.begin() as connection:
        await connection.execute(text("DROP TRIGGER fail_second"))
    stored = await repository.ingest_batch(batch, Detector())
    assert [item.ingest_seq for item in stored] == [1, 2]
    assert (await repository.load_checkpoint(_probe_id(path))).state[
        "offset"
    ] == path.stat().st_size
    assert await repository.ingest_batch(batch, Detector()) == []
    assert len(await repository.list_events()) == 2


async def test_source_keys_deduplicate_replayed_observations_across_batch_ids(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password for root from 10.0.0.8\n" * 6)
    batch = await candidate(probe)
    stored = await repository.ingest_batch(batch, Detector())
    assert len(stored) == 6
    assert stored[-1].score == 100  # Same-batch observations contribute to correlation.
    replay = batch.model_copy(update={"batch_id": uuid4(), "checkpoints": ()})
    assert await repository.ingest_batch(replay, Detector()) == []
    assert len(await repository.list_events()) == 6


async def test_stale_checkpoint_and_reused_batch_id_fail_without_partial_changes(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password\n")
    batch = await candidate(probe)
    stale = batch.model_copy(update={"batch_id": uuid4()})
    await repository.ingest_batch(batch, Detector())
    checkpoint = await repository.load_checkpoint(_probe_id(path))
    with pytest.raises(ValueError, match="checkpoint changed"):
        await repository.ingest_batch(stale, Detector())
    changed = batch.model_copy(update={"observations": ()})
    with pytest.raises(ValueError, match="reused with different content"):
        await repository.ingest_batch(changed, Detector())
    assert await repository.load_checkpoint(_probe_id(path)) == checkpoint
    assert len(await repository.list_events()) == 1


@pytest.mark.parametrize("rotation", ["rename", "truncate", "recreate"])
async def test_rotation_generations_do_not_deduplicate_distinct_lines(
    repository: Repository, tmp_path: Path, rotation: str
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password\n")
    first = await repository.ingest_batch(await candidate(probe), Detector())
    if rotation == "rename":
        path.rename(path.with_suffix(".log.1"))
    elif rotation == "recreate":
        path.unlink()
        await repository.ingest_batch(await candidate(probe), Detector())
    path.write_text("Failed password\n")
    second = await repository.ingest_batch(
        await candidate(LogProbe([path], repository=repository)), Detector()
    )
    assert len(first) == len(second) == 1
    assert first[0].source_key != second[0].source_key
    assert second[0].evidence["rotated"] is True


async def test_partial_line_survives_restart_without_advancing_checkpoint(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    before = await repository.load_checkpoint(_probe_id(path))
    append(path, "Failed password for")
    partial = await candidate(probe)
    await repository.ingest_batch(partial, Detector())
    assert (await repository.load_checkpoint(_probe_id(path))).state["offset"] == before.state[
        "offset"
    ]
    append(path, " root from 10.0.0.8\n")
    restarted = LogProbe([path], repository=repository)
    stored = await repository.ingest_batch(await candidate(restarted), Detector())
    assert len(stored) == 1
    assert stored[0].summary == "Failed password for root from 10.0.0.8"


async def test_monitor_retries_the_same_candidate_after_lost_commit_acknowledgment(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password\n")
    collected: list[ProbeBatch] = []
    committed = asyncio.Event()
    retried = asyncio.Event()
    original = repository.ingest_batch
    failed_id = None

    async def collect() -> ProbeBatch:
        batch = await candidate(probe)
        collected.append(batch)
        return batch

    async def lost_ack(batch: ProbeBatch, detector: Detector):
        nonlocal failed_id
        result = await original(batch, detector)
        if failed_id is None:
            failed_id = batch.batch_id
            committed.set()
            raise OSError("lost commit acknowledgment")
        if batch.batch_id == failed_id:
            retried.set()
        return result

    monkeypatch.setattr(repository, "ingest_batch", lost_ack)
    monitor = MonitorService(repository, Detector(), jobs=[ProbeJob("logs", 0.01, collect)])
    try:
        await monitor.start()
        await asyncio.wait_for(committed.wait(), 2)
        await asyncio.wait_for(retried.wait(), 2)
        assert collected[0].batch_id == failed_id
        assert len(await repository.list_events(EventQuery(source=EventSource.LOG))) == 1
    finally:
        await monitor.stop()


async def test_production_composition_uses_transactional_log_collector(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    config = AppConfig(log_paths=[str(path)])
    monitor = _build_monitor(config, repository)
    log_job = next(job for job in monitor.jobs if job.name == "logs")
    batch = await log_job.collect()
    assert isinstance(batch, ProbeBatch)
    await monitor.process_batch(batch)
    append(path, "Failed password\n")
    restarted = _build_monitor(config, repository)
    log_job = next(job for job in restarted.jobs if job.name == "logs")
    resumed = await log_job.collect()
    assert isinstance(resumed, ProbeBatch)
    assert len(resumed.observations) == 1


async def test_cancel_before_commit_keeps_cursor_and_does_not_publish(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    before = await repository.load_checkpoint(_probe_id(path))
    append(path, "Failed password\n")
    batch = await candidate(probe)
    monitor = MonitorService(repository, Detector())
    started = asyncio.Event()
    release = asyncio.Event()
    original = AsyncSession.commit

    async def delayed_commit(session: AsyncSession) -> None:
        started.set()
        await release.wait()
        await original(session)

    monkeypatch.setattr(AsyncSession, "commit", delayed_commit)
    stream = monitor.events()
    notification = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    processing = asyncio.create_task(monitor.process_batch(batch))
    try:
        await asyncio.wait_for(started.wait(), 2)
        assert not notification.done()
        assert await repository.list_events() == []
        assert await repository.load_checkpoint(_probe_id(path)) == before
        processing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await processing
        assert not notification.done()
        assert await repository.list_events() == []
        assert await repository.load_checkpoint(_probe_id(path)) == before
        monkeypatch.setattr(AsyncSession, "commit", original)
        result = await monitor.process_batch(batch)
        published = await asyncio.wait_for(notification, 2)
        assert published.id == result[0].id
    finally:
        release.set()
        notification.cancel()
        await stream.aclose()


async def test_checkpoints_store_fingerprints_without_unmatched_raw_log_content(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    secret = "password=unmatched-private-content"
    path.write_text(secret + "\n")
    probe = LogProbe([path], repository=repository)
    await repository.ingest_batch(await candidate(probe), Detector())
    checkpoint = await repository.load_checkpoint(_probe_id(path))
    assert len(str(checkpoint.state["head_hash"])) == 64
    assert len(str(checkpoint.state["tail_hash"])) == 64
    serialized = checkpoint.model_dump_json()
    assert secret not in serialized
    assert secret.encode().hex() not in serialized


async def test_renamed_log_drains_old_generation_before_reading_replacement(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from socketclaw.probes import logs

    monkeypatch.setattr(logs, "_MAX_POLL_LINES", 2)
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password old\n" * 5)
    path.rename(path.with_suffix(".log.1"))
    path.write_text("Failed password replacement\n")
    first = await repository.ingest_batch(await candidate(probe), Detector())
    checkpoint = await repository.load_checkpoint(_probe_id(path))
    assert len(first) == 2
    assert checkpoint.state["backlog_bytes"] > 0
    assert checkpoint.state["sampled_size"] > checkpoint.state["offset"]
    # A different collector process can continue draining the old file.
    restarted = LogProbe([path], repository=repository)
    for _ in range(3):
        await repository.ingest_batch(await candidate(restarted), Detector())
    events = await repository.list_events()
    assert len(events) == 6
    assert len({item.source_key for item in events}) == 6
    assert sum(item.summary == "Failed password old" for item in events) == 5
    assert await repository.list_ingest_gaps(_probe_id(path)) == []
    checkpoint = await repository.load_checkpoint(_probe_id(path))
    assert checkpoint.state["backlog_bytes"] == 0


async def test_deleted_generation_records_gap_with_checkpoint_atomically(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    original = await repository.load_checkpoint(_probe_id(path))
    append(path, "Failed password lost\n")
    path.unlink()
    path.write_text("Failed password replacement\n")
    batch = await candidate(probe)
    assert len(batch.gaps) == 1
    assert batch.gaps[0].from_offset == original.state["offset"]
    assert batch.gaps[0].reason == "rotated_source_unavailable"
    async with repository._engine.begin() as connection:
        await connection.execute(
            text(
                "CREATE TRIGGER fail_gap BEFORE INSERT ON ingest_gaps "
                "BEGIN SELECT RAISE(ABORT, 'injected gap failure'); END"
            )
        )
    with pytest.raises(IntegrityError, match="injected gap failure"):
        await repository.ingest_batch(batch, Detector())
    assert await repository.load_checkpoint(_probe_id(path)) == original
    assert await repository.list_events() == []
    async with repository._engine.begin() as connection:
        await connection.execute(text("DROP TRIGGER fail_gap"))
    await repository.ingest_batch(batch, Detector())
    await repository.ingest_batch(batch, Detector())
    assert len(await repository.list_ingest_gaps(_probe_id(path))) == 1
    assert (await repository.load_checkpoint(_probe_id(path))).state["gap_count"] == 1


async def test_incomplete_retired_line_does_not_block_new_file(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    append(path, "Failed password incomplete")
    path.rename(path.with_suffix(".log.1"))
    path.write_text("Failed password replacement\n")
    batch = await candidate(probe)
    assert len(batch.gaps) == 1
    assert batch.gaps[0].reason == "incomplete_rotated_line"
    stored = await repository.ingest_batch(batch, Detector())
    assert [item.summary for item in stored] == ["Failed password replacement"]


async def test_missing_source_is_visible_without_repeated_gap_records(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "missing.log"
    probe = LogProbe([path], repository=repository)
    await repository.ingest_batch(await candidate(probe), Detector())
    assert (await repository.load_checkpoint(_probe_id(path))).state["missing"] is True
    assert await repository.list_ingest_gaps(_probe_id(path)) == []
    assert (await candidate(probe)).checkpoints == ()


async def test_log_errors_share_the_batch_bound_with_matching_lines(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from socketclaw.probes import logs

    path = tmp_path / "auth.log"
    await attached(repository, path)
    append(path, "Failed password\n" * 1000)
    denied = tmp_path / "denied.log"
    original = logs.os.open

    def open_file(selected, *args, **kwargs):
        if Path(selected) == denied:
            raise PermissionError("synthetic permission failure")
        return original(selected, *args, **kwargs)

    monkeypatch.setattr(logs.os, "open", open_file)
    batch = await candidate(LogProbe([denied, path], repository=repository))
    assert len(batch.observations) == 1000
    assert sum(item.event_type == "log.auth_failure" for item in batch.observations) == 999
    progress = next(item for item in batch.checkpoints if item.probe_id == _probe_id(path))
    assert progress.state["backlog_bytes"] == len("Failed password\n")


async def test_preview_is_bounded_and_never_commits_cursor_or_observations(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    await attached(repository, path)
    before = await repository.load_checkpoint(_probe_id(path))
    append(path, "Failed password for root from 192.0.2.1\n" * 3000)
    preview = await preview_log(path)
    assert preview.bytes_read <= 65536
    assert len(preview.matches) == 20
    assert preview.limited
    assert await repository.load_checkpoint(_probe_id(path)) == before
    assert await repository.list_events() == []


async def test_parser_upgrade_resumes_legacy_checkpoint_without_rewriting_history(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "auth.log"
    probe = await attached(repository, path)
    before = await repository.load_checkpoint(_probe_id(path))
    legacy = before.model_copy(update={"state": {**before.state, "parser_version": 1}})
    await repository.ingest_batch(ProbeBatch(checkpoints=(legacy,)), Detector())
    append(path, "2020-01-01T00:00:00Z 10.0.0.2 sshd[1]: Failed password for root from 192.0.2.1\n")
    batch = await candidate(probe)
    assert len(batch.observations) == 1
    assert batch.observations[0].evidence["byte_start"] == before.state["offset"]
    assert batch.observations[0].evidence["parser_version"] == 3
    stored = (await repository.ingest_batch(batch, Detector()))[0]
    assert stored.source_at is not None and stored.source_at.year == 2020
    assert stored.ingested_at is not None and stored.ingested_at > stored.source_at
    assert stored.target == "10.0.0.2"
    assert stored.evidence["actor_ip"] == "192.0.2.1"
    assert (await repository.load_checkpoint(_probe_id(path))).state["parser_version"] == 3


async def test_context_is_bounded_durable_atomic_and_not_reemitted(repository, tmp_path):
    path = tmp_path / "auth.log"
    await attached(repository, path)
    append(path, "".join(f"normal before {i}\n" for i in range(5)))
    prepared = await candidate(LogProbe([path], repository=repository))
    assert not prepared.observations
    await repository.ingest_batch(prepared, Detector())
    checkpoint = await repository.load_checkpoint(_probe_id(path))
    assert len(checkpoint.state["context_before"]) == 3
    append(path, "Failed password for alice from 192.0.2.9\n")
    batch = await candidate(LogProbe([path], repository=repository))
    assert [item.event_type for item in batch.observations] == ["log.context"] * 3 + [
        "log.auth_failure"
    ]
    assert [item.evidence["message"] for item in batch.observations[:3]] == [
        f"normal before {i}" for i in (2, 3, 4)
    ]
    assert all(
        item.evidence["context_for"] == str(batch.observations[-1].id)
        for item in batch.observations[:3]
    )
    invalid = batch.checkpoints[0].model_copy(
        update={"state": {**batch.checkpoints[0].state, "oversized": "x" * 70000}}
    )
    with pytest.raises(ValueError, match="64 KiB"):
        await repository.ingest_batch(
            batch.model_copy(update={"checkpoints": (invalid,)}), Detector()
        )
    assert (await repository.load_checkpoint(_probe_id(path))).state["offset"] == checkpoint.state[
        "offset"
    ]
    await repository.ingest_batch(batch, Detector())
    assert await repository.ingest_batch(batch, Detector()) == []
    append(path, "".join(f"normal after {i}\n" for i in range(5)))
    after = await candidate(LogProbe([path], repository=repository))
    assert len(after.observations) == 3
    assert all(
        item.evidence["context_for"] == str(batch.observations[-1].id)
        for item in after.observations
    )
    await repository.ingest_batch(after, Detector())
    assert not (await candidate(LogProbe([path], repository=repository))).observations
    assert len({item.source_key for item in (*batch.observations, *after.observations)}) == 7


async def test_unsupported_coverage_is_distinct_from_read_failure_and_persists_when_idle(
    repository, tmp_path
):
    path = tmp_path / "auth.log"
    await attached(repository, path)
    append(path, "an unsupported application record\n")
    batch = await candidate(LogProbe([path], repository=repository))
    assert batch.health[0].error_kind == "unsupported_format"
    assert "Read 1 lines" in batch.health[0].detail
    await repository.ingest_batch(batch, Detector())
    idle = await candidate(LogProbe([path], repository=repository))
    assert idle.health[0].error_kind == "unsupported_format"
    append(path, "sudo: pam_unix(sudo:auth): authentication failure; rhost=bad user=alice\n")
    partial = await candidate(LogProbe([path], repository=repository))
    assert partial.health[0].error_kind == "partial_format"
