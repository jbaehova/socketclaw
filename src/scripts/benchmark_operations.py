"""Reproducible local load measurements; results are evidence, not an SLA."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import platform
import sqlite3
import statistics
import tempfile
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from uuid import uuid4

from socketclaw.collection import ProbeBatch
from socketclaw.detection import Detector
from socketclaw.domain import EventSource, ObservationOutcome, SecurityEvent
from socketclaw.export import export_json
from socketclaw.monitor import MonitorService, ProbeJob
from socketclaw.probes.ports import PortProbe
from socketclaw.storage import EventQuery, Repository


def report(**values: object) -> None:
    print(json.dumps(values), flush=True)


async def burst(path: Path, size: int, batches: int) -> list[float]:
    repository = Repository(path)
    await repository.initialize()
    samples: list[float] = []
    try:
        for batch_index in range(batches):
            now = datetime.now(UTC)
            observations = tuple(
                SecurityEvent(
                    source=EventSource.LOG,
                    outcome=ObservationOutcome.OK,
                    event_type="log.auth_failure",
                    target="192.0.2.9",
                    title="Synthetic authentication failure",
                    summary="Benchmark fixture, no live security incident",
                    source_key=f"burst:{batch_index}:{index}",
                    evidence={"asset": "benchmark", "user": "fixture", "source_ip": "192.0.2.9"},
                )
                for index in range(size)
            )
            started = time.perf_counter()
            saved = await repository.ingest_batch(
                ProbeBatch(collected_at=now, observations=observations), Detector()
            )
            elapsed = time.perf_counter() - started
            assert len(saved) == size
            samples.append(elapsed)
            report(kind="burst_sample", size=size, batch=batch_index, seconds=elapsed)
    finally:
        await repository.close()
    return samples


def seed_history(path: Path, days: int, daily: int) -> None:
    """Clone one valid normal row; retain its immutable rule provenance."""
    with sqlite3.connect(path) as connection:
        columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(events)")]
        template = list(connection.execute("SELECT * FROM events LIMIT 1").fetchone())
        statement = f"INSERT INTO events VALUES ({','.join('?' for _ in columns)})"
        positions = {column: index for index, column in enumerate(columns)}
        now = datetime.now(UTC)
        sequence = 1
        for day in range(days):
            rows: list[list[object]] = []
            for _ in range(daily):
                sequence += 1
                row = template.copy()
                row[positions["id"]] = str(uuid4())
                row[positions["ingest_seq"]] = sequence
                row[positions["source_key"]] = f"history:{sequence}"
                timestamp = (now - timedelta(days=day + 2)).isoformat(timespec="microseconds")
                for column in (
                    "observed_at",
                    "ingested_at",
                    "collected_at",
                    "committed_at",
                    "correlation_at",
                ):
                    row[positions[column]] = timestamp
                rows.append(row)
                if len(rows) == 10000:
                    connection.executemany(statement, rows)
                    rows.clear()
            connection.executemany(statement, rows)
            connection.commit()
        connection.execute(
            "UPDATE schema_meta SET value=? WHERE key='ingest_sequence'", (str(sequence),)
        )


async def history(path: Path, days: int, daily: int) -> None:
    repository = Repository(path)
    await repository.initialize()
    try:
        await repository.ingest_batch(
            ProbeBatch(
                observations=(
                    SecurityEvent(
                        source=EventSource.PING,
                        event_type="ping.result",
                        target="127.0.0.1",
                        title="Synthetic normal observation",
                        summary="Capacity fixture",
                        evidence={"packet_loss": 0, "outcome": "ok"},
                    ),
                )
            ),
            Detector(),
        )
        await asyncio.to_thread(seed_history, path, days, daily)
        started = time.perf_counter()
        events = await repository.list_events(EventQuery(limit=100))
        query = time.perf_counter() - started
        started = time.perf_counter()
        await repository.database_info()
        diagnostic = time.perf_counter() - started
        started = time.perf_counter()
        exported = [export_json(event, None) for event in events]
        export = time.perf_counter() - started
        started = time.perf_counter()
        preview = await repository.retain_history(normal_days=30, dry_run=True)
        preview_time = time.perf_counter() - started
        started = time.perf_counter()
        result = await repository.retain_history(normal_days=30, dry_run=False)
        cleanup = time.perf_counter() - started
        report(
            kind="history",
            days=days,
            daily_events=daily,
            total_events=1 + days * daily,
            query_seconds=query,
            full_diagnostic_seconds=diagnostic,
            export_100_seconds=export,
            exported_bytes=sum(map(len, exported)),
            preview_seconds=preview_time,
            cleanup_seconds=cleanup,
            eligible_events=preview.eligible_events,
            deleted_events=result.deleted_events,
            protected_events=result.protected_events,
            database_bytes=result.database_bytes,
            backup_created=result.backup_path is not None,
        )
    finally:
        await repository.close()
    restarted = Repository(path)
    try:
        await restarted.initialize()
        await restarted.database_info()
    finally:
        await restarted.close()
    report(kind="restart", days=days, ok=True)


async def sustained(path: Path, seconds: int, rate: int) -> None:
    repository = Repository(path)
    await repository.initialize()
    queue: deque[SecurityEvent] = deque()
    checks: list[float] = []
    samples: list[int] = []
    emitted = 0

    async def accept(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    probe = PortProbe()

    async def collect_logs() -> list[SecurityEvent]:
        return [queue.popleft() for _ in range(min(len(queue), 100))]

    async def collect_service() -> list[SecurityEvent]:
        event = await probe.collect("127.0.0.1", [port])
        checks.append(time.monotonic())
        return [event]

    monitor = MonitorService(
        repository,
        Detector(),
        jobs=(
            ProbeJob("benchmark:log", 0.5, collect_logs),
            ProbeJob("benchmark:service", 1.0, collect_service),
        ),
    )
    started = time.monotonic()
    try:
        await monitor.start()
        while time.monotonic() - started < seconds:
            expected = int((time.monotonic() - started) * rate)
            while emitted < expected:
                emitted += 1
                queue.append(
                    SecurityEvent(
                        source=EventSource.LOG,
                        outcome=ObservationOutcome.OK,
                        event_type="log.auth_failure",
                        target="192.0.2.9",
                        title="Synthetic sustained load",
                        summary="Benchmark fixture",
                        source_key=f"sustained:{emitted}",
                    )
                )
            samples.append(len(queue))
            await asyncio.sleep(0.1)
        deadline = time.monotonic() + 30
        while queue and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        monitor.pause()
        while (
            any(
                health.activity in {"scheduled", "manual"} for health in monitor.status.probe_health
            )
            and time.monotonic() < deadline
        ):
            await asyncio.sleep(0.1)
        await monitor.stop()
        status = monitor.status
        with sqlite3.connect(path) as connection:
            committed = int(
                connection.execute(
                    "SELECT count(*) FROM events WHERE source_key LIKE 'sustained:%'"
                ).fetchone()[0]
            )
        report(
            kind="sustained",
            duration_seconds=seconds,
            input_per_second=rate,
            generated=emitted,
            committed=committed,
            peak_backlog=max(samples, default=0),
            remaining_backlog=len(queue),
            first_half_max=max(samples[: len(samples) // 2], default=0),
            second_half_max=max(samples[len(samples) // 2 :], default=0),
            service_checks=len(checks),
            max_service_interval=max((b - a for a, b in pairwise(checks)), default=0),
            last_error=status.last_error,
            pending_batches=status.pending_batches,
        )
    finally:
        await monitor.stop()
        server.close()
        await server.wait_closed()
        await repository.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batches", type=int, default=5)
    parser.add_argument("--history-days", type=int, nargs="*", default=[])
    parser.add_argument("--daily-events", type=int, default=18720)
    parser.add_argument("--sustained-seconds", type=int, default=0)
    parser.add_argument("--input-rate", type=int, default=100)
    args = parser.parse_args()
    batches = int(args.batches)
    days_list: list[int] = args.history_days
    daily = int(args.daily_events)
    duration = int(args.sustained_seconds)
    rate = int(args.input_rate)
    if batches < 1 or daily < 1 or rate < 1 or duration < 0 or any(day < 1 for day in days_list):
        parser.error("counts must be positive")
    report(
        kind="hardware",
        platform=platform.platform(),
        processor=platform.processor(),
        machine=platform.machine(),
        python=platform.python_version(),
        batches=batches,
    )
    with tempfile.TemporaryDirectory(prefix="socketclaw-benchmark-") as directory:
        base = Path(directory)
        for size in (100, 500, 1000):
            samples = await burst(base / f"burst-{size}.db", size, batches)
            report(
                kind="burst_summary",
                size=size,
                median=statistics.median(samples),
                p95=sorted(samples)[math.ceil(len(samples) * 0.95) - 1],
                samples=samples,
            )
        for days in days_list:
            await history(base / f"history-{days}.db", days, daily)
        if duration:
            await sustained(base / "sustained.db", duration, rate)


if __name__ == "__main__":
    asyncio.run(main())
