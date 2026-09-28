"""Opt-in owner-process soak/load evidence using only private loopback fixtures.

Examples: --seconds 60 --rate 10, --seconds 1800 --rate 100,
--seconds 259200 --rate 1. A short run never satisfies the 72-hour release gate.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import signal
import sqlite3
import ssl
import statistics
import sys
import tempfile
import time
from contextlib import closing, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark_operations import seed_history

from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig, ConfigStore, NotificationConfig, ServiceConfig
from socketclaw.control import ControlClient
from socketclaw.detection import Detector
from socketclaw.domain import EventSource, SecurityEvent
from socketclaw.storage import Repository


def counts(database: Path) -> dict[str, int]:
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as db:
        return {
            "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "log_events": db.execute("SELECT COUNT(*) FROM events WHERE source='log'").fetchone()[
                0
            ],
            "unique_log_sources": db.execute(
                "SELECT COUNT(DISTINCT source_key) FROM events WHERE source='log'"
            ).fetchone()[0],
            "gaps": db.execute("SELECT COUNT(*) FROM ingest_gaps").fetchone()[0],
            "checkpoints": db.execute("SELECT COUNT(*) FROM probe_checkpoints").fetchone()[0],
        }


async def run(seconds: int, rate: int, output: Path, burst_seconds: int = 0) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scv-", dir="/tmp") as root:
        home = Path(root)
        logs = [home / "fixture-a.log", home / "fixture-b.log"]
        for path in logs:
            path.touch(mode=0o600)
        store = ConfigStore(home)
        seed = Repository(store.database_path)
        await seed.initialize()
        await seed.ingest_batch(
            ProbeBatch(
                observations=(
                    SecurityEvent(
                        source=EventSource.PING,
                        event_type="ping.result",
                        target="127.0.0.1",
                        title="Fixture",
                        summary="Normal capacity fixture",
                        evidence={"packet_loss": 0, "outcome": "ok"},
                    ),
                )
            ),
            Detector(),
        )
        await seed.close()
        await asyncio.to_thread(seed_history, store.database_path, 90, 100)
        attempts: dict[str, int] = {}
        received: set[str] = set()
        service_status = [200]

        certificate, key = home / "fixture.pem", home / "fixture.key"
        openssl = await asyncio.create_subprocess_exec(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "4",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, certificate_error = await openssl.communicate()
        if openssl.returncode:
            raise RuntimeError(f"Cannot prepare private TLS fixture: {certificate_error!r}")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)

        async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                status = service_status[0]
                if header.startswith(b"POST "):
                    fields = dict(
                        line.split(b":", 1) for line in header.split(b"\r\n")[1:] if b":" in line
                    )
                    normalized = {name.lower(): value.strip() for name, value in fields.items()}
                    await reader.readexactly(int(normalized.get(b"content-length", b"0")))
                    identifier = normalized.get(b"idempotency-key", b"").decode()
                    attempts[identifier] = attempts.get(identifier, 0) + 1
                    status = 503 if attempts[identifier] == 1 else 200
                    if status == 200:
                        received.add(identifier)
                writer.write(
                    (
                        f"HTTP/1.1 {status} Fixture\r\nContent-Length: 2\r\n"
                        "Connection: close\r\n\r\nok"
                    ).encode()
                )
                await writer.drain()
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()

        server = await asyncio.start_server(respond, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        secure = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=tls)
        tls_port = int(secure.sockets[0].getsockname()[1])
        store.save(
            AppConfig(
                targets=["127.0.0.1"],
                ports=[port],
                log_paths=[str(p) for p in logs],
                notifications=NotificationConfig(webhook=f"http://127.0.0.1:{port}/alerts"),
                services=[
                    ServiceConfig(
                        id=kind,
                        name=f"Fixture {kind}",
                        host="127.0.0.1",
                        port=tls_port if kind == "https" else port,
                        protocol=kind,
                        interval=1,
                    )
                    for kind in ("tcp", "http", "https")
                ],
            )
        )
        env = {**os.environ, "SOCKETCLAW_HOME": root}
        env.pop("OPENAI_API_KEY", None)
        with (home / "owner.log").open("wb") as owner_log:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import functools,httpx,ssl,os; "
                "httpx.AsyncClient=functools.partial(httpx.AsyncClient, "
                "verify=ssl.create_default_context(cafile=os.environ['FIXTURE_CA'])); "
                "from socketclaw.entrypoint import main; main()",
                "monitor",
                env={**env, "FIXTURE_CA": str(certificate)},
                stdout=owner_log,
                stderr=owner_log,
            )
            latencies: list[float] = []
            samples: list[dict[str, Any]] = []
            generated = 0
            cleanup_id: str | None = None
            started = time.monotonic()
            client = ControlClient(home)
            try:
                for _ in range(200):
                    if (home / "control.sock").exists():
                        await client.connect()
                        break
                    if process.returncode is not None:
                        raise RuntimeError("Owner failed to start")
                    await asyncio.sleep(0.1)
                else:
                    raise TimeoutError("Owner startup timed out")
                # Wait for the initial empty-file checkpoint before generating measured input.
                for _ in range(200):
                    if counts(store.database_path)["checkpoints"] >= 2:
                        break
                    await asyncio.sleep(0.1)
                started = time.monotonic()
                eligible = (await client.call("retention.preview", {"days": 30}))["eligible"]
                for tick in range(seconds):
                    active_rate = 100 if 300 <= tick < 300 + burst_seconds else rate
                    service_status[0] = (
                        503 if seconds // 3 <= tick < seconds // 3 + min(10, seconds // 4) else 200
                    )
                    if tick and tick % 300 == 0:
                        for path in logs:
                            path.replace(path.with_suffix(f".{tick}.log"))
                            path.touch(mode=0o600)
                        # Keep archives bounded only after all earlier input is durable.
                        if counts(store.database_path)["log_events"] == generated:
                            for path in logs:
                                archives = sorted(
                                    home.glob(f"{path.stem}.*.log"),
                                    key=lambda item: item.stat().st_mtime,
                                )
                                for archive in archives[:-4]:
                                    archive.unlink()
                    for index, path in enumerate(logs):
                        amount = active_rate // 2 + (active_rate % 2 if index == 0 else 0)
                        with path.open("a") as stream:
                            for _ in range(amount):
                                generated += 1
                                stream.write(
                                    f"Sep 29 12:00:00 fixture sshd[123]: Failed password for "
                                    f"fixture from 192.0.2.1 port 12345 ssh2 seq={generated}\n"
                                )
                    start = time.monotonic()
                    await client.call("health.get")
                    latencies.append(time.monotonic() - start)
                    if tick == seconds // 2:
                        cleanup_id = (await client.call("retention.apply", {"days": 30}))["id"]
                    if tick % 60 == 0:
                        sample = {
                            "second": tick,
                            "generated": generated,
                            **counts(store.database_path),
                        }
                        rss = await asyncio.create_subprocess_exec(
                            "ps",
                            "-o",
                            "rss=",
                            "-p",
                            str(process.pid),
                            stdout=asyncio.subprocess.PIPE,
                        )
                        usage, _ = await rss.communicate()
                        sample["rss_bytes"] = int(usage.strip() or b"0") * 1024
                        samples.append(sample)
                        print(json.dumps(sample), flush=True)
                    if tick and tick % 30 == 0:
                        client = ControlClient(home)
                        await client.connect()
                    await asyncio.sleep(max(0, started + tick + 1 - time.monotonic()))
                for _ in range(300):
                    actual = counts(store.database_path)
                    notifications = await client.call("notification.status")
                    if actual["log_events"] >= generated and notifications["pending"] == 0:
                        break
                    await asyncio.sleep(0.1)
                await client.call("owner.stop")
                await asyncio.wait_for(process.wait(), 15)
                actual = counts(store.database_path)
                elapsed = time.monotonic() - started
                with closing(sqlite3.connect(store.database_path)) as db:
                    deliveries = {row[0] for row in db.execute("SELECT id FROM deliveries")}
                    cleanup_row = db.execute(
                        "SELECT data_json FROM maintenance_jobs WHERE id=?", (cleanup_id,)
                    ).fetchone()
                    cleanup: dict[str, Any] = json.loads(cleanup_row[0]) if cleanup_row else {}
                    intervals: dict[str, list[float]] = {}
                    previous: dict[str, datetime] = {}
                    for service_id, at in db.execute(
                        "SELECT service_id,collected_at FROM events WHERE service_id IS NOT NULL "
                        "ORDER BY service_id,ingest_seq"
                    ):
                        timestamp = datetime.fromisoformat(at)
                        if service_id in previous:
                            intervals.setdefault(service_id, []).append(
                                (timestamp - previous[service_id]).total_seconds()
                            )
                        previous[service_id] = timestamp
                service_p95 = {
                    name: sorted(values)[max(0, int(len(values) * 0.95) - 1)]
                    for name, values in intervals.items()
                }
                code = Path(__file__).resolve().parents[1] / "src" / "socketclaw"
                fingerprint = hashlib.sha256()
                for source in sorted(code.rglob("*.py")):
                    fingerprint.update(str(source.relative_to(code)).encode())
                    fingerprint.update(source.read_bytes())
                result: dict[str, Any] = {
                    "platform": platform.platform(),
                    "architecture": platform.machine(),
                    "requested_seconds": seconds,
                    "elapsed_seconds": elapsed,
                    "rate": rate,
                    "burst_seconds": burst_seconds,
                    "source_sha256": fingerprint.hexdigest(),
                    "generated": generated,
                    **actual,
                    "owner_exit": process.returncode,
                    "rpc_samples": len(latencies),
                    "rpc_median_ms": statistics.median(latencies) * 1000,
                    "rpc_p95_ms": sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] * 1000,
                    "samples": samples,
                    "webhook_deliveries": len(deliveries),
                    "webhook_received": len(received),
                    "webhook_attempts": sum(attempts.values()),
                    "service_interval_p95_seconds": service_p95,
                    "cleanup_status": cleanup.get("status"),
                    "cleanup_deleted": cleanup.get("deleted"),
                    "cleanup_expected": eligible,
                    "rotations": max(0, (seconds - 1) // 300) * 2,
                    "passed": actual["log_events"] == generated
                    and actual["unique_log_sources"] == generated
                    and actual["gaps"] == 0
                    and deliveries == received
                    and cleanup.get("status") == "completed"
                    and cleanup.get("deleted") == eligible
                    and len(service_p95) == 3
                    and all(value <= 2 for value in service_p95.values())
                    and process.returncode == 0,
                    "release_72h_gate": "not_evaluated",
                    "scope": (
                        "Real owner, TCP/HTTP/HTTPS, two files, webhook retries, "
                        "service outage/recovery, rotation, RSS, IPC reconnect"
                    ),
                    "remaining_profile": ("72h RSS trend, cross-platform execution and user tasks"),
                }
                output.write_text(json.dumps(result, indent=2) + "\n")
                return result
            finally:
                if process.returncode is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 10)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                server.close()
                await server.wait_closed()
                secure.close()
                await secure.wait_closed()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--rate", type=int, default=10)
    parser.add_argument(
        "--burst-seconds",
        type=int,
        default=0,
        help="Inject 100 logs/sec from second 300 for this duration",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/completion/owner-soak.json"))
    args = parser.parse_args()
    if args.seconds < 1 or not 1 <= args.rate <= 1000:
        parser.error("seconds must be positive; rate must be 1..1000")
    result = asyncio.run(run(args.seconds, args.rate, args.output, args.burst_seconds))
    print(json.dumps({key: value for key, value in result.items() if key != "samples"}), flush=True)
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
