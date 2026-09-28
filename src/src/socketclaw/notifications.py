"""Transactional outbox in the evidence DB, with at-least-once delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import time
from collections.abc import Callable, Generator
from contextlib import closing, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from .completion_schema import OUTBOX_DDL, OUTBOX_TRIGGER
from .config import NotificationConfig


@contextmanager
def notification_connection(
    path: Path, *, read_only: bool = False
) -> Generator[sqlite3.Connection]:
    if path.is_symlink():
        raise OSError("notification database must not be a symbolic link")
    with (
        closing(
            sqlite3.connect(
                f"{path.absolute().as_uri()}?mode={'ro' if read_only else 'rw'}", uri=True
            )
        ) as connection,
        connection,
    ):
        connection.execute("PRAGMA busy_timeout=5000")
        yield connection


async def drained_thread(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


class NotificationOutbox:
    def __init__(self, database: Path, settings: NotificationConfig) -> None:
        self.database = database
        self.path = database
        self.settings = settings

    @staticmethod
    def _meta(connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            "INSERT INTO notification_metadata VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def configure(self) -> None:
        """Run before collectors start, including when channels are disabled."""
        if not self.path.exists():
            return
        with notification_connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for statement in OUTBOX_DDL:
                connection.execute(statement)
            connection.execute(OUTBOX_TRIGGER)
            first = (
                connection.execute(
                    "SELECT 1 FROM notification_metadata WHERE key='configured'"
                ).fetchone()
                is None
            )
            for channel, destination, enabled in (
                ("local", "local", self.settings.local),
                ("webhook", self.settings.webhook or "", bool(self.settings.webhook)),
            ):
                revision = hashlib.sha256(destination.encode()).hexdigest()[:24]
                connection.execute(
                    "INSERT INTO notification_config VALUES(?,?,?,?) "
                    "ON CONFLICT(channel) DO UPDATE SET enabled=excluded.enabled, "
                    "destination=excluded.destination, revision=excluded.revision",
                    (channel, int(enabled), destination, revision),
                )
            if first:
                self._import_legacy(connection)
                self._meta(connection, "configured", "1")

    def _import_legacy(self, connection: sqlite3.Connection) -> None:
        legacy = self.database.parent / "notifications.db"
        has_history = bool(
            connection.execute("SELECT 1 FROM incident_transitions LIMIT 1").fetchone()
        )
        if not legacy.exists():
            self._meta(connection, "reconciliation", "required" if has_history else "ok")
            return
        connection.execute("SAVEPOINT legacy_import")
        try:
            with notification_connection(legacy, read_only=True) as source:
                if source.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise ValueError("legacy outbox integrity check failed")
                rows = source.execute(
                    "SELECT id,channel,payload,attempts,next_attempt,delivered_at"
                    ",error FROM deliveries"
                ).fetchall()
                directory = legacy.parent / "backups"
                if directory.is_symlink():
                    raise OSError("backup directory must not be a symbolic link")
                directory.mkdir(mode=0o700, exist_ok=True)
                backup = directory / f"notifications-legacy-{uuid4().hex}.db"
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                with closing(sqlite3.connect(backup)) as target:
                    source.backup(target)
                self._meta(connection, "legacy_backup", str(backup))
            for identifier, channel, payload, attempts, due, delivered, error in rows:
                data = json.loads(payload)
                transition = data.get("transition_id") or str(identifier).rsplit(":", 1)[0]
                target_row = connection.execute(
                    "SELECT destination,revision FROM notification_config WHERE channel=?",
                    (channel,),
                ).fetchone()
                if target_row is None:
                    continue
                linked = connection.execute(
                    "SELECT 1 FROM incident_transitions WHERE id=?", (transition,)
                ).fetchone()
                connection.execute(
                    "INSERT OR IGNORE INTO deliveries "
                    "(id,transition_id,channel,destination,revision,payload,attempts,next_attempt,"
                    "delivered_at,error,held) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        transition,
                        channel,
                        "" if channel == "webhook" and delivered is None else target_row[0],
                        target_row[1],
                        payload,
                        attempts,
                        due,
                        delivered,
                        error,
                        int(not linked or (channel == "webhook" and delivered is None)),
                    ),
                )
            self._backfill(connection)
            self._meta(connection, "reconciliation", "required" if rows else "ok")
        except (OSError, sqlite3.Error, ValueError, TypeError):
            connection.execute("ROLLBACK TO legacy_import")
            self._meta(connection, "reconciliation", "required")
        finally:
            connection.execute("RELEASE legacy_import")

    def _backfill(self, connection: sqlite3.Connection) -> None:
        for identifier, raw in connection.execute("SELECT id,data_json FROM incident_transitions"):
            data = json.loads(raw)
            if data["action"] not in {
                "opened",
                "reopened",
                "recurred",
                "observed_recovery",
                "worsened",
            }:
                continue
            payload = json.dumps(
                {
                    "incident_id": data["incident_id"],
                    "transition_id": identifier,
                    "action": data["action"],
                    "at": data["at"],
                    "delayed_evidence": True,
                }
            )
            for channel, destination, revision in connection.execute(
                "SELECT channel,destination,revision FROM notification_config WHERE enabled=1"
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO deliveries "
                    "(id,transition_id,channel,destination,revision,payload) VALUES(?,?,?,?,?,?)",
                    (
                        f"{identifier}:{channel}:{revision}",
                        identifier,
                        channel,
                        destination,
                        revision,
                        payload,
                    ),
                )

    def reconcile(self, *, send_history: bool) -> None:
        with notification_connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if send_history:
                connection.execute(
                    "UPDATE deliveries SET destination=(SELECT destination FROM "
                    "notification_config c WHERE c.channel=deliveries.channel),held=0 "
                    "WHERE destination='' AND held=1 AND EXISTS(SELECT 1 FROM "
                    "notification_config c WHERE c.channel=deliveries.channel AND c.enabled=1) "
                    "AND EXISTS(SELECT 1 FROM incident_transitions t "
                    "WHERE t.id=deliveries.transition_id)"
                )
                self._backfill(connection)
            else:
                connection.execute(
                    "UPDATE deliveries SET held=2,error='operator_cancelled' "
                    "WHERE destination='' AND held=1"
                )
            self._meta(
                connection, "reconciliation", "reviewed_send" if send_history else "reviewed_skip"
            )

    def collect(self) -> None:
        """Compatibility entry point. Enqueue runs inside the evidence transaction."""
        if self.path.exists():
            self.configure()
            self.reconcile(send_history=True)

    def pending(self) -> list[tuple[str, str, str, int]]:
        if not self.path.exists():
            return []
        with notification_connection(self.path, read_only=True) as connection:
            return connection.execute(
                "SELECT d.id,d.channel,d.payload,d.attempts FROM deliveries d "
                "JOIN notification_config c ON d.channel=c.channel "
                "WHERE d.delivered_at IS NULL AND d.next_attempt<=? AND c.enabled=1 "
                "AND ((d.held=0 AND d.revision=c.revision) OR d.held=-1) "
                "AND d.destination<>'' AND d.lease_until<=? ORDER BY d.rowid LIMIT 50",
                (time.time(), time.time()),
            ).fetchall()

    def _claim(self, identifier: str) -> str | None:
        with notification_connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT d.destination FROM deliveries d JOIN notification_config c "
                "ON d.channel=c.channel WHERE d.id=? AND c.enabled=1 "
                "AND ((d.held=0 AND d.revision=c.revision) OR d.held=-1) "
                "AND d.delivered_at IS NULL AND d.lease_until<=?",
                (identifier, time.time()),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE deliveries SET lease_until=? WHERE id=?", (time.time() + 30, identifier)
            )
            return str(row[0])

    def _record(self, identifier: str, attempts: int, error: str | None) -> None:
        with notification_connection(self.path) as connection:
            connection.execute(
                (
                    "UPDATE deliveries SET "
                    "attempts=?,error=?,delivered_at=?,next_attempt=?,lease_until"
                    "=0 WHERE id=?"
                ),
                (
                    attempts + 1,
                    error,
                    time.time() if error is None else None,
                    time.time() + min(3600, 2 ** min(attempts + 1, 12)),
                    identifier,
                ),
            )

    def resolve_delivery(self, identifier: str, *, cancel: bool) -> None:
        """Cancel a held delivery, or authorize its original destination explicitly."""
        with notification_connection(self.path) as connection:
            row = connection.execute(
                "SELECT destination FROM deliveries WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise KeyError(identifier)
            if not cancel and not row[0]:
                raise ValueError("Original destination is unknown; cancel this legacy delivery")
            connection.execute(
                "UPDATE deliveries SET held=?,next_attempt=0,error=? WHERE id=?",
                (2 if cancel else -1, "operator_cancelled" if cancel else None, identifier),
            )

    async def deliver(self) -> None:
        if not self.settings.local and not self.settings.webhook:
            return
        for identifier, channel, payload, attempts in await asyncio.to_thread(self.pending):
            if (channel == "local" and not self.settings.local) or (
                channel == "webhook" and not self.settings.webhook
            ):
                continue
            destination = await drained_thread(self._claim, identifier)
            if destination is None:
                continue
            error = None
            try:
                if channel == "webhook":
                    async with httpx.AsyncClient(
                        timeout=10, follow_redirects=False, trust_env=False
                    ) as client:
                        response = await client.post(
                            destination,
                            content=payload,
                            headers={
                                "Content-Type": "application/json",
                                "Idempotency-Key": identifier,
                            },
                        )
                        response.raise_for_status()
                else:
                    await _local_notification(payload)
            except (OSError, RuntimeError, httpx.HTTPError) as exc:
                error = type(exc).__name__
            await drained_thread(self._record, identifier, attempts, error)

    def status(self) -> dict[str, object]:
        result: dict[str, object] = {
            "pending": 0,
            "failed": 0,
            "delivered": 0,
            "held": 0,
            "cancelled": 0,
            "last_error": None,
            "next_attempt_at": None,
            "worker_state": "not_started",
            "reconciliation": "not_initialized",
            "enabled_channels": [
                channel
                for channel, enabled in (
                    ("local", self.settings.local),
                    ("webhook", bool(self.settings.webhook)),
                )
                if enabled
            ],
        }
        if not self.path.exists():
            return result
        with notification_connection(self.path, read_only=True) as connection:
            if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='deliveries'"
            ).fetchone():
                result["worker_state"] = "not_initialized"
                return result
            row = connection.execute(
                "SELECT SUM(delivered_at IS NULL),SUM(delivered_at IS NULL AND error IS NOT NULL),"
                "SUM(delivered_at IS NOT NULL) FROM deliveries"
            ).fetchone()
            result.update(
                zip(("pending", "failed", "delivered"), (int(x or 0) for x in row), strict=True)
            )
            error = connection.execute(
                "SELECT error FROM deliveries WHERE delivered_at IS NULL AND error IS NOT NULL "
                "ORDER BY next_attempt DESC LIMIT 1"
            ).fetchone()
            result["last_error"] = error[0] if error else None
            due = connection.execute(
                "SELECT MIN(next_attempt) FROM deliveries WHERE delivered_at IS NULL"
            ).fetchone()[0]
            if due is not None:
                result["next_attempt_at"] = datetime.fromtimestamp(float(due), UTC).isoformat()
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='notification_metadata'"
            ).fetchone():
                meta = dict(connection.execute("SELECT key,value FROM notification_metadata"))
                result["reconciliation"] = meta.get("reconciliation", "not_initialized")
                result["worker_error"] = meta.get("worker_error") or None
                heartbeat = float(meta.get("heartbeat", "0"))
                result["worker_state"] = "running" if time.time() - heartbeat <= 10 else "stale"
                if meta.get("worker_error"):
                    result["worker_state"] = "degraded"
                result["held"] = connection.execute(
                    "SELECT COUNT(*) FROM deliveries d LEFT JOIN "
                    "notification_config c ON d.channel=c.channel WHERE "
                    "d.delivered_at IS NULL AND d.held<>2 AND (d.held>0 OR c.enabled<>1 OR "
                    "(d.held=0 AND d.revision<>c.revision))"
                ).fetchone()[0]
                cancelled = connection.execute(
                    "SELECT COUNT(*) FROM deliveries WHERE held=2 AND delivered_at IS NULL"
                ).fetchone()[0]
                result["cancelled"] = cancelled
                result["pending"] = int(row[0] or 0) - cancelled
                result["failed"] = int(row[1] or 0) - cancelled
        if not result["enabled_channels"]:
            result["worker_state"] = "disabled"
        return result

    def heartbeat(self, error: str = "") -> None:
        with notification_connection(self.path) as connection:
            self._meta(connection, "heartbeat", str(time.time()))
            self._meta(connection, "worker_error", error)

    def details(self) -> list[dict[str, object]]:
        with notification_connection(self.path, read_only=True) as connection:
            return [
                dict(zip(("id", "channel", "attempts", "held", "error"), row, strict=True))
                for row in connection.execute(
                    "SELECT id,channel,attempts,held,error FROM deliveries WHERE "
                    "delivered_at IS NULL ORDER BY rowid LIMIT 100"
                )
            ]

    async def run(self) -> None:
        await drained_thread(self.configure)

        async def pulse() -> None:
            while True:
                with suppress(OSError, sqlite3.Error):
                    await drained_thread(self.heartbeat, self._worker_error)
                await asyncio.sleep(2)

        self._worker_error = ""
        heartbeat = asyncio.create_task(pulse())
        try:
            while True:
                try:
                    await self.deliver()
                    self._worker_error = ""
                except (OSError, sqlite3.Error, ValueError) as exc:
                    self._worker_error = type(exc).__name__
                await asyncio.sleep(2)
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
            with suppress(OSError, sqlite3.Error):
                await drained_thread(self.heartbeat, "worker_stopped")


async def _local_notification(payload: str) -> None:
    data = json.loads(payload)
    message = f"Incident {data['incident_id']}: {data['action']}"
    if data.get("delayed_evidence"):
        message = "Historical evidence / " + message
    if platform.system() == "Darwin":
        executable = shutil.which("osascript")
        args = [
            "-e",
            'on run argv\ndisplay notification (item 1 of argv) with title "SocketClaw"\nend run',
            message,
        ]
    else:
        executable = shutil.which("notify-send")
        args = ["SocketClaw", message]
    if executable is None:
        raise RuntimeError("local notification command unavailable")
    process = await asyncio.create_subprocess_exec(
        executable, *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        await asyncio.wait_for(process.wait(), 10)
    except (TimeoutError, asyncio.CancelledError):
        process.kill()
        await process.wait()
        raise
    if process.returncode:
        raise RuntimeError("local notification command failed")
