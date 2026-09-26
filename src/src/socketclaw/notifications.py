"""Durable transition outbox. Webhooks are at-least-once with stable idempotency keys."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .config import NotificationConfig


class NotificationOutbox:
    def __init__(self, database: Path, settings: NotificationConfig) -> None:
        self.database = database
        self.path = database.parent / "notifications.db"
        self.settings = settings

    def collect(self) -> None:
        """Copy unseen transitions atomically; evidence updates do not create notifications."""
        if not self.settings.local and not self.settings.webhook:
            return
        if self.path.is_symlink():
            raise OSError("notification database must not be a symbolic link")
        with sqlite3.connect(self.path) as outbox:
            os.chmod(self.path, 0o600)
            outbox.execute(
                "CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, "
                "channel TEXT NOT NULL, payload TEXT NOT NULL, "
                "attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0, "
                "delivered_at REAL, error TEXT)"
            )
            outbox.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
            )
            row = outbox.execute(
                "SELECT value FROM metadata WHERE key='transition_cursor'"
            ).fetchone()
            cursor = int(row[0]) if row else 0
            with sqlite3.connect(
                f"{self.database.absolute().as_uri()}?mode=ro", uri=True
            ) as source:
                rows = source.execute(
                    "SELECT rowid, id, data_json FROM incident_transitions "
                    "WHERE rowid>? ORDER BY rowid LIMIT 1000",
                    (cursor,),
                ).fetchall()
            for _sequence, identifier, raw in rows:
                transition = json.loads(raw)
                if transition["action"] not in {
                    "opened",
                    "reopened",
                    "recurred",
                    "observed_recovery",
                    "worsened",
                }:
                    continue
                # Send only incident identity/state. Raw observations and notes remain local.
                try:
                    recorded = datetime.fromisoformat(transition["at"])
                    delayed = (datetime.now(UTC) - recorded).total_seconds() > 300
                except (ValueError, TypeError):
                    delayed = True
                payload = json.dumps(
                    {
                        "incident_id": transition["incident_id"],
                        "transition_id": identifier,
                        "action": transition["action"],
                        "at": transition["at"],
                        "delayed_evidence": delayed,
                    }
                )
                for channel in ("local", "webhook"):
                    enabled = self.settings.local if channel == "local" else self.settings.webhook
                    if enabled:
                        outbox.execute(
                            "INSERT OR IGNORE INTO deliveries(id,channel,payload) VALUES(?,?,?)",
                            (f"{identifier}:{channel}", channel, payload),
                        )

            if rows:
                outbox.execute(
                    "INSERT INTO metadata(key,value) VALUES('transition_cursor',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (rows[-1][0],),
                )

    def pending(self) -> list[tuple[str, str, str, int]]:
        if not self.path.exists():
            return []
        with sqlite3.connect(self.path) as connection:
            return connection.execute(
                "SELECT id,channel,payload,attempts FROM deliveries "
                "WHERE delivered_at IS NULL AND next_attempt<=? ORDER BY rowid LIMIT 50",
                (time.time(),),
            ).fetchall()

    def _record(self, identifier: str, attempts: int, error: str | None) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "UPDATE deliveries SET attempts=?, error=?, delivered_at=?, "
                "next_attempt=? WHERE id=?",
                (
                    attempts + 1,
                    error,
                    time.time() if error is None else None,
                    time.time() + min(3600, 2 ** min(attempts + 1, 12)),
                    identifier,
                ),
            )

    async def deliver(self) -> None:
        for identifier, channel, payload, attempts in await asyncio.to_thread(self.pending):
            if channel == "local" and not self.settings.local:
                continue
            if channel == "webhook" and not self.settings.webhook:
                continue
            error = None
            try:
                if channel == "webhook":
                    assert self.settings.webhook is not None
                    async with httpx.AsyncClient(
                        timeout=10, follow_redirects=False, trust_env=False
                    ) as client:
                        response = await client.post(
                            self.settings.webhook,
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
            await asyncio.to_thread(self._record, identifier, attempts, error)

    def status(self) -> dict[str, object]:
        """Inspect persisted delivery diagnostics without creating a DB or sending anything."""
        result: dict[str, object] = {
            "pending": 0,
            "failed": 0,
            "delivered": 0,
            "last_error": None,
            "next_attempt_at": None,
            "enabled_channels": [
                channel
                for channel, enabled in (
                    ("local", self.settings.local),
                    ("webhook", bool(self.settings.webhook)),
                )
                if enabled
            ],
        }
        if self.path.is_symlink():
            raise OSError("notification database must not be a symbolic link")
        if not self.path.exists():
            return result
        with sqlite3.connect(f"{self.path.absolute().as_uri()}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT SUM(delivered_at IS NULL), "
                "SUM(delivered_at IS NULL AND error IS NOT NULL), "
                "SUM(delivered_at IS NOT NULL) FROM deliveries"
            ).fetchone()
            result.update(
                zip(
                    ("pending", "failed", "delivered"),
                    (int(item or 0) for item in row),
                    strict=True,
                )
            )
            error = connection.execute(
                "SELECT error, next_attempt FROM deliveries "
                "WHERE delivered_at IS NULL AND error IS NOT NULL "
                "ORDER BY next_attempt DESC LIMIT 1"
            ).fetchone()
            if error:
                result["last_error"] = str(error[0])
            upcoming = connection.execute(
                "SELECT MIN(next_attempt) FROM deliveries WHERE delivered_at IS NULL"
            ).fetchone()
            if upcoming and upcoming[0] is not None:
                result["next_attempt_at"] = datetime.fromtimestamp(
                    float(upcoming[0]), UTC
                ).isoformat()
            return result

    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.collect)
                await self.deliver()
            except (OSError, sqlite3.Error):
                # Delivery failures stay pending; collection never stops because
                # a local notification database is temporarily unavailable.
                pass
            await asyncio.sleep(2)


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
