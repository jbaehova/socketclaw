"""Resumable bounded cleanup and verified, journaled offline database recovery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from .domain import utc_now
from .migrations import SCHEMA_VERSION, recovery_backup
from .storage import Repository


class RetentionJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID = Field(default_factory=uuid4)
    status: str = "planned"
    cutoff: datetime
    generation: str
    watermark: int = 0
    cursor: int = 0
    backup: str | None = None
    backup_sha256: str | None = None
    initial_candidates: int = 0
    deleted: int = 0
    protected: int = 0
    remaining: int = 0
    batch_size: int = 1000
    cancel_requested: bool = False
    error: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


def private_json(path: Path, data: Any) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise OSError("Managed metadata must not be a symbolic link")
    fd, filename = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def file_digest(path: Path) -> str:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise OSError("Backup must be a regular file, not a link")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_backup(path: Path) -> dict[str, Any]:
    manifest_path = path.with_suffix(".json")
    if manifest_path.is_symlink():
        raise OSError("Backup manifest must not be a symbolic link")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("database") != path.name or manifest.get("sha256") != file_digest(path):
        raise ValueError("Backup checksum or manifest does not match")
    with closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("Backup integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("Backup references are invalid")
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        if (
            row is None
            or not 1 <= int(row[0]) <= SCHEMA_VERSION
            or int(row[0]) != manifest.get("schema_version")
        ):
            raise ValueError("Backup schema is unsupported or does not match its manifest")
    return manifest


def annotate_backup(path: Path, *, purpose: str, pinned: bool) -> None:
    manifest = verify_backup(path)
    manifest.update(purpose=purpose, pinned=pinned)
    private_json(path.with_suffix(".json"), manifest)


def backup_inventory(database: Path) -> list[dict[str, Any]]:
    directory = database.parent / "backups"
    if directory.is_symlink():
        raise OSError("Backup directory must not be a symbolic link")
    records: list[dict[str, Any]] = []
    referenced: set[str] = set()
    if database.exists():
        with closing(
            sqlite3.connect(f"{database.absolute().as_uri()}?mode=ro", uri=True)
        ) as connection:
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='maintenance_jobs'"
            ).fetchone():
                for (raw,) in connection.execute("SELECT data_json FROM maintenance_jobs"):
                    job = json.loads(raw)
                    if job.get("backup") and job["status"] != "completed":
                        referenced.add(job["backup"])
    for path in sorted(directory.glob("*.db")):
        if path.is_symlink():
            raise OSError("Backup files must not be symbolic links")
        try:
            manifest_path = path.with_suffix(".json")
            if manifest_path.is_symlink():
                raise OSError("Backup manifests must not be links")
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            manifest = {"purpose": "unverified", "pinned": True}
        records.append(
            {
                "path": str(path),
                "bytes": path.stat().st_size,
                "created_at": manifest.get("created_at"),
                "purpose": manifest.get("purpose", "migration"),
                "pinned": bool(manifest.get("pinned", True) or str(path) in referenced),
                "referenced": str(path) in referenced,
            }
        )
    return records


def prune_backups(
    database: Path, *, keep_last: int = 3, older_than_days: int = 30, apply: bool = False
) -> list[str]:
    if keep_last < 1 or older_than_days < 1:
        raise ValueError("Keep at least one backup and use a positive retention period")
    inventory = sorted(
        backup_inventory(database), key=lambda r: r["created_at"] or "", reverse=True
    )
    cutoff = utc_now() - timedelta(days=older_than_days)
    candidates = [
        r
        for r in inventory[keep_last:]
        if not r["pinned"] and r["created_at"] and datetime.fromisoformat(r["created_at"]) < cutoff
    ]
    if apply:
        for record in candidates:
            path = Path(record["path"])
            verify_backup(path)
            path.unlink()
            path.with_suffix(".json").unlink()
    return [r["path"] for r in candidates]


# A service's latest observation is retained even if other sources are very busy.
ELIGIBLE = """
e.observed_at < :cutoff AND e.ingest_seq <= :watermark AND e.score < 40
AND NOT EXISTS (SELECT 1 FROM incident_events i WHERE i.event_id=e.id)
AND NOT EXISTS (SELECT 1 FROM investigations i WHERE i.event_id=e.id)
AND NOT EXISTS (SELECT 1 FROM response_proposals p WHERE p.event_id=e.id)
AND NOT EXISTS (SELECT 1 FROM event_suppressions s WHERE s.event_id=e.id)
AND (e.service_id IS NULL OR e.ingest_seq <
    (SELECT MAX(last.ingest_seq) FROM events last WHERE last.service_id=e.service_id))
"""


class MaintenanceService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self._tasks: dict[UUID, asyncio.Task[None]] = {}
        self._cancelled: set[UUID] = set()

    async def preview(self, days: int = 30) -> dict[str, Any]:
        if not 1 <= days <= 36500:
            raise ValueError("days must be between 1 and 36500")
        cutoff = utc_now() - timedelta(days=days)
        async with self.repository.sessions() as session:
            eligible = await session.scalar(
                text("SELECT COUNT(*) FROM events e WHERE " + ELIGIBLE),
                {"cutoff": cutoff.isoformat(), "watermark": 2**63 - 1},
            )
            total = await session.scalar(
                text("SELECT COUNT(*) FROM events WHERE observed_at<:cutoff"),
                {"cutoff": cutoff.isoformat()},
            )
        database = self.repository.database_path
        size = sum(
            p.stat().st_size
            for p in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm"))
            if p.exists()
        )
        free = shutil.disk_usage(database.parent).free
        return {
            "eligible": int(eligible or 0),
            "protected": int(total or 0) - int(eligible or 0),
            "cutoff": cutoff.isoformat(),
            "database_bytes": size,
            "backup_required_bytes": 2 * size + 256 * 1024 * 1024,
            "free_bytes": free,
            "backup_bytes": sum(item["bytes"] for item in backup_inventory(database)),
            "file_shrink_promised": False,
        }

    async def _save(self, job: RetentionJob) -> None:
        job.updated_at = utc_now()
        job.cancel_requested = job.id in self._cancelled
        async with self.repository.sessions() as session:
            await session.execute(
                text(
                    "INSERT INTO maintenance_jobs VALUES(:id,:data) ON "
                    "CONFLICT(id) DO UPDATE SET data_json=excluded.data_json"
                ),
                {"id": str(job.id), "data": job.model_dump_json()},
            )
            await session.commit()

    async def get(self, identifier: UUID) -> RetentionJob:
        async with self.repository.sessions() as session:
            raw = await session.scalar(
                text("SELECT data_json FROM maintenance_jobs WHERE id=:id"), {"id": str(identifier)}
            )
        if raw is None:
            raise KeyError(str(identifier))
        return RetentionJob.model_validate_json(raw)

    async def list(self) -> list[RetentionJob]:
        async with self.repository.sessions() as session:
            rows = await session.scalars(
                text("SELECT data_json FROM maintenance_jobs ORDER BY rowid DESC LIMIT 100")
            )
            return [RetentionJob.model_validate_json(raw) for raw in rows]

    async def create(self, days: int = 30) -> RetentionJob:
        preview = await self.preview(days)
        if preview["free_bytes"] < preview["backup_required_bytes"]:
            raise OSError("Not enough free space for the recovery backup; nothing was deleted")
        async with self.repository.sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            active = await session.scalar(
                text(
                    "SELECT id FROM maintenance_jobs WHERE "
                    "json_extract(data_json,'$.status') IN "
                    "('planned','backing_up','running','paused') LIMIT 1"
                )
            )
            if active:
                raise ValueError(f"A cleanup already exists: {active}. Resume or cancel it first.")
            generation = str(
                await session.scalar(
                    text("SELECT value FROM schema_meta WHERE key='restore_generation'")
                )
            )
            job = RetentionJob(
                cutoff=datetime.fromisoformat(preview["cutoff"]),
                generation=generation,
                initial_candidates=preview["eligible"],
                remaining=preview["eligible"],
                protected=preview["protected"],
            )
            await session.execute(
                text("INSERT INTO maintenance_jobs VALUES(:id,:data)"),
                {"id": str(job.id), "data": job.model_dump_json()},
            )
            await session.commit()
        return job

    def launch(self, identifier: UUID) -> None:
        if identifier in self._tasks and not self._tasks[identifier].done():
            return
        self._cancelled.discard(identifier)
        task = asyncio.create_task(self.run(identifier), name=f"retention-{identifier}")
        self._tasks[identifier] = task
        task.add_done_callback(lambda _: self._tasks.pop(identifier, None))

    async def cancel(self, identifier: UUID) -> RetentionJob:
        job = await self.get(identifier)
        self._cancelled.add(identifier)
        task = self._tasks.get(identifier)
        if task is not None:
            async with self.repository.sessions() as session:
                await session.execute(
                    text(
                        "UPDATE maintenance_jobs SET "
                        "data_json=json_set(data_json,'$.cancel_requested',json('true"
                        "')) WHERE id=:id"
                    ),
                    {"id": str(identifier)},
                )
                await session.commit()
            return await self.get(identifier)
        if job.status != "completed":
            job.status = "cancelled"
            await self._save(job)
        return job

    async def resume(self, identifier: UUID) -> RetentionJob:
        job = await self.get(identifier)
        if job.status == "completed":
            return job
        for other in await self.list():
            if other.id != identifier and other.status in {
                "planned",
                "backing_up",
                "running",
                "paused",
            }:
                raise ValueError("Another cleanup is active")
        self._cancelled.discard(identifier)
        job.cancel_requested = False
        await self._save(job)
        self.launch(identifier)
        return job

    async def run(self, identifier: UUID) -> None:
        job = await self.get(identifier)
        if job.status == "completed":
            return
        if job.cancel_requested:
            self._cancelled.add(identifier)
        try:
            async with self.repository.sessions() as session:
                generation = await session.scalar(
                    text("SELECT value FROM schema_meta WHERE key='restore_generation'")
                )
            if job.generation != generation:
                raise ValueError("Database was restored; this cleanup cannot resume")
            if job.backup is None:
                job.status = "backing_up"
                await self._save(job)
                worker = asyncio.create_task(
                    asyncio.to_thread(
                        recovery_backup, self.repository.database_path, SCHEMA_VERSION
                    )
                )
                try:
                    backup = await asyncio.shield(worker)
                except asyncio.CancelledError:
                    backup = await worker
                    job.backup, job.backup_sha256 = str(backup.path), backup.sha256
                    await self._save(job)
                    raise
                job.backup, job.backup_sha256 = str(backup.path), backup.sha256
                await asyncio.to_thread(
                    annotate_backup, backup.path, purpose="retention", pinned=True
                )
                with closing(
                    sqlite3.connect(f"{backup.path.absolute().as_uri()}?mode=ro", uri=True)
                ) as source:
                    job.watermark = int(
                        source.execute("SELECT COALESCE(MAX(ingest_seq),0) FROM events").fetchone()[
                            0
                        ]
                    )
                    limits = {"cutoff": job.cutoff.isoformat(), "watermark": job.watermark}
                    job.initial_candidates = source.execute(
                        "SELECT COUNT(*) FROM events e WHERE " + ELIGIBLE, limits
                    ).fetchone()[0]
                    job.remaining = job.initial_candidates
                await self._save(job)
            if job.watermark == 0:
                with closing(
                    sqlite3.connect(f"{Path(job.backup).absolute().as_uri()}?mode=ro", uri=True)
                ) as source:
                    job.watermark = int(
                        source.execute("SELECT COALESCE(MAX(ingest_seq),0) FROM events").fetchone()[
                            0
                        ]
                    )
            manifest = await asyncio.to_thread(verify_backup, Path(job.backup))
            if manifest["sha256"] != job.backup_sha256:
                raise ValueError("Cleanup backup changed")
            job.status, job.error = "running", None
            await self._save(job)
            while identifier not in self._cancelled:
                start = time.monotonic()
                # Persist progress in the same transaction as deletion.
                async with self.repository.sessions() as session:
                    await session.execute(text("BEGIN IMMEDIATE"))
                    params = {
                        "cutoff": job.cutoff.isoformat(),
                        "watermark": job.watermark,
                        "cursor": job.cursor,
                        "limit": job.batch_size,
                    }
                    rows = (
                        await session.execute(
                            text(
                                "SELECT id,ingest_seq,source_key FROM events e WHERE "
                                + ELIGIBLE
                                + " AND e.ingest_seq>:cursor ORDER BY e.ingest_seq LIMIT :limit"
                            ),
                            params,
                        )
                    ).all()
                    if not rows:
                        job.status, job.remaining = "completed", 0
                        job.protected = int(
                            await session.scalar(
                                text(
                                    "SELECT COUNT(*) FROM events WHERE observed_at<:cutoff "
                                    "AND ingest_seq<=:watermark"
                                ),
                                params,
                            )
                            or 0
                        )
                    else:
                        source_keys = [
                            {"key": row.source_key} for row in rows if row.source_key is not None
                        ]
                        if source_keys:
                            await session.execute(
                                text("INSERT OR IGNORE INTO retained_source_keys VALUES(:key)"),
                                source_keys,
                            )
                        ids = [row.id for row in rows]
                        for offset in range(0, len(ids), 400):
                            batch = ids[offset : offset + 400]
                            holders = ",".join(f":v{i}" for i in range(len(batch)))
                            await session.execute(
                                text(f"DELETE FROM events WHERE id IN ({holders})"),
                                {f"v{i}": value for i, value in enumerate(batch)},
                            )
                        job.deleted += len(rows)
                        job.cursor = rows[-1].ingest_seq
                        job.remaining = max(0, job.initial_candidates - job.deleted)
                    job.updated_at = utc_now()
                    job.cancel_requested = identifier in self._cancelled
                    await session.execute(
                        text("UPDATE maintenance_jobs SET data_json=:data WHERE id=:id"),
                        {"data": job.model_dump_json(), "id": str(identifier)},
                    )
                    await session.commit()
                if not rows:
                    await asyncio.to_thread(
                        annotate_backup, Path(job.backup), purpose="retention", pinned=False
                    )
                    break
                elapsed = time.monotonic() - start
                job.batch_size = (
                    max(50, job.batch_size // 2)
                    if elapsed > 0.1
                    else min(10000, job.batch_size + 100)
                )
                await asyncio.sleep(0.01)
            if identifier in self._cancelled and job.status != "completed":
                job.status = "cancelled"
                await self._save(job)
        except asyncio.CancelledError:
            job.status = "paused"
            await self._save(job)
            raise
        except Exception as exc:
            job.status, job.error = "failed", type(exc).__name__ + ": " + str(exc)
            await self._save(job)

    async def close(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def wait(self, identifier: UUID) -> RetentionJob:
        task = self._tasks.get(identifier)
        if task is not None:
            await asyncio.shield(task)
        return await self.get(identifier)


def restore_database(database: Path, backup: Path, *, apply: bool = False) -> dict[str, Any]:
    """Caller holds the home lock; live SQLite connections must already be closed."""
    manifest = verify_backup(backup)
    journal = database.parent / "restore-journal.json"
    if journal.exists():
        raise RuntimeError("An interrupted restore needs recovery before another restore")
    result = {
        "backup": str(backup),
        "schema": manifest["schema_version"],
        "applied": False,
        "warning": (
            "Records after the snapshot will be replaced. Previously sent "
            "alerts may repeat. Review configured sources before "
            "restarting."
        ),
    }
    if not apply:
        return result
    if database.is_symlink():
        raise OSError("Database must not be a symbolic link")
    rescue = None
    if database.exists():
        with closing(
            sqlite3.connect(f"{database.absolute().as_uri()}?mode=ro", uri=True)
        ) as source:
            version = int(
                source.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
            )
        rescue = recovery_backup(database, version)
        annotate_backup(rescue.path, purpose="restore-rescue", pinned=True)
    staging = database.parent / f".restore-{uuid4().hex}.db"
    displaced = database.parent / f".before-restore-{uuid4().hex}"
    private_json(
        journal,
        {
            "phase": "prepared",
            "backup": str(backup),
            "staging": str(staging),
            "displaced": str(displaced),
            "rescue": str(rescue.path) if rescue else None,
        },
    )
    try:
        with (
            closing(sqlite3.connect(f"{backup.absolute().as_uri()}?mode=ro", uri=True)) as source,
            closing(sqlite3.connect(staging)) as target,
        ):
            source.backup(target, pages=256)
            target.execute(
                "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('restore_generation',?)",
                (uuid4().hex,),
            )
            target.commit()
        config = database.parent / "config.toml"
        current_hash = hashlib.sha256(config.read_bytes()).hexdigest() if config.is_file() else None
        review_required = manifest.get("config_sha256") != current_hash
        with closing(sqlite3.connect(staging)) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO schema_meta VALUES('restore_review_required',?)",
                ("1" if review_required else "0",),
            )
            connection.commit()
        result["configuration_review_required"] = review_required
        staging.chmod(0o600)
        with staging.open("rb") as stream:
            os.fsync(stream.fileno())
        displaced.mkdir(mode=0o700)
        for path in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm")):
            if path.exists():
                path.replace(displaced / path.name)
        staging.replace(database)
        private_json(
            journal,
            {
                "phase": "installed",
                "backup": str(backup),
                "displaced": str(displaced),
                "rescue": str(rescue.path) if rescue else None,
            },
        )
        result.update(
            applied=True, rescue=str(rescue.path) if rescue else None, displaced=str(displaced)
        )
        journal.unlink()
        return result
    except BaseException:
        # The journal and private original remain available for an explicit recovery.
        raise


def recover_restore(database: Path) -> dict[str, str]:
    """Roll an interrupted restore back to its verified rescue, under the home lock."""
    journal = database.parent / "restore-journal.json"
    if journal.is_symlink():
        raise OSError("Restore journal must not be a link")
    data = json.loads(journal.read_text())
    rescue = data.get("rescue")
    path = Path(rescue or data["backup"])
    verify_backup(path)
    staging = database.parent / f".recover-{uuid4().hex}.db"
    with (
        closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)) as source,
        closing(sqlite3.connect(staging)) as target,
    ):
        source.backup(target)
        target.execute(
            "INSERT OR REPLACE INTO schema_meta VALUES('restore_generation',?)", (uuid4().hex,)
        )
        target.execute("INSERT OR REPLACE INTO schema_meta VALUES('restore_review_required','1')")
        target.commit()
    staging.chmod(0o600)
    with staging.open("rb") as stream:
        os.fsync(stream.fileno())
    for sidecar in (Path(str(database) + "-wal"), Path(str(database) + "-shm")):
        sidecar.unlink(missing_ok=True)
    staging.replace(database)
    journal.unlink()
    return {"restored_rescue" if rescue else "restored_backup": str(path)}


def require_reviewed_restore(database: Path) -> None:
    if not database.exists():
        return
    with closing(
        sqlite3.connect(f"{database.absolute().as_uri()}?mode=ro", uri=True)
    ) as connection:
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key='restore_review_required'"
        ).fetchone()
    if row == ("1",):
        raise RuntimeError(
            "Restored evidence used different settings. Review "
            "config.toml, then run db acknowledge-restore before "
            "collecting."
        )


def acknowledge_restore(database: Path) -> None:
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "INSERT OR REPLACE INTO schema_meta VALUES('restore_review_required','0')"
        )
