"""Sequential SQLite upgrades and private, consistent recovery snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncConnection

from . import __version__

SCHEMA_VERSION = 4


@dataclass(frozen=True, slots=True)
class MigrationBackup:
    path: Path
    manifest: Path
    sha256: str


def recovery_backup(database: Path, version: int) -> MigrationBackup:
    """Use SQLite's backup API, including committed WAL pages, before any DDL.

    The caller holds the writer lock and an IMMEDIATE transaction. Backup uses
    a separate read-only connection so it does not wait on its own write lock.
    """
    directory = database.parent / "backups"
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
        raise RuntimeError("Migration backup directory must be a real directory")
    directory.chmod(0o700)
    size = database.stat().st_size
    wal = Path(f"{database}-wal")
    if wal.exists():
        size += wal.stat().st_size
    if shutil.disk_usage(directory).free < 2 * size + 1024 * 1024:
        raise RuntimeError("Not enough disk space for a verified migration backup")
    name = f"schema-v{version}-{uuid4().hex}.db"
    destination = directory / name
    manifest = destination.with_suffix(".json")
    descriptor, temporary = tempfile.mkstemp(prefix=".migration-", dir=directory)
    os.close(descriptor)
    staging = Path(temporary)
    try:
        with (
            closing(sqlite3.connect(f"{database.absolute().as_uri()}?mode=ro", uri=True)) as source,
            closing(sqlite3.connect(staging)) as target,
        ):
            source.backup(target, pages=256)
            if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise RuntimeError("Migration backup failed integrity verification")
            if target.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("Migration backup has broken foreign keys")
            actual = target.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if actual != (str(version),):
                raise RuntimeError("Database version changed while making migration backup")
        with staging.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            os.fsync(stream.fileno())
        staging.replace(destination)
        payload = {
            "manifest_version": 1,
            "app_version": __version__,
            "schema_version": version,
            "created_at": datetime.now(UTC).isoformat(),
            "database": name,
            "sha256": digest,
            "includes_private_evidence": True,
            "includes_api_key_file": False,
        }
        # Exclusive creation prevents an existing file or symlink being overwritten.
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return MigrationBackup(destination, manifest, digest)
    finally:
        staging.unlink(missing_ok=True)


async def migrate_v1_to_v2(connection: AsyncConnection) -> None:
    """Add observation provenance without inventing historical measurements."""
    columns = (
        "ingest_seq INTEGER",
        "ingested_at VARCHAR(40)",
        "source_at VARCHAR(40)",
        "source_key VARCHAR(200)",
        "outcome VARCHAR(20) NOT NULL DEFAULT 'unknown'",
        "observed_quality VARCHAR(30) NOT NULL DEFAULT 'legacy_unknown'",
        "ingest_order_origin VARCHAR(30) NOT NULL DEFAULT 'legacy_reconstructed'",
    )
    for column in columns:
        await connection.exec_driver_sql(f"ALTER TABLE events ADD COLUMN {column}")
    await connection.exec_driver_sql(
        "WITH ordered AS (SELECT id, ROW_NUMBER() OVER (ORDER BY observed_at, id) AS seq "
        "FROM events) UPDATE events SET ingest_seq = "
        "(SELECT seq FROM ordered WHERE ordered.id = events.id)"
    )
    for operation in ("INSERT", "UPDATE OF ingest_seq"):
        trigger_name = "insert" if operation == "INSERT" else "update"
        await connection.exec_driver_sql(
            f"CREATE TRIGGER events_require_sequence_{trigger_name} BEFORE {operation} ON events "
            "WHEN NEW.ingest_seq IS NULL OR NEW.ingest_seq <= 0 BEGIN "
            "SELECT RAISE(ABORT, 'ingest_seq must be positive'); END"
        )
    await connection.exec_driver_sql(
        "CREATE UNIQUE INDEX ix_events_ingest_seq ON events (ingest_seq)"
    )
    await connection.exec_driver_sql(
        "CREATE UNIQUE INDEX ix_events_source_key ON events (source_key)"
    )
    await connection.exec_driver_sql(
        "INSERT INTO schema_meta(key, value) "
        "SELECT 'ingest_sequence', CAST(COUNT(*) AS TEXT) FROM events"
    )

    # Keep historical migration DDL independent of later ORM model changes.
    tables = (
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, "
        "applied_at VARCHAR(40) NOT NULL, backup_path TEXT NOT NULL, "
        "backup_sha256 VARCHAR(64) NOT NULL)",
        "CREATE TABLE probe_checkpoints (probe_id VARCHAR(200) PRIMARY KEY NOT NULL, "
        "revision INTEGER NOT NULL, state_json TEXT NOT NULL, committed_seq INTEGER NOT NULL, "
        "updated_at VARCHAR(40) NOT NULL)",
        "CREATE TABLE ingest_batches (batch_id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "payload_hash VARCHAR(64) NOT NULL, committed_seq INTEGER NOT NULL, "
        "committed_at VARCHAR(40) NOT NULL)",
        "CREATE TABLE ingest_gaps (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "probe_id VARCHAR(200) NOT NULL, gap_json TEXT NOT NULL, committed_seq INTEGER NOT NULL)",
        "CREATE INDEX ix_ingest_gaps_probe_id ON ingest_gaps (probe_id)",
        "CREATE TABLE probe_health (probe_id VARCHAR(300) PRIMARY KEY NOT NULL, "
        "health_json TEXT NOT NULL)",
        "CREATE TABLE health_transitions (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "probe_id VARCHAR(300) NOT NULL, recorded_at VARCHAR(40) NOT NULL, "
        "health_json TEXT NOT NULL)",
        "CREATE INDEX ix_health_transitions_probe_id ON health_transitions (probe_id)",
    )
    for statement in tables:
        await connection.exec_driver_sql(statement)


async def migrate_v2_to_v3(connection: AsyncConnection) -> None:
    """Preserve historical unknown rule provenance; never rescore existing events."""
    await connection.exec_driver_sql(
        "CREATE TABLE rule_versions (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "applied_at VARCHAR(40) NOT NULL, snapshot_json TEXT NOT NULL, "
        "fingerprint VARCHAR(64) NOT NULL)"
    )
    await connection.exec_driver_sql(
        "ALTER TABLE events ADD COLUMN rule_version VARCHAR(36) REFERENCES rule_versions(id)"
    )
    await connection.exec_driver_sql(
        "CREATE INDEX ix_events_correlation ON events (rule_version, source, ingested_at)"
    )


async def migrate_v3_to_v4(connection: AsyncConnection) -> None:
    """Add operational incident history without rewriting or regrouping old observations."""
    statements = (
        "CREATE TABLE incidents (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "correlation_key VARCHAR(2000) NOT NULL, status VARCHAR(20) NOT NULL, "
        "first_seen_at VARCHAR(40) NOT NULL, last_seen_at VARCHAR(40) NOT NULL, "
        "revision INTEGER NOT NULL, "
        "rule_version VARCHAR(36) NOT NULL REFERENCES rule_versions(id), data_json TEXT NOT NULL)",
        "CREATE INDEX ix_incidents_key_seen ON incidents(correlation_key, last_seen_at)",
        "CREATE TABLE incident_occurrences (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "incident_id VARCHAR(36) NOT NULL REFERENCES incidents(id), number INTEGER NOT NULL, "
        "started_at VARCHAR(40) NOT NULL, data_json TEXT NOT NULL, UNIQUE(incident_id, number))",
        "CREATE TABLE incident_events (incident_id VARCHAR(36) NOT NULL REFERENCES incidents(id), "
        "event_id VARCHAR(36) NOT NULL REFERENCES events(id) ON DELETE RESTRICT, "
        "occurrence_id VARCHAR(36) NOT NULL REFERENCES incident_occurrences(id), "
        "data_json TEXT NOT NULL, PRIMARY KEY(incident_id, event_id))",
        "CREATE TABLE incident_transitions (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "incident_id VARCHAR(36) NOT NULL REFERENCES incidents(id), revision INTEGER NOT NULL, "
        "data_json TEXT NOT NULL, UNIQUE(incident_id, revision))",
        "CREATE TABLE incident_notes (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "incident_id VARCHAR(36) NOT NULL REFERENCES incidents(id), "
        "supersedes_id VARCHAR(36) UNIQUE REFERENCES incident_notes(id), "
        "at VARCHAR(40) NOT NULL, data_json TEXT NOT NULL)",
        "CREATE INDEX ix_incident_notes_incident_id ON incident_notes(incident_id)",
        "CREATE TABLE suppression_rules (id VARCHAR(36) PRIMARY KEY NOT NULL, "
        "enabled BOOLEAN NOT NULL, starts_at VARCHAR(40) NOT NULL, "
        "expires_at VARCHAR(40) NOT NULL, data_json TEXT NOT NULL)",
        "CREATE TABLE event_suppressions (event_id VARCHAR(36) NOT NULL "
        "REFERENCES events(id) ON DELETE RESTRICT, suppression_id VARCHAR(36) NOT NULL "
        "REFERENCES suppression_rules(id), family VARCHAR(30) NOT NULL, "
        "data_json TEXT NOT NULL, PRIMARY KEY(event_id, suppression_id, family))",
    )
    for statement in statements:
        await connection.exec_driver_sql(statement)
