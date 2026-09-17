"""Async SQLite persistence for events, investigations, responses, and runs."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    case,
    event,
    func,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL, CursorResult
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql.elements import ColumnElement

from .collection import (
    CheckpointChange,
    IngestGap,
    LogCheckpointState,
    PortBaselineState,
    ProbeBatch,
)
from .db import Base
from .detection import Detector
from .domain import (
    Assessment,
    DetectionResult,
    DetectionSignal,
    EventSource,
    InvestigationResult,
    InvestigationState,
    ModelUsage,
    ObservationOutcome,
    ResponseProposal,
    SecurityEvent,
    Severity,
    utc_now,
)
from .health import ProbeHealth
from .incident_store import (
    IncidentLinkRow,
    IncidentStore,
    project_observation,
    read_history,
    validate_incidents,
)
from .incidents import IncidentHistory, IncidentLink
from .migrations import (
    SCHEMA_VERSION,
    migrate_v1_to_v2,
    migrate_v2_to_v3,
    migrate_v3_to_v4,
    recovery_backup,
)
from .rules import RuleConfig, RuleVersion

_EVIDENCE_MAX_BYTES = 32 * 1024
_INVESTIGATION_ERROR_MAX_LENGTH = 4000
_ERROR_TRUNCATION_MARKER = "\n[truncated]"
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


class SchemaMetaRow(Base):
    __tablename__ = "schema_meta"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(String(200), nullable=False)


class ProbeCheckpointRow(Base):
    __tablename__ = "probe_checkpoints"

    probe_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    state_json: Mapped[str] = mapped_column(Text, nullable=False)
    committed_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class IngestBatchRow(Base):
    __tablename__ = "ingest_batches"

    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    committed_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    committed_at: Mapped[str] = mapped_column(String(40), nullable=False)


class IngestGapRow(Base):
    __tablename__ = "ingest_gaps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    probe_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    gap_json: Mapped[str] = mapped_column(Text, nullable=False)
    committed_seq: Mapped[int] = mapped_column(Integer, nullable=False)


class MigrationRow(Base):
    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[str] = mapped_column(String(40), nullable=False)
    backup_path: Mapped[str] = mapped_column(Text, nullable=False)
    backup_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class ProbeHealthRow(Base):
    __tablename__ = "probe_health"

    probe_id: Mapped[str] = mapped_column(String(300), primary_key=True)
    health_json: Mapped[str] = mapped_column(Text, nullable=False)


class HealthTransitionRow(Base):
    __tablename__ = "health_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    probe_id: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    recorded_at: Mapped[str] = mapped_column(String(40), nullable=False)
    health_json: Mapped[str] = mapped_column(Text, nullable=False)


class RuleVersionRow(Base):
    __tablename__ = "rule_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    applied_at: Mapped[str] = mapped_column(String(40), nullable=False)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint("ingest_seq > 0", name="ck_events_ingest_seq_positive"),
        Index("ix_events_observed_at", "observed_at"),
        Index("ix_events_severity", "severity"),
        Index("ix_events_source", "source"),
        Index("ix_events_target", "target"),
        Index("ix_events_ingest_seq", "ingest_seq", unique=True),
        Index("ix_events_source_key", "source_key", unique=True),
        Index("ix_events_correlation", "rule_version", "source", "ingested_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observed_at: Mapped[str] = mapped_column(String(40), nullable=False)
    ingest_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ingested_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rule_version: Mapped[str | None] = mapped_column(ForeignKey("rule_versions.id"), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    observed_quality: Mapped[str] = mapped_column(String(30), nullable=False, default="recorded")
    ingest_order_origin: Mapped[str] = mapped_column(String(30), nullable=False, default="recorded")
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str | None] = mapped_column(String(253), nullable=True)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    signals_json: Mapped[str] = mapped_column(Text, nullable=False)
    investigation_state: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class InvestigationRow(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_event_id", "event_id"),
        Index("ix_investigations_status", "status"),
        Index("ix_investigations_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    assessment_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    usage_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_id: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_effort: Mapped[str] = mapped_column(String(20), nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class ResponseProposalRow(Base):
    __tablename__ = "response_proposals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=False,
    )
    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    proposal_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class RunRow(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    stopped_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    clean_shutdown: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class EventQuery(BaseModel):
    """Validated event history filters."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    severity: Severity | None = None
    severities: tuple[Severity, ...] = ()
    source: EventSource | None = None
    target: str | None = Field(default=None, min_length=1, max_length=253)
    text: str | None = Field(default=None, min_length=1, max_length=200)
    after: datetime | None = None
    before: datetime | None = None
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)

    @field_validator("after", "before")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("query timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_window(self) -> EventQuery:
        if self.after is not None and self.before is not None and self.after > self.before:
            raise ValueError("after must not be later than before")
        return self


class StoredEvent(SecurityEvent):
    """A persisted event with explainable detection signals."""

    signals: tuple[DetectionSignal, ...] = ()
    ingest_seq: int | None = Field(default=None, ge=1)
    ingest_order_origin: Literal["recorded", "legacy_reconstructed"] = "recorded"


class RelatedObservation(BaseModel):
    model_config = ConfigDict(frozen=True)
    event: StoredEvent
    link: IncidentLink


class RelatedPage(BaseModel):
    model_config = ConfigDict(frozen=True)
    items: tuple[RelatedObservation, ...]
    watermark: int
    next_before: int | None
    has_more: bool


class IncidentReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    history: IncidentHistory
    observations: tuple[StoredEvent, ...]


InvestigationStatus = Literal["queued", "running", "complete", "failed"]
ResponseStatus = Literal["pending", "approved", "rejected"]
StoredResponseStatus = Literal[
    "pending",
    "simulated",
    "approved",
    "executed",
    "rejected",
]


class StoredInvestigation(BaseModel):
    """A durable model investigation at any lifecycle stage."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    id: UUID
    event_id: UUID
    status: InvestigationStatus
    assessment: Assessment | None = None
    usage: ModelUsage | None = None
    model_id: str = Field(min_length=1, max_length=200)
    requested_effort: str = Field(min_length=1, max_length=20)
    error: str | None = Field(default=None, min_length=1, max_length=4000)
    created_at: datetime
    completed_at: datetime | None = None

    @field_validator("created_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("investigation timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_outcome(self) -> StoredInvestigation:
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completed_at must not be earlier than created_at")
        if self.status in {"queued", "running"}:
            if any(
                value is not None
                for value in (self.assessment, self.usage, self.error, self.completed_at)
            ):
                raise ValueError("active investigations cannot have an outcome")
        elif self.status == "complete":
            if self.completed_at is None:
                raise ValueError("complete investigations require a completion timestamp")
            if self.assessment is None or self.usage is None or self.error is not None:
                raise ValueError("complete investigations require assessment and usage only")
        else:
            if self.completed_at is None:
                raise ValueError("failed investigations require a completion timestamp")
            if self.assessment is not None or self.usage is not None or self.error is None:
                raise ValueError("failed investigations require an error only")
        return self


class SessionStats(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    total_events: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    completed_investigations: int = 0
    failed_investigations: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0


class StoredResponseProposal(BaseModel):
    """A durable response waiting for explicit operator review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    event_id: UUID
    investigation_id: UUID
    proposal: ResponseProposal
    status: StoredResponseStatus
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("response proposal timestamps must include a timezone")
        return value.astimezone(UTC)


class StoredRun(BaseModel):
    """One application process lifetime and its shutdown outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    id: UUID
    started_at: datetime
    stopped_at: datetime | None = None
    version: str = Field(min_length=1, max_length=40)
    clean_shutdown: bool = False

    @field_validator("started_at", "stopped_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("run timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> StoredRun:
        if self.stopped_at is not None and self.stopped_at < self.started_at:
            raise ValueError("stopped_at must not be earlier than started_at")
        if self.clean_shutdown and self.stopped_at is None:
            raise ValueError("a clean shutdown requires a stop timestamp")
        return self


class DatabaseInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    journal_mode: str
    foreign_keys: bool


class Repository:
    """Method-scoped async persistence with detached typed results."""

    def __init__(self, database_path: Path, *, read_only: bool = False) -> None:
        self.database_path = Path(database_path)
        self.read_only = read_only
        url = URL.create(
            "sqlite+aiosqlite",
            database=self.database_path.absolute().as_uri()
            if read_only
            else str(self.database_path),
            query={"mode": "ro", "uri": "true"} if read_only else {},
        )
        self._engine: AsyncEngine = create_async_engine(
            url,
            echo=False,
        )
        self._sessions = async_sessionmaker(self._engine, expire_on_commit=False)
        self.incidents = IncidentStore(self._sessions)
        event.listen(self._engine.sync_engine, "connect", _configure_sqlite)

    async def initialize(self) -> None:
        """Initialize a new home or migrate existing data under the owner's lock."""
        if self.read_only:
            raise RuntimeError("Cannot initialize or migrate a read-only repository")
        _validate_database_files(self.database_path)
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_database_files(self.database_path)
        async with self._engine.connect() as connection:
            # Inspect before setting WAL or changing permissions on an unknown schema.
            version = await self._schema_version(connection)
            if version is not None and (version < 1 or version > SCHEMA_VERSION):
                raise RuntimeError(f"Unsupported SocketClaw schema version {version}")
            await connection.commit()
            await _enable_wal(connection)
            await connection.commit()
            await connection.exec_driver_sql("BEGIN IMMEDIATE")
            backup = None
            try:
                version = await self._schema_version(connection)
                if version is None:
                    await connection.run_sync(Base.metadata.create_all)
                    await connection.execute(
                        sqlite_insert(SchemaMetaRow),
                        [
                            {"key": "schema_version", "value": str(SCHEMA_VERSION)},
                            {"key": "ingest_sequence", "value": "0"},
                        ],
                    )
                elif version < SCHEMA_VERSION:
                    worker = asyncio.create_task(
                        asyncio.to_thread(recovery_backup, self.database_path, version)
                    )
                    try:
                        backup = await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        await worker
                        raise
                    before = await self._historical_counts(connection)
                    for destination in range(version + 1, SCHEMA_VERSION + 1):
                        migration = {2: migrate_v1_to_v2, 3: migrate_v2_to_v3, 4: migrate_v3_to_v4}[
                            destination
                        ]
                        await migration(connection)
                        await connection.execute(
                            sqlite_insert(MigrationRow).values(
                                version=destination,
                                applied_at=_timestamp(utc_now()),
                                backup_path=str(backup.path),
                                backup_sha256=backup.sha256,
                            )
                        )
                    await connection.execute(
                        update(SchemaMetaRow)
                        .where(SchemaMetaRow.key == "schema_version")
                        .values(value=str(SCHEMA_VERSION))
                    )
                    await self._validate_domain_rows(connection)
                    if await self._historical_counts(connection) != before:
                        raise RuntimeError("Migration changed historical row counts")
                    if (await connection.exec_driver_sql("PRAGMA foreign_key_check")).all():
                        raise RuntimeError("Migration failed foreign key validation")
                    if (await connection.exec_driver_sql("PRAGMA quick_check")).scalars().all() != [
                        "ok"
                    ]:
                        raise RuntimeError("Migration failed integrity validation")
                elif version != SCHEMA_VERSION:
                    raise RuntimeError(f"Unsupported SocketClaw schema version {version}")
                await connection.commit()
            except BaseException as exc:
                await connection.rollback()
                if isinstance(exc, Exception) and backup is not None:
                    raise RuntimeError(
                        f"Migration rolled back. Recovery backup: {backup.path}. {exc}"
                    ) from exc
                raise
        try:
            os.chmod(self.database_path, 0o600)
        except OSError as exc:
            raise RuntimeError("Cannot secure the SocketClaw database file") from exc

    async def _schema_version(self, connection: AsyncConnection) -> int | None:
        names = await connection.run_sync(lambda sync: inspect(sync).get_table_names())
        if not names:
            return None
        if "schema_meta" not in names:
            raise RuntimeError("SocketClaw database has tables but no schema metadata")
        value = (
            await connection.execute(
                select(SchemaMetaRow.value).where(SchemaMetaRow.key == "schema_version")
            )
        ).scalar_one_or_none()
        if value is None:
            raise RuntimeError("SocketClaw database has no schema version")
        try:
            return int(value)
        except ValueError as exc:
            raise RuntimeError(f"Invalid SocketClaw schema version {value!r}") from exc

    async def _historical_counts(self, connection: AsyncConnection) -> tuple[int, ...]:
        return tuple(
            [
                int(
                    (await connection.execute(select(func.count()).select_from(table))).scalar_one()
                )
                for table in (EventRow, InvestigationRow, ResponseProposalRow, RunRow)
            ]
        )

    async def require_current_schema(self) -> None:
        """Read-only compatibility check; never initialize, migrate, or recover work."""
        _validate_database_files(self.database_path)
        if not self.database_path.exists():
            raise FileNotFoundError("SocketClaw database has not been created")
        async with self._engine.connect() as connection:
            version = await self._schema_version(connection)
        _require_schema_version(str(version) if version is not None else None)

    async def close(self) -> None:
        await self._engine.dispose()

    async def database_info(self) -> DatabaseInfo:
        await self.require_current_schema()
        async with self._engine.connect() as connection:
            journal_mode = (await connection.exec_driver_sql("PRAGMA journal_mode")).scalar_one()
            foreign_keys = (await connection.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
            integrity_values = (
                (await connection.exec_driver_sql("PRAGMA quick_check")).scalars().all()
            )
            if (await connection.exec_driver_sql("PRAGMA foreign_key_check")).all():
                raise RuntimeError("SocketClaw database failed foreign key validation")
            if [str(value) for value in integrity_values] != ["ok"]:
                raise RuntimeError("SocketClaw database failed SQLite quick_check")
        async with self._sessions() as session:
            schema = await session.get(SchemaMetaRow, "schema_version")
        if schema is None:
            raise RuntimeError("SocketClaw database has not been initialized")
        _require_schema_version(schema.value)
        await self._validate_domain_rows()
        return DatabaseInfo(
            schema_version=int(schema.value),
            journal_mode=str(journal_mode).lower(),
            foreign_keys=bool(foreign_keys),
        )

    async def _validate_domain_rows(self, connection: AsyncConnection | None = None) -> None:
        """Stream every persisted record through its safe domain decoder."""
        sessions = (
            async_sessionmaker(connection, expire_on_commit=False) if connection else self._sessions
        )
        async with sessions() as session:
            try:
                await validate_incidents(session)
            except Exception as exc:
                raise RuntimeError("SocketClaw database has invalid incident history") from exc
            counter = await session.get(SchemaMetaRow, "ingest_sequence")
            maximum = await session.scalar(select(func.max(EventRow.ingest_seq)))
            if (
                counter is None
                or not counter.value.isdecimal()
                or int(counter.value) < (maximum or 0)
            ):
                raise RuntimeError("SocketClaw database has an invalid ingestion watermark")
            checkpoints = await session.stream_scalars(select(ProbeCheckpointRow))
            async for checkpoint in checkpoints:
                try:
                    if checkpoint.revision < 1 or not 0 <= checkpoint.committed_seq <= int(
                        counter.value
                    ):
                        raise ValueError("invalid checkpoint revision or sequence")
                    _parse_timestamp(checkpoint.updated_at)
                    if checkpoint.probe_id.startswith("log:"):
                        LogCheckpointState.model_validate_json(checkpoint.state_json)
                    elif checkpoint.probe_id.startswith("ports:"):
                        PortBaselineState.model_validate_json(checkpoint.state_json)
                except Exception as exc:
                    raise RuntimeError(
                        "SocketClaw database has an invalid collector checkpoint"
                    ) from exc
            gaps = await session.stream_scalars(select(IngestGapRow))
            async for gap in gaps:
                try:
                    decoded = IngestGap.model_validate_json(gap.gap_json)
                    if str(decoded.id) != gap.id or decoded.probe_id != gap.probe_id:
                        raise ValueError("gap identity mismatch")
                    if not 0 <= gap.committed_seq <= int(counter.value):
                        raise ValueError("gap sequence exceeds ingestion watermark")
                except Exception as exc:
                    raise RuntimeError("SocketClaw database has an invalid ingestion gap") from exc
            health_rows = await session.stream_scalars(select(ProbeHealthRow))
            async for health in health_rows:
                try:
                    decoded_health = ProbeHealth.model_validate_json(health.health_json)
                    if decoded_health.probe_id != health.probe_id:
                        raise ValueError("health identity mismatch")
                except Exception as exc:
                    raise RuntimeError(
                        "SocketClaw database has an invalid probe health record"
                    ) from exc
            versions = await session.stream_scalars(select(RuleVersionRow))
            async for version in versions:
                try:
                    _rule_version(version)
                except Exception as exc:
                    raise RuntimeError("SocketClaw database has an invalid rule version") from exc
            active = await session.get(SchemaMetaRow, "active_rule_version")
            if active is not None and await session.get(RuleVersionRow, active.value) is None:
                raise RuntimeError("Active rule version is missing")
            event_rows = await session.stream_scalars(select(EventRow))
            async for row in event_rows:
                try:
                    _stored_event(row)
                except Exception as exc:
                    raise RuntimeError("SocketClaw database has an invalid event record") from exc

            investigation_rows = await session.stream_scalars(select(InvestigationRow))
            async for row in investigation_rows:
                try:
                    _stored_investigation(row)
                except Exception as exc:
                    raise RuntimeError(
                        "SocketClaw database has an invalid investigation record"
                    ) from exc

            proposal_rows = await session.stream_scalars(select(ResponseProposalRow))
            async for row in proposal_rows:
                try:
                    _stored_response_proposal(row)
                except Exception as exc:
                    raise RuntimeError(
                        "SocketClaw database has an invalid response proposal record"
                    ) from exc

            run_rows = await session.stream_scalars(select(RunRow))
            async for row in run_rows:
                try:
                    _stored_run(row)
                except Exception as exc:
                    raise RuntimeError("SocketClaw database has an invalid run record") from exc

    async def save_event(
        self,
        security_event: SecurityEvent,
        detection: DetectionResult,
    ) -> StoredEvent:
        row = _event_row(security_event, detection)
        async with self._sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            counter = await session.get(SchemaMetaRow, "ingest_sequence")
            if counter is None or not counter.value.isdecimal():
                raise RuntimeError("Missing or invalid ingest sequence counter")
            row.ingest_seq = int(counter.value) + 1
            counter.value = str(row.ingest_seq)
            session.add(row)
            await session.commit()
        return _stored_event(row)

    async def load_checkpoint(self, probe_id: str) -> CheckpointChange:
        async with self._sessions() as session:
            row = await session.get(ProbeCheckpointRow, probe_id)
            if row is None:
                return CheckpointChange(probe_id=probe_id, expected_revision=0, state={})
            return CheckpointChange(
                probe_id=probe_id,
                expected_revision=row.revision,
                state=json.loads(row.state_json),
            )

    async def save_probe_health(self, health: ProbeHealth) -> None:
        """Replace the projection and audit meaningful state transitions together."""
        async with self._sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            previous = await session.get(ProbeHealthRow, health.probe_id)
            previous_health = (
                ProbeHealth.model_validate_json(previous.health_json) if previous else None
            )
            payload = health.model_dump_json()
            if previous_health is None or (
                previous_health.state,
                previous_health.error_kind,
                previous_health.error,
            ) != (health.state, health.error_kind, health.error):
                session.add(
                    HealthTransitionRow(
                        id=str(uuid4()),
                        probe_id=health.probe_id,
                        recorded_at=_timestamp(health.updated_at),
                        health_json=payload,
                    )
                )
            await session.merge(ProbeHealthRow(probe_id=health.probe_id, health_json=payload))
            await session.commit()

    async def list_probe_health(self, probe_ids: Collection[str]) -> list[ProbeHealth]:
        if not probe_ids:
            return []
        async with self._sessions() as session:
            rows = await session.scalars(
                select(ProbeHealthRow).where(ProbeHealthRow.probe_id.in_(probe_ids))
            )
            return [ProbeHealth.model_validate_json(row.health_json) for row in rows]

    async def list_health_transitions(self, probe_id: str, *, limit: int = 50) -> list[ProbeHealth]:
        if not 1 <= limit <= 1000:
            raise ValueError("health history limit must be between 1 and 1000")
        async with self._sessions() as session:
            rows = await session.scalars(
                select(HealthTransitionRow)
                .where(HealthTransitionRow.probe_id == probe_id)
                .order_by(HealthTransitionRow.recorded_at.desc(), HealthTransitionRow.id)
                .limit(limit)
            )
            return [ProbeHealth.model_validate_json(row.health_json) for row in rows]

    async def list_ingest_gaps(self, probe_id: str, *, limit: int = 100) -> list[IngestGap]:
        if not 1 <= limit <= 1000:
            raise ValueError("gap query limit must be between 1 and 1000")
        async with self._sessions() as session:
            rows = await session.scalars(
                select(IngestGapRow)
                .where(IngestGapRow.probe_id == probe_id)
                .order_by(IngestGapRow.committed_seq.desc(), IngestGapRow.id)
                .limit(limit)
            )
            return [IngestGap.model_validate_json(row.gap_json) for row in rows]

    async def _activate_rules(self, session: AsyncSession, config: RuleConfig) -> UUID:
        active = await session.get(SchemaMetaRow, "active_rule_version")
        if active is not None:
            row = await session.get(RuleVersionRow, active.value)
            if row is None:
                raise RuntimeError("Active rule version is missing")
            version = _rule_version(row)
            if version.fingerprint == config.fingerprint:
                return version.id
        identifier = uuid4()
        session.add(
            RuleVersionRow(
                id=str(identifier),
                applied_at=_timestamp(utc_now()),
                snapshot_json=config.snapshot(),
                fingerprint=config.fingerprint,
            )
        )
        await session.flush()
        await session.merge(SchemaMetaRow(key="active_rule_version", value=str(identifier)))
        await session.flush()
        return identifier

    async def get_rule_version(self, identifier: UUID) -> RuleVersion | None:
        async with self._sessions() as session:
            row = await session.get(RuleVersionRow, str(identifier))
            return _rule_version(row) if row else None

    async def ingest_batch(self, batch: ProbeBatch, detector: Detector) -> list[StoredEvent]:
        """Commit observations, deduplication receipt, and cursors together.

        A repeated receipt returns no new events. Failed or canceled transactions
        leave both the observation sequence and collector checkpoints untouched.
        """
        if not batch.observations and not batch.checkpoints and not batch.gaps:
            return []
        payload_hash = hashlib.sha256(batch.model_dump_json().encode()).hexdigest()
        stored: list[StoredEvent] = []
        async with self._sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            receipt = await session.get(IngestBatchRow, str(batch.batch_id))
            if receipt is not None:
                if receipt.payload_hash != payload_hash:
                    raise ValueError("Batch ID was reused with different content")
                return []
            for candidate in batch.checkpoints:
                checkpoint = await session.get(ProbeCheckpointRow, candidate.probe_id)
                actual_revision = checkpoint.revision if checkpoint is not None else 0
                if actual_revision != candidate.expected_revision:
                    raise ValueError("Collector checkpoint changed before this batch committed")
            counter = await session.get(SchemaMetaRow, "ingest_sequence")
            if counter is None or not counter.value.isdecimal():
                raise RuntimeError("Missing or invalid ingest sequence counter")
            rule_version: UUID | None = None
            for observation in batch.observations:
                if observation.source_key is not None:
                    existing = (
                        await session.execute(
                            select(EventRow.id).where(EventRow.source_key == observation.source_key)
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        continue
                if rule_version is None:
                    rule_version = await self._activate_rules(session, detector.config)
                observation = observation.model_copy(
                    update={
                        "ingested_at": batch.collected_at,
                        "rule_version": rule_version,
                    }
                )
                recent = await self.correlation_history(
                    observation, detector.window, session=session
                )
                detection = detector.score(observation, recent)
                row = _event_row(observation, detection)
                row.ingest_seq = int(counter.value) + 1
                counter.value = str(row.ingest_seq)
                session.add(row)
                await session.flush()
                await project_observation(session, observation, detection, detector.config)
                stored.append(_stored_event(row))
            for candidate in batch.checkpoints:
                state_json = json.dumps(candidate.state, separators=(",", ":"), allow_nan=False)
                if len(state_json.encode()) > 64 * 1024:
                    raise ValueError("Collector checkpoint exceeds 64 KiB")
                await session.merge(
                    ProbeCheckpointRow(
                        probe_id=candidate.probe_id,
                        revision=candidate.expected_revision + 1,
                        state_json=state_json,
                        committed_seq=int(counter.value),
                        updated_at=_timestamp(utc_now()),
                    )
                )
            for gap in batch.gaps:
                session.add(
                    IngestGapRow(
                        id=str(gap.id),
                        probe_id=gap.probe_id,
                        gap_json=gap.model_dump_json(),
                        committed_seq=int(counter.value),
                    )
                )
            session.add(
                IngestBatchRow(
                    batch_id=str(batch.batch_id),
                    payload_hash=payload_hash,
                    committed_seq=int(counter.value),
                    committed_at=_timestamp(utc_now()),
                )
            )
            await session.commit()
        return stored

    async def incident_report(self, identifier: UUID) -> IncidentReport | None:
        async with self._sessions() as session:
            await session.execute(text("BEGIN"))
            history = await read_history(session, identifier)
            if history is None:
                return None
            rows = await session.scalars(
                select(EventRow)
                .join(IncidentLinkRow, IncidentLinkRow.event_id == EventRow.id)
                .where(IncidentLinkRow.incident_id == str(identifier))
                .order_by(EventRow.ingest_seq, EventRow.id)
            )
            return IncidentReport(
                history=history, observations=tuple(_stored_event(row) for row in rows)
            )

    async def incident_observations(
        self,
        identifier: UUID,
        *,
        watermark: int | None = None,
        before: int | None = None,
        limit: int = 100,
    ) -> RelatedPage:
        if not 1 <= limit <= 200:
            raise ValueError("Observation page size must be 1-200")
        async with self._sessions() as session:
            await session.execute(text("BEGIN"))
            if watermark is None:
                watermark = int(
                    await session.scalar(
                        select(func.max(EventRow.ingest_seq))
                        .join(IncidentLinkRow, IncidentLinkRow.event_id == EventRow.id)
                        .where(IncidentLinkRow.incident_id == str(identifier))
                    )
                    or 0
                )
            query = (
                select(EventRow, IncidentLinkRow)
                .join(IncidentLinkRow, IncidentLinkRow.event_id == EventRow.id)
                .where(
                    IncidentLinkRow.incident_id == str(identifier), EventRow.ingest_seq <= watermark
                )
            )
            if before is not None:
                query = query.where(EventRow.ingest_seq < before)
            rows = (
                await session.execute(query.order_by(EventRow.ingest_seq.desc()).limit(limit + 1))
            ).all()
            items = tuple(
                RelatedObservation(
                    event=_stored_event(event),
                    link=IncidentLink.model_validate_json(link.data_json),
                )
                for event, link in rows[:limit]
            )
            more = len(rows) > limit
            return RelatedPage(
                items=items,
                watermark=watermark,
                has_more=more,
                next_before=items[-1].event.ingest_seq if more else None,
            )

    async def get_event(self, event_id: UUID) -> StoredEvent | None:
        async with self._sessions() as session:
            row = await session.get(EventRow, str(event_id))
            return _stored_event(row) if row is not None else None

    async def list_events(
        self,
        query: EventQuery | None = None,
    ) -> list[StoredEvent]:
        filters = query or EventQuery()
        statement = select(EventRow)
        if filters.severity is not None:
            statement = statement.where(EventRow.severity == filters.severity.value)
        if filters.severities:
            statement = statement.where(
                EventRow.severity.in_([severity.value for severity in filters.severities])
            )
        if filters.source is not None:
            statement = statement.where(EventRow.source == filters.source.value)
        if filters.target is not None:
            statement = statement.where(EventRow.target == filters.target)
        if filters.text:
            escaped_text = (
                filters.text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            pattern = f"%{escaped_text}%"
            statement = statement.where(
                or_(
                    func.lower(EventRow.title).like(pattern, escape="\\"),
                    func.lower(EventRow.summary).like(pattern, escape="\\"),
                    func.lower(func.coalesce(EventRow.target, "")).like(
                        pattern,
                        escape="\\",
                    ),
                )
            )
        if filters.after is not None:
            statement = statement.where(EventRow.observed_at >= _timestamp(filters.after))
        if filters.before is not None:
            statement = statement.where(EventRow.observed_at <= _timestamp(filters.before))
        statement = (
            statement.order_by(EventRow.observed_at.desc(), EventRow.id.desc())
            .limit(filters.limit)
            .offset(filters.offset)
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_event(row) for row in rows]

    async def correlation_history(
        self, observation: SecurityEvent, window: timedelta, *, session: AsyncSession | None = None
    ) -> list[StoredEvent]:
        """Read the exact rule window independently of UI history limits.

        The monitor serializes this query with scoring and persistence under its
        ingest lock. Only committed observations contribute, including on restart.
        """
        if observation.ingested_at is None or observation.source not in {
            EventSource.PING,
            EventSource.LOG,
        }:
            return []
        statement = select(EventRow).where(
            EventRow.source == observation.source.value,
            EventRow.id != str(observation.id),
            EventRow.ingested_at >= _timestamp(observation.ingested_at - window),
            EventRow.ingested_at <= _timestamp(observation.ingested_at),
            EventRow.rule_version
            == (str(observation.rule_version) if observation.rule_version else None),
        )
        if observation.target is not None:
            statement = statement.where(func.lower(EventRow.target) == observation.target.lower())
        else:
            path = observation.evidence.get("path")
            if observation.source != EventSource.LOG or not isinstance(path, str) or not path:
                return []
            statement = statement.where(
                EventRow.target.is_(None),
                func.json_extract(EventRow.evidence_json, "$.path") == path,
            )
        if session is not None:
            rows = (await session.execute(statement)).scalars().all()
        else:
            async with self._sessions() as reader:
                rows = (await reader.execute(statement)).scalars().all()
        return [_stored_event(row) for row in rows]

    async def queue_investigation(
        self,
        event_id: UUID,
        *,
        model_id: str,
        requested_effort: str,
    ) -> StoredInvestigation:
        """Create durable queued work while preventing duplicate active work."""
        queued = StoredInvestigation(
            id=uuid4(),
            event_id=event_id,
            status="queued",
            model_id=model_id,
            requested_effort=requested_effort,
            created_at=utc_now(),
        )
        row = InvestigationRow(
            id=str(queued.id),
            event_id=str(event_id),
            status="queued",
            assessment_json=None,
            usage_json=None,
            model_id=queued.model_id,
            requested_effort=queued.requested_effort,
            error=None,
            created_at=_timestamp(queued.created_at),
            completed_at=None,
        )
        async with self._sessions() as session:
            result = await session.execute(
                update(EventRow)
                .where(
                    EventRow.id == str(event_id),
                    EventRow.investigation_state.not_in(
                        (InvestigationState.QUEUED.value, InvestigationState.RUNNING.value)
                    ),
                )
                .values(investigation_state=InvestigationState.QUEUED.value)
            )
            if _row_count(result) != 1:
                await session.rollback()
                event_row = await session.get(EventRow, str(event_id))
                if event_row is None:
                    raise KeyError(str(event_id))
                raise ValueError("event already has an active investigation")
            session.add(row)
            await session.commit()
        return _stored_investigation(row)

    async def start_investigation(self, investigation_id: UUID) -> StoredInvestigation:
        """Atomically move one queued investigation into provider execution."""
        async with self._sessions() as session:
            row = await session.get(InvestigationRow, str(investigation_id))
            if row is None:
                raise KeyError(str(investigation_id))
            if row.status != "queued":
                raise ValueError(f"investigation cannot start from {row.status}")
            event_id = row.event_id
        async with self._sessions() as session:
            investigation_result = await session.execute(
                update(InvestigationRow)
                .where(
                    InvestigationRow.id == str(investigation_id),
                    InvestigationRow.status == "queued",
                )
                .values(status="running")
            )
            event_result = await session.execute(
                update(EventRow)
                .where(
                    EventRow.id == event_id,
                    EventRow.investigation_state == InvestigationState.QUEUED.value,
                )
                .values(investigation_state=InvestigationState.RUNNING.value)
            )
            if _row_count(investigation_result) != 1 or _row_count(event_result) != 1:
                await session.rollback()
                raise ValueError("investigation state changed concurrently")
            await session.commit()
            updated = await session.get(InvestigationRow, str(investigation_id))
            if updated is None:
                raise RuntimeError("started investigation disappeared")
            return _stored_investigation(updated)

    async def complete_investigation(
        self,
        investigation_id: UUID,
        result: InvestigationResult,
    ) -> StoredInvestigation:
        """Atomically persist a running investigation result and proposal."""
        now = utc_now()
        async with self._sessions() as session:
            row = await session.get(InvestigationRow, str(investigation_id))
            if row is None:
                raise KeyError(str(investigation_id))
            if row.status != "running":
                raise ValueError(f"investigation cannot complete from {row.status}")
            if row.model_id != result.model_id or row.requested_effort != result.requested_effort:
                raise ValueError("investigation result does not match the queued model contract")
            event_id = row.event_id
            event_row = await session.get(EventRow, event_id)
            if event_row is None:
                raise RuntimeError("investigation event disappeared")
            _validate_proposal_target(
                result.assessment.response_proposal,
                event_row.target,
            )
        async with self._sessions() as session:
            investigation_result = await session.execute(
                update(InvestigationRow)
                .where(
                    InvestigationRow.id == str(investigation_id),
                    InvestigationRow.status == "running",
                )
                .values(
                    status="complete",
                    assessment_json=result.assessment.model_dump_json(),
                    usage_json=result.usage.model_dump_json(),
                    error=None,
                    completed_at=_timestamp(now),
                )
            )
            event_result = await session.execute(
                update(EventRow)
                .where(
                    EventRow.id == event_id,
                    EventRow.investigation_state == InvestigationState.RUNNING.value,
                )
                .values(investigation_state=InvestigationState.COMPLETE.value)
            )
            if _row_count(investigation_result) != 1 or _row_count(event_result) != 1:
                await session.rollback()
                raise ValueError("investigation state changed concurrently")
            if result.assessment.response_proposal is not None:
                session.add(
                    ResponseProposalRow(
                        id=str(uuid4()),
                        event_id=event_id,
                        investigation_id=str(investigation_id),
                        proposal_json=result.assessment.response_proposal.model_dump_json(),
                        status="pending",
                        created_at=_timestamp(now),
                    )
                )
            await session.commit()
            updated = await session.get(InvestigationRow, str(investigation_id))
            if updated is None:
                raise RuntimeError("completed investigation disappeared")
            return _stored_investigation(updated)

    async def fail_investigation(
        self,
        investigation_id: UUID,
        *,
        error: str,
    ) -> StoredInvestigation:
        """Atomically preserve a safe terminal error for queued or running work."""
        now = utc_now()
        normalized_error = _normalize_investigation_error(error)
        async with self._sessions() as session:
            row = await session.get(InvestigationRow, str(investigation_id))
            if row is None:
                raise KeyError(str(investigation_id))
            if row.status not in {"queued", "running"}:
                raise ValueError(f"investigation cannot fail from {row.status}")
            active_status = cast(Literal["queued", "running"], row.status)
            failed = StoredInvestigation(
                id=investigation_id,
                event_id=UUID(row.event_id),
                status="failed",
                model_id=row.model_id,
                requested_effort=row.requested_effort,
                error=normalized_error,
                created_at=_parse_timestamp(row.created_at),
                completed_at=now,
            )
            event_id = row.event_id
        async with self._sessions() as session:
            investigation_result = await session.execute(
                update(InvestigationRow)
                .where(
                    InvestigationRow.id == str(investigation_id),
                    InvestigationRow.status == active_status,
                )
                .values(
                    status="failed",
                    assessment_json=None,
                    usage_json=None,
                    error=failed.error,
                    completed_at=_timestamp(now),
                )
            )
            event_result = await session.execute(
                update(EventRow)
                .where(
                    EventRow.id == event_id,
                    EventRow.investigation_state == active_status,
                )
                .values(investigation_state=InvestigationState.FAILED.value)
            )
            if _row_count(investigation_result) != 1 or _row_count(event_result) != 1:
                await session.rollback()
                raise ValueError("investigation state changed concurrently")
            await session.commit()
            updated = await session.get(InvestigationRow, str(investigation_id))
            if updated is None:
                raise RuntimeError("failed investigation disappeared")
            return _stored_investigation(updated)

    async def recover_incomplete_investigations(self) -> int:
        """Mark work left active by a previous process as safely retryable."""
        now = utc_now()
        error = "SocketClaw stopped before the investigation completed"
        async with self._sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(InvestigationRow).where(
                            InvestigationRow.status.in_(("queued", "running"))
                        )
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                return 0
            investigation_ids = [row.id for row in rows]
            event_ids = list({row.event_id for row in rows})
            await session.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id.in_(investigation_ids))
                .values(
                    status="failed",
                    error=error,
                    completed_at=_timestamp(now),
                )
            )
            await session.execute(
                update(EventRow)
                .where(
                    EventRow.id.in_(event_ids),
                    EventRow.investigation_state.in_(
                        (InvestigationState.QUEUED.value, InvestigationState.RUNNING.value)
                    ),
                )
                .values(investigation_state=InvestigationState.FAILED.value)
            )
            await session.commit()
            return len(rows)

    async def list_investigations(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
    ) -> list[StoredInvestigation]:
        _validate_limit(limit, "investigation")
        statement = select(InvestigationRow)
        if event_id is not None:
            statement = statement.where(InvestigationRow.event_id == str(event_id))
        statement = statement.order_by(
            InvestigationRow.created_at.desc(),
            InvestigationRow.id.desc(),
        ).limit(limit)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_investigation(row) for row in rows]

    async def list_response_proposals(
        self,
        *,
        event_id: UUID | None = None,
        limit: int = 100,
    ) -> list[StoredResponseProposal]:
        _validate_limit(limit, "response proposal")
        statement = select(ResponseProposalRow)
        if event_id is not None:
            statement = statement.where(ResponseProposalRow.event_id == str(event_id))
        statement = statement.order_by(
            ResponseProposalRow.created_at.desc(),
            ResponseProposalRow.id.desc(),
        ).limit(limit)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_response_proposal(row) for row in rows]

    async def update_response_proposal_status(
        self,
        proposal_id: UUID,
        status: ResponseStatus,
        *,
        expected_status: StoredResponseStatus,
        protected_targets: Collection[str],
    ) -> StoredResponseProposal:
        predecessors: dict[ResponseStatus, frozenset[StoredResponseStatus]] = {
            "pending": frozenset(),
            "approved": frozenset({"pending"}),
            "rejected": frozenset({"pending", "approved"}),
        }
        if status not in predecessors:
            raise ValueError(f"unknown response status: {status}")

        async with self._sessions() as session:
            row = await session.get(ResponseProposalRow, str(proposal_id))
            if row is None:
                raise KeyError(str(proposal_id))
            current = cast(StoredResponseStatus, row.status)
            if current != expected_status:
                raise ValueError(
                    f"response status changed from {expected_status} to {current} concurrently"
                )
            if current not in predecessors or current not in predecessors[status]:
                raise ValueError(f"response status cannot transition from {current} to {status}")
            proposal = _decode_legacy_response_proposal(row.proposal_json)
            if status == "approved":
                event_row = await session.get(EventRow, row.event_id)
                investigation_row = await session.get(
                    InvestigationRow,
                    row.investigation_id,
                )
                if event_row is None or investigation_row is None:
                    raise ValueError("response proposal has missing durable context")
                if (
                    investigation_row.event_id != row.event_id
                    or investigation_row.status != "complete"
                ):
                    raise ValueError("response proposal has inconsistent durable context")
                event = _stored_event(event_row)
                _validate_proposal_target(proposal, event.target)
                _reject_protected_target(proposal, protected_targets)
            result = await session.execute(
                update(ResponseProposalRow)
                .where(
                    ResponseProposalRow.id == str(proposal_id),
                    ResponseProposalRow.status == expected_status,
                )
                .values(status=status)
            )
            if _row_count(result) != 1:
                await session.rollback()
                latest = await session.get(ResponseProposalRow, str(proposal_id))
                if latest is None:
                    raise KeyError(str(proposal_id))
                raise ValueError(
                    "response status cannot transition from "
                    f"{latest.status} to {status}; it changed concurrently"
                )
            await session.commit()
            updated = await session.get(ResponseProposalRow, str(proposal_id))
            if updated is None:
                raise RuntimeError("updated response proposal disappeared")
            return _stored_response_proposal(updated)

    async def start_run(self, version: str) -> StoredRun:
        """Persist the start of an application process before work begins."""
        candidate = StoredRun(
            id=uuid4(),
            started_at=utc_now(),
            version=version,
        )
        row = RunRow(
            id=str(candidate.id),
            started_at=_timestamp(candidate.started_at),
            stopped_at=None,
            version=candidate.version,
            clean_shutdown=0,
        )
        async with self._sessions() as session:
            session.add(row)
            await session.commit()
        return _stored_run(row)

    async def stop_run(
        self,
        run_id: UUID,
        *,
        clean_shutdown: bool,
    ) -> StoredRun:
        """Finish one active run exactly once and record its shutdown outcome."""
        stopped_at = utc_now()
        async with self._sessions() as session:
            result = await session.execute(
                update(RunRow)
                .where(RunRow.id == str(run_id), RunRow.stopped_at.is_(None))
                .values(
                    stopped_at=_timestamp(stopped_at),
                    clean_shutdown=int(clean_shutdown),
                )
            )
            if _row_count(result) != 1:
                await session.rollback()
                row = await session.get(RunRow, str(run_id))
                if row is None:
                    raise KeyError(str(run_id))
                raise ValueError("run has already stopped")
            await session.commit()
            row = await session.get(RunRow, str(run_id))
            if row is None:
                raise RuntimeError("stopped run disappeared")
            return _stored_run(row)

    async def list_runs(self, *, limit: int = 100) -> list[StoredRun]:
        """Return the newest application process records first."""
        _validate_limit(limit, "run")
        statement = select(RunRow).order_by(RunRow.started_at.desc(), RunRow.id.desc()).limit(limit)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_run(row) for row in rows]

    async def session_stats(self) -> SessionStats:
        cost_value = cast(
            ColumnElement[float],
            func.json_extract(
                InvestigationRow.usage_json,
                "$.cost_usd",
                type_=Float,
            ),
        )
        prompt_tokens_value = cast(
            ColumnElement[int],
            func.json_extract(
                InvestigationRow.usage_json,
                "$.prompt_tokens",
                type_=Integer,
            ),
        )
        completion_tokens_value = cast(
            ColumnElement[int],
            func.json_extract(
                InvestigationRow.usage_json,
                "$.completion_tokens",
                type_=Integer,
            ),
        )
        async with self._sessions() as session:
            total_events = (
                await session.execute(select(func.count()).select_from(EventRow))
            ).scalar_one()
            severity_rows = (
                await session.execute(
                    select(EventRow.severity, func.count())
                    .group_by(EventRow.severity)
                    .order_by(EventRow.severity)
                )
            ).all()
            completed, failed, total_tokens, cost_usd = (
                await session.execute(
                    select(
                        func.coalesce(
                            func.sum(case((InvestigationRow.status == "complete", 1), else_=0)),
                            0,
                        ),
                        func.coalesce(
                            func.sum(case((InvestigationRow.status == "failed", 1), else_=0)),
                            0,
                        ),
                        func.coalesce(
                            func.sum(
                                case(
                                    (
                                        InvestigationRow.status == "complete",
                                        func.coalesce(prompt_tokens_value, 0)
                                        + func.coalesce(completion_tokens_value, 0),
                                    ),
                                    else_=0,
                                )
                            ),
                            0,
                        ),
                        func.coalesce(
                            func.sum(
                                case(
                                    (
                                        InvestigationRow.status == "complete",
                                        cost_value,
                                    ),
                                    else_=0.0,
                                )
                            ),
                            0.0,
                        ),
                    )
                )
            ).one()

        return SessionStats(
            total_events=total_events,
            by_severity={severity: count for severity, count in severity_rows},
            completed_investigations=int(completed),
            failed_investigations=int(failed),
            total_tokens=int(total_tokens),
            cost_usd=float(cost_usd),
        )


class _DatabaseCursor(Protocol):
    def execute(self, statement: str) -> object: ...

    def close(self) -> None: ...


class _DatabaseConnection(Protocol):
    def cursor(self) -> _DatabaseCursor: ...


async def _enable_wal(connection: AsyncConnection) -> None:
    for attempt in range(5):
        try:
            await connection.exec_driver_sql("PRAGMA journal_mode=WAL")
            return
        except OperationalError as exc:
            if "locked" not in str(exc).casefold() or attempt == 4:
                raise
            await connection.rollback()
            await asyncio.sleep(0.01 * (2**attempt))


def _configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
    cursor = cast(_DatabaseConnection, dbapi_connection).cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def _validate_database_files(database_path: Path) -> None:
    for candidate in (
        database_path,
        Path(f"{database_path}-wal"),
        Path(f"{database_path}-shm"),
    ):
        try:
            file_status = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(file_status.st_mode):
            raise RuntimeError(f"SocketClaw database path must not be a symlink: {candidate}")
        if not stat.S_ISREG(file_status.st_mode):
            raise RuntimeError(f"SocketClaw database path must be a regular file: {candidate}")
        if file_status.st_nlink != 1:
            raise RuntimeError(f"SocketClaw database path must not be hard-linked: {candidate}")


def _event_row(security_event: SecurityEvent, detection: DetectionResult) -> EventRow:
    normalized = security_event.model_copy(
        update={
            "score": detection.score,
            "severity": detection.severity,
        }
    )
    evidence_json = json.dumps(
        normalized.evidence,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(evidence_json.encode("utf-8")) > _EVIDENCE_MAX_BYTES:
        raise ValueError(f"event evidence must not exceed {_EVIDENCE_MAX_BYTES} UTF-8 bytes")
    return EventRow(
        id=str(normalized.id),
        observed_at=_timestamp(normalized.observed_at),
        ingested_at=_timestamp(normalized.ingested_at or utc_now()),
        source_at=_timestamp(normalized.source_at) if normalized.source_at else None,
        source_key=normalized.source_key,
        rule_version=str(normalized.rule_version) if normalized.rule_version else None,
        outcome=normalized.outcome.value,
        observed_quality=normalized.observed_quality,
        ingest_order_origin="recorded",
        source=normalized.source.value,
        event_type=normalized.event_type,
        title=normalized.title,
        summary=normalized.summary,
        target=normalized.target,
        evidence_json=evidence_json,
        score=normalized.score,
        severity=normalized.severity.value,
        signals_json=json.dumps(
            [signal.model_dump(mode="json") for signal in detection.signals],
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        investigation_state=normalized.investigation_state.value,
        created_at=_timestamp(normalized.created_at),
    )


def _stored_event(row: EventRow) -> StoredEvent:
    return StoredEvent(
        id=UUID(row.id),
        observed_at=_parse_timestamp(row.observed_at),
        ingest_seq=row.ingest_seq,
        ingest_order_origin=cast(
            Literal["recorded", "legacy_reconstructed"], row.ingest_order_origin
        ),
        ingested_at=_parse_timestamp(row.ingested_at) if row.ingested_at else None,
        source_at=_parse_timestamp(row.source_at) if row.source_at else None,
        source_key=row.source_key,
        rule_version=UUID(row.rule_version) if row.rule_version else None,
        outcome=ObservationOutcome(row.outcome),
        observed_quality=cast(Literal["recorded", "legacy_unknown"], row.observed_quality),
        source=EventSource(row.source),
        event_type=_normalize_legacy_required_text(
            row.event_type,
            "legacy.event",
            100,
        ),
        title=_normalize_legacy_required_text(
            row.title,
            "Legacy event",
            200,
        ),
        summary=_normalize_legacy_required_text(
            row.summary,
            "Legacy event had no summary",
            2000,
        ),
        target=_normalize_legacy_optional_text(row.target, 253),
        evidence=_decode_legacy_evidence(row.evidence_json),
        score=row.score,
        severity=Severity(row.severity),
        investigation_state=InvestigationState(row.investigation_state),
        created_at=_parse_timestamp(row.created_at),
        signals=_decode_legacy_signals(row.signals_json),
    )


def _stored_investigation(row: InvestigationRow) -> StoredInvestigation:
    return StoredInvestigation(
        id=UUID(row.id),
        event_id=UUID(row.event_id),
        status=cast(InvestigationStatus, row.status),
        assessment=(
            _decode_legacy_assessment(row.assessment_json) if row.assessment_json else None
        ),
        usage=(_decode_legacy_usage(row.usage_json) if row.usage_json else None),
        model_id=_normalize_legacy_required_text(row.model_id, "unknown model", 200),
        requested_effort=_normalize_legacy_required_text(
            row.requested_effort,
            "unknown",
            20,
        ),
        error=(_normalize_investigation_error(row.error) if row.status == "failed" else row.error),
        created_at=_parse_timestamp(row.created_at),
        completed_at=(_parse_timestamp(row.completed_at) if row.completed_at else None),
    )


def _stored_response_proposal(row: ResponseProposalRow) -> StoredResponseProposal:
    return StoredResponseProposal(
        id=UUID(row.id),
        event_id=UUID(row.event_id),
        investigation_id=UUID(row.investigation_id),
        proposal=_decode_legacy_response_proposal(row.proposal_json),
        status=cast(StoredResponseStatus, row.status),
        created_at=_parse_timestamp(row.created_at),
    )


def _stored_run(row: RunRow) -> StoredRun:
    return StoredRun(
        id=UUID(row.id),
        started_at=_parse_timestamp(row.started_at),
        stopped_at=_parse_timestamp(row.stopped_at) if row.stopped_at else None,
        version=row.version,
        clean_shutdown=bool(row.clean_shutdown),
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("database timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("stored database timestamps must include a timezone")
    return parsed.astimezone(UTC)


def _require_schema_version(value: str | None) -> None:
    if value is None:
        raise RuntimeError("SocketClaw database has no schema version")
    try:
        version = int(value)
    except ValueError as exc:
        raise RuntimeError(f"Invalid SocketClaw schema version {value!r}") from exc
    if 1 <= version < SCHEMA_VERSION:
        raise RuntimeError(
            f"SocketClaw schema {version} needs migration to {SCHEMA_VERSION}; "
            "run socketclaw db migrate or launch the TUI"
        )
    if version != SCHEMA_VERSION:
        raise RuntimeError(f"Unsupported SocketClaw schema version {value}")


def _row_count(result: object) -> int:
    return cast(CursorResult[Any], result).rowcount


def _normalize_investigation_error(error: object) -> str:
    normalized = error.strip() if isinstance(error, str) else ""
    normalized = _OPENAI_KEY.sub("[REDACTED]", normalized)
    normalized = _BEARER_TOKEN.sub("Bearer [REDACTED]", normalized)
    if not normalized:
        normalized = "Investigation failed without an error message"
    if len(normalized) > _INVESTIGATION_ERROR_MAX_LENGTH:
        content_length = _INVESTIGATION_ERROR_MAX_LENGTH - len(_ERROR_TRUNCATION_MARKER)
        normalized = normalized[:content_length].rstrip() + _ERROR_TRUNCATION_MARKER
    return normalized


def _decode_legacy_assessment(payload: str) -> Assessment:
    value: object = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("stored assessment must be a JSON object")
    data = dict(cast(dict[str, object], value))
    data["summary"] = _normalize_legacy_required_text(
        data.get("summary"),
        "Legacy assessment had no summary",
        2000,
    )
    data["rationale"] = _normalize_legacy_items(
        data.get("rationale"),
        required_fallback="Legacy assessment had no rationale",
    )
    data["recommended_actions"] = _normalize_legacy_items(data.get("recommended_actions"))
    proposal_value = data.get("response_proposal")
    if proposal_value is not None:
        proposal = _normalize_legacy_response_proposal(proposal_value)
        if data.get("classification") == "benign" and proposal.action == "block":
            data["response_proposal"] = None
        else:
            data["response_proposal"] = proposal
    return Assessment.model_validate(data)


def _decode_legacy_usage(payload: str) -> ModelUsage:
    value: object = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("stored usage must be a JSON object")
    data = dict(cast(dict[str, object], value))
    prompt_tokens = data.get("prompt_tokens", 0)
    completion_tokens = data.get("completion_tokens", 0)
    if (
        isinstance(prompt_tokens, int)
        and not isinstance(prompt_tokens, bool)
        and isinstance(completion_tokens, int)
        and not isinstance(completion_tokens, bool)
    ):
        data["total_tokens"] = prompt_tokens + completion_tokens
        reasoning_tokens = data.get("reasoning_tokens", 0)
        if (
            isinstance(reasoning_tokens, int)
            and not isinstance(reasoning_tokens, bool)
            and reasoning_tokens > completion_tokens
        ):
            data["reasoning_tokens"] = completion_tokens
    request_id = data.get("provider_request_id")
    data["provider_request_id"] = _normalize_legacy_optional_text(request_id, 200)
    return ModelUsage.model_validate(data)


def _decode_legacy_response_proposal(payload: str) -> ResponseProposal:
    return _normalize_legacy_response_proposal(json.loads(payload))


def _decode_legacy_signals(payload: str) -> tuple[DetectionSignal, ...]:
    value: object = json.loads(payload)
    if not isinstance(value, list):
        raise ValueError("stored detection signals must be a JSON array")
    signals: list[DetectionSignal] = []
    for index, candidate in enumerate(cast(list[object], value), start=1):
        if not isinstance(candidate, dict):
            raise ValueError("stored detection signal must be a JSON object")
        data = dict(cast(dict[str, object], candidate))
        data["code"] = _normalize_legacy_required_text(
            data.get("code"),
            f"legacy.signal.{index}",
            80,
        )
        data["label"] = _normalize_legacy_required_text(
            data.get("label"),
            "Legacy detection signal",
            120,
        )
        data["detail"] = _normalize_legacy_required_text(
            data.get("detail"),
            "Legacy signal had no detail",
            500,
        )
        signals.append(DetectionSignal.model_validate(data))
    return tuple(signals)


def _decode_legacy_evidence(payload: str) -> dict[str, Any]:
    value: object = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("stored event evidence must be a JSON object")
    evidence = cast(dict[str, object], value)

    def normalize(candidate: object) -> object:
        if isinstance(candidate, float) and not math.isfinite(candidate):
            if math.isnan(candidate):
                return "NaN"
            return "Infinity" if candidate > 0 else "-Infinity"
        if isinstance(candidate, dict):
            mapping = cast(dict[object, object], candidate)
            return {str(key): normalize(nested) for key, nested in mapping.items()}
        if isinstance(candidate, list):
            return [normalize(nested) for nested in cast(list[object], candidate)]
        return candidate

    return cast(dict[str, Any], normalize(evidence))


def _normalize_legacy_response_proposal(value: object) -> ResponseProposal:
    if not isinstance(value, dict):
        return ResponseProposal.model_validate(value)
    data = dict(cast(dict[str, object], value))
    data["requires_approval"] = True
    data["reason"] = _normalize_legacy_required_text(
        data.get("reason"),
        "Legacy response proposal had no reason",
        1000,
    )
    data["command"] = _normalize_legacy_optional_text(data.get("command"), 2000)
    data["platform"] = _normalize_legacy_optional_text(data.get("platform"), 80)
    target = data.get("target_ip")
    if data.get("action") != "block" and isinstance(target, str):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            data["target_ip"] = None
    try:
        return ResponseProposal.model_validate(data)
    except ValueError:
        if data.get("action") != "block":
            raise
        reason = _normalize_legacy_required_text(
            data.get("reason"),
            "Legacy response proposal had no reason",
            1000,
        )
        data["action"] = "monitor"
        data["command"] = None
        if isinstance(target, str):
            try:
                ipaddress.ip_address(target)
            except ValueError:
                data["target_ip"] = None
        data["reason"] = _normalize_legacy_required_text(
            f"Legacy unsafe block proposal retained for review only: {reason}",
            "Legacy unsafe block proposal retained for review only",
            1000,
        )
        return ResponseProposal.model_validate(data)


def _normalize_legacy_required_text(
    value: object,
    fallback: str,
    max_length: int,
) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    return (normalized or fallback)[:max_length]


def _normalize_legacy_optional_text(value: object, max_length: int) -> str | None:
    normalized = value.strip() if isinstance(value, str) else ""
    return normalized[:max_length] or None


def _normalize_legacy_items(
    value: object,
    *,
    required_fallback: str | None = None,
) -> tuple[str, ...]:
    raw_items = cast(list[object], value) if isinstance(value, list) else []
    items = tuple(
        normalized[:1000]
        for item in raw_items[:12]
        if isinstance(item, str) and (normalized := item.strip())
    )
    if not items and required_fallback is not None:
        return (required_fallback,)
    return items


def _validate_limit(limit: object, subject: str) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError(f"{subject} limit must be an integer between 1 and 500")


def _reject_protected_target(
    proposal: ResponseProposal,
    protected_targets: Collection[str],
) -> None:
    if proposal.action != "block" or proposal.target_ip is None:
        return
    target = ipaddress.ip_address(proposal.target_ip)
    for candidate in protected_targets:
        try:
            protected = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if target == protected:
            raise ValueError(f"response target {target} is a configured protected target")


def _validate_proposal_target(
    proposal: ResponseProposal | None,
    event_target: str | None,
) -> None:
    if proposal is None or proposal.action != "block" or proposal.target_ip is None:
        return
    if event_target is None:
        raise ValueError("block proposal has no corresponding event target")
    try:
        observed_target = ipaddress.ip_address(event_target)
    except ValueError as exc:
        raise ValueError("block proposal requires an IP event target") from exc
    if ipaddress.ip_address(proposal.target_ip) != observed_target:
        raise ValueError("block proposal target does not match the event target")


def _rule_version(row: RuleVersionRow) -> RuleVersion:
    return RuleVersion(
        id=UUID(row.id),
        applied_at=_parse_timestamp(row.applied_at),
        snapshot_json=row.snapshot_json,
        fingerprint=row.fingerprint,
    )
