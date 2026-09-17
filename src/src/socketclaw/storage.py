"""Async SQLite persistence for events, investigations, responses, and runs."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import re
import stat
from collections.abc import Collection
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import (
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
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL, CursorResult
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql.elements import ColumnElement

from .domain import (
    Assessment,
    DetectionResult,
    DetectionSignal,
    EventSource,
    InvestigationResult,
    InvestigationState,
    ModelUsage,
    ResponseProposal,
    SecurityEvent,
    Severity,
    utc_now,
)

SCHEMA_VERSION = 1
_EVIDENCE_MAX_BYTES = 32 * 1024
_INVESTIGATION_ERROR_MAX_LENGTH = 4000
_ERROR_TRUNCATION_MARKER = "\n[truncated]"
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


class Base(DeclarativeBase):
    pass


class SchemaMetaRow(Base):
    __tablename__ = "schema_meta"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(String(200), nullable=False)


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_observed_at", "observed_at"),
        Index("ix_events_severity", "severity"),
        Index("ix_events_source", "source"),
        Index("ix_events_target", "target"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observed_at: Mapped[str] = mapped_column(String(40), nullable=False)
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

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self._engine: AsyncEngine = create_async_engine(
            URL.create("sqlite+aiosqlite", database=str(self.database_path)),
            echo=False,
        )
        self._sessions = async_sessionmaker(self._engine, expire_on_commit=False)
        event.listen(self._engine.sync_engine, "connect", _configure_sqlite)

    async def initialize(self) -> None:
        _validate_database_files(self.database_path)
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_database_files(self.database_path)
        async with self._engine.connect() as connection:
            table_names = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_table_names()
            )
            if "schema_meta" not in table_names and table_names:
                raise RuntimeError("SocketClaw database has tables but no schema metadata")
            if "schema_meta" in table_names:
                version_value = (
                    await connection.execute(
                        select(SchemaMetaRow.value).where(SchemaMetaRow.key == "schema_version")
                    )
                ).scalar_one_or_none()
                if version_value is not None:
                    _require_schema_version(version_value)
            await _enable_wal(connection)
            await connection.commit()
            await connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                await connection.run_sync(Base.metadata.create_all)
                await connection.execute(
                    sqlite_insert(SchemaMetaRow)
                    .values(key="schema_version", value=str(SCHEMA_VERSION))
                    .on_conflict_do_nothing(index_elements=[SchemaMetaRow.key])
                )
                version_value = (
                    await connection.execute(
                        select(SchemaMetaRow.value).where(SchemaMetaRow.key == "schema_version")
                    )
                ).scalar_one_or_none()
                _require_schema_version(version_value)
            except BaseException:
                await connection.rollback()
                raise
            else:
                await connection.commit()
        try:
            os.chmod(self.database_path, 0o600)
        except OSError as exc:
            raise RuntimeError("Cannot secure the SocketClaw database file") from exc

    async def close(self) -> None:
        await self._engine.dispose()

    async def database_info(self) -> DatabaseInfo:
        async with self._engine.connect() as connection:
            journal_mode = (await connection.exec_driver_sql("PRAGMA journal_mode")).scalar_one()
            foreign_keys = (await connection.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
            integrity_values = (
                (await connection.exec_driver_sql("PRAGMA quick_check")).scalars().all()
            )
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

    async def _validate_domain_rows(self) -> None:
        """Stream every persisted record through its safe domain decoder."""
        async with self._sessions() as session:
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
        row = EventRow(
            id=str(normalized.id),
            observed_at=_timestamp(normalized.observed_at),
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
        async with self._sessions() as session:
            session.add(row)
            await session.commit()
        return _stored_event(row)

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


def _stored_event(row: EventRow) -> StoredEvent:
    return StoredEvent(
        id=UUID(row.id),
        observed_at=_parse_timestamp(row.observed_at),
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
