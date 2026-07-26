"""Async SQLite persistence for events, investigations, responses, and runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    event,
    func,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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

    model_config = ConfigDict(frozen=True)

    severity: Severity | None = None
    source: EventSource | None = None
    target: str | None = None
    text: str | None = Field(default=None, max_length=200)
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


class StoredEvent(SecurityEvent):
    """A persisted event with explainable detection signals."""

    signals: tuple[DetectionSignal, ...] = ()


InvestigationStatus = Literal["complete", "failed"]
ResponseStatus = Literal["pending", "simulated", "approved", "executed", "rejected"]


class StoredInvestigation(BaseModel):
    """A completed or failed model investigation."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    event_id: UUID
    status: InvestigationStatus
    assessment: Assessment | None = None
    usage: ModelUsage | None = None
    model_id: str
    requested_effort: str
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class SessionStats(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_events: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    completed_investigations: int = 0
    failed_investigations: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0


class StoredResponseProposal(BaseModel):
    """A durable response waiting for simulation, approval, or execution."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    event_id: UUID
    investigation_id: UUID
    proposal: ResponseProposal
    status: ResponseStatus
    created_at: datetime


class DatabaseInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: int
    journal_mode: str
    foreign_keys: bool


class Repository:
    """Method-scoped async persistence with detached typed results."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self._engine: AsyncEngine = create_async_engine(
            f"sqlite+aiosqlite:///{self.database_path}",
            echo=False,
        )
        self._sessions = async_sessionmaker(self._engine, expire_on_commit=False)
        event.listen(self._engine.sync_engine, "connect", _configure_sqlite)

    async def initialize(self) -> None:
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        async with self._engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with self._sessions() as session:
            current = await session.get(SchemaMetaRow, "schema_version")
            if current is None:
                session.add(
                    SchemaMetaRow(
                        key="schema_version",
                        value=str(SCHEMA_VERSION),
                    )
                )
            elif int(current.value) != SCHEMA_VERSION:
                raise RuntimeError(f"Unsupported SocketClaw schema version {current.value}")
            await session.commit()

    async def close(self) -> None:
        await self._engine.dispose()

    async def database_info(self) -> DatabaseInfo:
        async with self._engine.connect() as connection:
            journal_mode = (await connection.exec_driver_sql("PRAGMA journal_mode")).scalar_one()
            foreign_keys = (await connection.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
        async with self._sessions() as session:
            schema = await session.get(SchemaMetaRow, "schema_version")
        if schema is None:
            raise RuntimeError("SocketClaw database has not been initialized")
        return DatabaseInfo(
            schema_version=int(schema.value),
            journal_mode=str(journal_mode).lower(),
            foreign_keys=bool(foreign_keys),
        )

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
        row = EventRow(
            id=str(normalized.id),
            observed_at=_timestamp(normalized.observed_at),
            source=normalized.source.value,
            event_type=normalized.event_type,
            title=normalized.title,
            summary=normalized.summary,
            target=normalized.target,
            evidence_json=json.dumps(normalized.evidence, default=str),
            score=normalized.score,
            severity=normalized.severity.value,
            signals_json=json.dumps(
                [signal.model_dump(mode="json") for signal in detection.signals]
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
            pattern = f"%{filters.text.lower()}%"
            statement = statement.where(
                or_(
                    func.lower(EventRow.title).like(pattern),
                    func.lower(EventRow.summary).like(pattern),
                    func.lower(func.coalesce(EventRow.target, "")).like(pattern),
                )
            )
        if filters.after is not None:
            statement = statement.where(EventRow.observed_at >= _timestamp(filters.after))
        if filters.before is not None:
            statement = statement.where(EventRow.observed_at <= _timestamp(filters.before))
        statement = (
            statement.order_by(EventRow.observed_at.desc())
            .limit(filters.limit)
            .offset(filters.offset)
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_event(row) for row in rows]

    async def save_investigation(
        self,
        event_id: UUID,
        result: InvestigationResult,
    ) -> StoredInvestigation:
        now = utc_now()
        investigation_id = uuid4()
        row = InvestigationRow(
            id=str(investigation_id),
            event_id=str(event_id),
            status="complete",
            assessment_json=result.assessment.model_dump_json(),
            usage_json=result.usage.model_dump_json(),
            model_id=result.model_id,
            requested_effort=result.requested_effort,
            error=None,
            created_at=_timestamp(now),
            completed_at=_timestamp(now),
        )
        async with self._sessions() as session:
            event_row = await session.get(EventRow, str(event_id))
            if event_row is None:
                raise KeyError(str(event_id))
            event_row.investigation_state = InvestigationState.COMPLETE.value
            session.add(row)
            if result.assessment.response_proposal is not None:
                session.add(
                    ResponseProposalRow(
                        id=str(uuid4()),
                        event_id=str(event_id),
                        investigation_id=str(investigation_id),
                        proposal_json=result.assessment.response_proposal.model_dump_json(),
                        status="pending",
                        created_at=_timestamp(now),
                    )
                )
            await session.commit()
        return _stored_investigation(row)

    async def save_investigation_failure(
        self,
        event_id: UUID,
        *,
        model_id: str,
        requested_effort: str,
        error: str,
    ) -> StoredInvestigation:
        now = utc_now()
        row = InvestigationRow(
            id=str(uuid4()),
            event_id=str(event_id),
            status="failed",
            assessment_json=None,
            usage_json=None,
            model_id=model_id,
            requested_effort=requested_effort,
            error=error,
            created_at=_timestamp(now),
            completed_at=_timestamp(now),
        )
        async with self._sessions() as session:
            event_row = await session.get(EventRow, str(event_id))
            if event_row is None:
                raise KeyError(str(event_id))
            event_row.investigation_state = InvestigationState.FAILED.value
            session.add(row)
            await session.commit()
        return _stored_investigation(row)

    async def list_investigations(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
    ) -> list[StoredInvestigation]:
        if not 1 <= limit <= 500:
            raise ValueError("investigation limit must be between 1 and 500")
        statement = select(InvestigationRow)
        if event_id is not None:
            statement = statement.where(InvestigationRow.event_id == str(event_id))
        statement = statement.order_by(InvestigationRow.created_at.desc()).limit(limit)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_investigation(row) for row in rows]

    async def list_response_proposals(
        self,
        *,
        event_id: UUID | None = None,
        limit: int = 100,
    ) -> list[StoredResponseProposal]:
        if not 1 <= limit <= 500:
            raise ValueError("response proposal limit must be between 1 and 500")
        statement = select(ResponseProposalRow)
        if event_id is not None:
            statement = statement.where(ResponseProposalRow.event_id == str(event_id))
        statement = statement.order_by(ResponseProposalRow.created_at.desc()).limit(limit)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [_stored_response_proposal(row) for row in rows]

    async def update_response_proposal_status(
        self,
        proposal_id: UUID,
        status: ResponseStatus,
    ) -> StoredResponseProposal:
        allowed: dict[ResponseStatus, frozenset[ResponseStatus]] = {
            "pending": frozenset({"simulated", "approved", "rejected"}),
            "approved": frozenset({"executed", "rejected"}),
            "simulated": frozenset(),
            "executed": frozenset(),
            "rejected": frozenset(),
        }
        if status not in allowed:
            raise ValueError(f"unknown response status: {status}")

        async with self._sessions() as session:
            row = await session.get(ResponseProposalRow, str(proposal_id))
            if row is None:
                raise KeyError(str(proposal_id))
            current = cast(ResponseStatus, row.status)
            if current not in allowed or status not in allowed[current]:
                raise ValueError(f"response status cannot transition from {current} to {status}")
            row.status = status
            await session.commit()
            return _stored_response_proposal(row)

    async def session_stats(self) -> SessionStats:
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
            investigations = (await session.execute(select(InvestigationRow))).scalars().all()

        completed = 0
        failed = 0
        total_tokens = 0
        cost_usd = 0.0
        for row in investigations:
            if row.status == "complete":
                completed += 1
                if row.usage_json:
                    usage = ModelUsage.model_validate_json(row.usage_json)
                    total_tokens += usage.total_tokens or 0
                    cost_usd += usage.cost_usd
            elif row.status == "failed":
                failed += 1
        return SessionStats(
            total_events=total_events,
            by_severity={severity: count for severity, count in severity_rows},
            completed_investigations=completed,
            failed_investigations=failed,
            total_tokens=total_tokens,
            cost_usd=cost_usd,
        )


class _DatabaseCursor(Protocol):
    def execute(self, statement: str) -> object: ...

    def close(self) -> None: ...


class _DatabaseConnection(Protocol):
    def cursor(self) -> _DatabaseCursor: ...


def _configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
    cursor = cast(_DatabaseConnection, dbapi_connection).cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


def _stored_event(row: EventRow) -> StoredEvent:
    return StoredEvent(
        id=UUID(row.id),
        observed_at=_parse_timestamp(row.observed_at),
        source=EventSource(row.source),
        event_type=row.event_type,
        title=row.title,
        summary=row.summary,
        target=row.target,
        evidence=json.loads(row.evidence_json),
        score=row.score,
        severity=Severity(row.severity),
        investigation_state=InvestigationState(row.investigation_state),
        created_at=_parse_timestamp(row.created_at),
        signals=tuple(
            DetectionSignal.model_validate(signal) for signal in json.loads(row.signals_json)
        ),
    )


def _stored_investigation(row: InvestigationRow) -> StoredInvestigation:
    return StoredInvestigation(
        id=UUID(row.id),
        event_id=UUID(row.event_id),
        status=cast(InvestigationStatus, row.status),
        assessment=(
            Assessment.model_validate_json(row.assessment_json) if row.assessment_json else None
        ),
        usage=(ModelUsage.model_validate_json(row.usage_json) if row.usage_json else None),
        model_id=row.model_id,
        requested_effort=row.requested_effort,
        error=row.error,
        created_at=_parse_timestamp(row.created_at),
        completed_at=(_parse_timestamp(row.completed_at) if row.completed_at else None),
    )


def _stored_response_proposal(row: ResponseProposalRow) -> StoredResponseProposal:
    return StoredResponseProposal(
        id=UUID(row.id),
        event_id=UUID(row.event_id),
        investigation_id=UUID(row.investigation_id),
        proposal=ResponseProposal.model_validate_json(row.proposal_json),
        status=cast(ResponseStatus, row.status),
        created_at=_parse_timestamp(row.created_at),
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("database timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)
