"""Transactional incident projections and append-only operational evidence."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timedelta
from typing import TypeVar
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base
from .domain import DetectionResult, DetectionSignal, SecurityEvent, utc_now
from .incidents import (
    Fact,
    Family,
    Incident,
    IncidentHistory,
    IncidentLink,
    IncidentNote,
    IncidentStatus,
    Occurrence,
    SuppressionDecision,
    SuppressionRule,
    Transition,
)
from .rules import RuleConfig


class IncidentRow(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_key_seen", "correlation_key", "last_seen_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    correlation_key: Mapped[str] = mapped_column(String(2000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen_at: Mapped[str] = mapped_column(String(40), nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(40), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_version: Mapped[str] = mapped_column(ForeignKey("rule_versions.id"), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class OccurrenceRow(Base):
    __tablename__ = "incident_occurrences"
    __table_args__ = (UniqueConstraint("incident_id", "number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class IncidentLinkRow(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.id", ondelete="RESTRICT"), primary_key=True
    )
    occurrence_id: Mapped[str] = mapped_column(
        ForeignKey("incident_occurrences.id"), nullable=False
    )
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class TransitionRow(Base):
    __tablename__ = "incident_transitions"
    __table_args__ = (UniqueConstraint("incident_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class NoteRow(Base):
    __tablename__ = "incident_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    supersedes_id: Mapped[str | None] = mapped_column(
        ForeignKey("incident_notes.id"), nullable=True, unique=True
    )
    at: Mapped[str] = mapped_column(String(40), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class SuppressionRow(Base):
    __tablename__ = "suppression_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    starts_at: Mapped[str] = mapped_column(String(40), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class SuppressionDecisionRow(Base):
    __tablename__ = "event_suppressions"
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.id", ondelete="RESTRICT"), primary_key=True
    )
    suppression_id: Mapped[str] = mapped_column(
        ForeignKey("suppression_rules.id"), primary_key=True
    )
    family: Mapped[str] = mapped_column(String(30), primary_key=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


T = TypeVar("T", bound=Fact)


_JsonRow = (
    IncidentRow
    | OccurrenceRow
    | IncidentLinkRow
    | TransitionRow
    | NoteRow
    | SuppressionRow
    | SuppressionDecisionRow
)


def _decode(model: type[T], row: _JsonRow) -> T:
    return model.model_validate_json(row.data_json)


def _ts(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


async def _put_incident(session: AsyncSession, incident: Incident) -> None:
    incident = Incident.model_validate(incident.model_dump())
    await session.merge(
        IncidentRow(
            id=str(incident.id),
            correlation_key=incident.correlation_key,
            status=incident.status,
            first_seen_at=_ts(incident.first_seen_at),
            last_seen_at=_ts(incident.last_seen_at),
            revision=incident.revision,
            rule_version=str(incident.rule_version),
            data_json=incident.model_dump_json(),
        )
    )
    await session.flush()


async def _put_occurrence(session: AsyncSession, occurrence: Occurrence) -> None:
    occurrence = Occurrence.model_validate(occurrence.model_dump())
    await session.merge(
        OccurrenceRow(
            id=str(occurrence.id),
            incident_id=str(occurrence.incident_id),
            number=occurrence.number,
            started_at=_ts(occurrence.started_at),
            data_json=occurrence.model_dump_json(),
        )
    )
    await session.flush()


def _transition(
    session: AsyncSession,
    incident: Incident,
    previous: IncidentStatus | None,
    action: str,
    reason: str,
    at: datetime,
    *,
    actor: str = "system",
) -> None:
    item = Transition.model_validate(
        dict(
            incident_id=incident.id,
            revision=incident.revision,
            previous=previous,
            current=incident.status,
            action=action,
            reason=reason,
            actor=actor,
            at=at,
        )
    )
    session.add(
        TransitionRow(
            id=str(item.id),
            incident_id=str(item.incident_id),
            revision=item.revision,
            data_json=item.model_dump_json(),
        )
    )


def _identity(event: SecurityEvent) -> tuple[str, str]:
    if event.target is not None:
        return ("target", event.target.casefold())
    path = event.evidence.get("path")
    if isinstance(path, str) and path:
        return ("path", path)
    probe = event.evidence.get("probe")
    if isinstance(probe, str) and probe:
        return ("probe", probe)
    # Unknown unrelated observations must not collapse into one global incident.
    return ("observation", str(event.id))


def _key(event: SecurityEvent, family: Family) -> str:
    payload = json.dumps(
        (str(event.rule_version), family, *_identity(event)), separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _families(detection: DetectionResult) -> dict[Family, list[DetectionSignal]]:
    result: dict[Family, list[DetectionSignal]] = {}
    for signal in detection.signals:
        if not signal.points:
            continue
        family: Family
        if signal.code.startswith("ping."):
            family = "availability"
        elif signal.code.startswith("port."):
            family = "exposure"
        elif signal.code.startswith("log.auth"):
            family = "authentication"
        elif signal.code.startswith("log.firewall"):
            family = "firewall"
        elif signal.code == "log.privilege_escalation":
            family = "privilege"
        elif signal.code == "log.malware_indicator":
            family = "malware"
        else:
            continue
        result.setdefault(family, []).append(signal)
    return result


def _ports(event: SecurityEvent, field: str) -> set[int]:
    raw = event.evidence.get(field)
    if not isinstance(raw, list):
        return set()
    return {
        item
        for item in raw
        if isinstance(item, int) and not isinstance(item, bool) and 1 <= item <= 65535
    }


def _recovered(event: SecurityEvent, occurrence: Occurrence, config: RuleConfig) -> bool:
    if event.evidence.get("outcome") in {"error", "unknown"}:
        return False
    if event.source == "ping":
        loss = event.evidence.get("packet_loss")
        return (
            isinstance(loss, int | float)
            and not isinstance(loss, bool)
            and math.isfinite(loss)
            and 0 <= loss < config.ping_degraded_percent
        )
    if event.source == "port_scan":
        affected = set(occurrence.affected_ports)
        return (
            bool(affected)
            and affected <= _ports(event, "scanned_ports")
            and not affected & (_ports(event, "open_ports") | _ports(event, "unresolved_ports"))
            and isinstance(event.evidence.get("open_ports"), list)
        )
    return False


def _matches(rule: SuppressionRule, event: SecurityEvent, family: Family, codes: set[str]) -> bool:
    return (
        (rule.family is None or rule.family == family)
        and (rule.rule_code is None or rule.rule_code in codes)
        and (
            rule.target is None
            or (event.target is not None and rule.target.casefold() == event.target.casefold())
        )
        and (rule.log_path is None or rule.log_path == event.evidence.get("path"))
    )


async def project_observation(
    session: AsyncSession, event: SecurityEvent, detection: DetectionResult, config: RuleConfig
) -> None:
    """Called only for deduplicated, flushed observations in the ingest transaction."""
    assert event.ingested_at is not None and event.rule_version is not None
    at = event.ingested_at
    families = _families(detection)
    if event.event_type == "system.probe_error":
        families["collector"] = []
    suppressions = [
        _decode(SuppressionRule, row)
        for row in await session.scalars(
            select(SuppressionRow).where(
                SuppressionRow.starts_at <= _ts(at),
                SuppressionRow.expires_at > _ts(at),
            )
        )
    ]
    for family, signals in families.items():
        codes = {signal.code for signal in signals}
        if family == "collector":
            codes.add("system.probe_error")
        remaining = set(codes)
        suppress_family = False
        for rule in suppressions:
            if rule.disabled_at is not None and at >= rule.disabled_at:
                continue
            if not _matches(rule, event, family, codes):
                continue
            matched = codes if rule.rule_code is None else {rule.rule_code}
            remaining -= matched
            suppress_family = suppress_family or rule.rule_code is None
            decision = SuppressionDecision(
                event_id=event.id,
                suppression_id=rule.id,
                family=family,
                rule_codes=tuple(sorted(matched)),
                reason=rule.reason,
                starts_at=rule.starts_at,
                expires_at=rule.expires_at,
                applied_at=at,
            )
            session.add(
                SuppressionDecisionRow(
                    event_id=str(event.id),
                    suppression_id=str(rule.id),
                    family=family,
                    data_json=decision.model_dump_json(),
                )
            )
        if suppress_family or (codes and not remaining):
            continue
        score = min(100, sum(signal.points for signal in signals if signal.code in remaining))
        await _anomaly(session, event, family, score)
    if event.source in {"ping", "port_scan"}:
        family = "availability" if event.source == "ping" else "exposure"
        if family not in families:
            await _recovery(session, event, family, config)


async def _candidate_incident(session: AsyncSession, key: str, at: datetime) -> IncidentRow | None:
    query = select(IncidentRow).where(IncidentRow.correlation_key == key)
    row = await session.scalar(
        query.where(IncidentRow.first_seen_at <= _ts(at))
        .order_by(IncidentRow.first_seen_at.desc(), IncidentRow.id.desc())
        .limit(1)
    )
    if row is None:
        row = await session.scalar(
            query.order_by(IncidentRow.first_seen_at, IncidentRow.id).limit(1)
        )
    return row


async def _anomaly(session: AsyncSession, event: SecurityEvent, family: Family, score: int) -> None:
    assert event.ingested_at is not None and event.rule_version is not None
    at = event.ingested_at
    key = _key(event, family)
    row = await _candidate_incident(session, key, at)
    incident = _decode(Incident, row) if row else None
    previous_id: UUID | None = None
    current: Occurrence | None = None
    if incident is not None:
        current_row = await session.get(OccurrenceRow, str(incident.current_occurrence_id))
        if current_row is None:
            raise RuntimeError("Incident occurrence is missing")
        current = _decode(Occurrence, current_row)
        if (incident.status == "resolved" or current.recovered_at is not None) and (
            at - incident.last_seen_at > timedelta(seconds=incident.reopen_within_seconds)
        ):
            previous_id = incident.id
            incident = None
    ports = tuple(sorted(_ports(event, "newly_opened") | _ports(event, "initial_open_ports")))
    if incident is None:
        occurrence_id = uuid4()
        incident = Incident(
            correlation_key=key,
            family=family,
            target=event.target,
            title=event.title,
            first_seen_at=at,
            last_seen_at=at,
            highest_score=score,
            rule_version=event.rule_version,
            current_occurrence_id=occurrence_id,
            previous_incident_id=previous_id,
        )
        current = Occurrence(
            id=occurrence_id,
            incident_id=incident.id,
            number=1,
            started_at=at,
            last_seen_at=at,
            affected_ports=ports,
        )
        await _put_incident(session, incident)
        await _put_occurrence(session, current)
        _transition(session, incident, None, "opened", "New anomalous observation", at)
    else:
        assert current is not None
        original_status = incident.status
        previous_resolution = incident.resolved_at
        recurrence_boundary = previous_resolution or current.recovered_at
        is_recurrence = (
            recurrence_boundary is not None
            and at > recurrence_boundary
            and at >= incident.last_seen_at
        )
        updates: dict[str, object] = dict(
            first_seen_at=min(incident.first_seen_at, at),
            last_seen_at=max(incident.last_seen_at, at),
            observation_count=incident.observation_count + 1,
            highest_score=max(incident.highest_score, score),
            revision=incident.revision + 1,
        )
        if is_recurrence:
            current = Occurrence(
                incident_id=incident.id,
                number=incident.occurrence_count + 1,
                started_at=at,
                last_seen_at=at,
                affected_ports=ports,
            )
            updates.update(
                current_occurrence_id=current.id,
                occurrence_count=current.number,
                last_reopened_at=at,
                status="open" if previous_resolution else incident.status,
                resolved_at=None,
            )
        else:
            if at < current.started_at:
                historical = await session.scalar(
                    select(OccurrenceRow)
                    .where(
                        OccurrenceRow.incident_id == str(incident.id),
                        OccurrenceRow.started_at <= _ts(at),
                    )
                    .order_by(OccurrenceRow.started_at.desc(), OccurrenceRow.number.desc())
                    .limit(1)
                )
                if historical is None:
                    historical = await session.scalar(
                        select(OccurrenceRow)
                        .where(OccurrenceRow.incident_id == str(incident.id))
                        .order_by(OccurrenceRow.number)
                        .limit(1)
                    )
                if historical is not None:
                    current = _decode(Occurrence, historical)
            current = current.model_copy(
                update=dict(
                    started_at=min(current.started_at, at),
                    last_seen_at=max(current.last_seen_at or at, at),
                    observation_count=current.observation_count + 1,
                    affected_ports=tuple(sorted(set(current.affected_ports) | set(ports))),
                )
            )
        incident = Incident.model_validate(incident.model_copy(update=updates).model_dump())
        await _put_incident(session, incident)
        await _put_occurrence(session, current)
        if is_recurrence:
            _transition(
                session,
                incident,
                original_status,
                "reopened" if previous_resolution else "recurred",
                "New anomalous observation after resolution or observed recovery",
                at,
            )
    link = IncidentLink(
        incident_id=incident.id,
        event_id=event.id,
        occurrence_id=current.id,
        kind="anomaly",
        reason=f"Same {family} family, source identity and rule version",
        linked_at=at,
    )
    session.add(
        IncidentLinkRow(
            incident_id=str(incident.id),
            event_id=str(event.id),
            occurrence_id=str(current.id),
            data_json=link.model_dump_json(),
        )
    )
    await session.flush()


async def _recovery(
    session: AsyncSession, event: SecurityEvent, family: Family, config: RuleConfig
) -> None:
    assert event.ingested_at is not None
    row = await _candidate_incident(session, _key(event, family), event.ingested_at)
    if row is None:
        return
    incident = _decode(Incident, row)
    occurrence_row = await session.get(OccurrenceRow, str(incident.current_occurrence_id))
    if occurrence_row is None:
        raise RuntimeError("Incident occurrence is missing")
    occurrence = _decode(Occurrence, occurrence_row)
    if (
        occurrence.recovered_at is not None
        or (occurrence.last_seen_at is None or event.ingested_at < occurrence.last_seen_at)
        or not _recovered(event, occurrence, config)
    ):
        return
    occurrence = occurrence.model_copy(update={"recovered_at": event.ingested_at})
    incident = incident.model_copy(update={"revision": incident.revision + 1})
    await _put_incident(session, incident)
    await _put_occurrence(session, occurrence)
    _transition(
        session,
        incident,
        incident.status,
        "observed_recovery",
        "Measured recovery observed; operator status is unchanged",
        event.ingested_at,
    )
    link = IncidentLink(
        incident_id=incident.id,
        event_id=event.id,
        occurrence_id=occurrence.id,
        kind="observed_recovery",
        reason="Measured recovery; this is not operator resolution",
        linked_at=event.ingested_at,
    )
    session.add(
        IncidentLinkRow(
            incident_id=str(incident.id),
            event_id=str(event.id),
            occurrence_id=str(occurrence.id),
            data_json=link.model_dump_json(),
        )
    )
    await session.flush()


class IncidentStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def get(self, identifier: UUID) -> Incident | None:
        async with self.sessions() as session:
            row = await session.get(IncidentRow, str(identifier))
            return _decode(Incident, row) if row else None

    async def list(
        self,
        *,
        status: IncidentStatus | None = None,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        _page(limit, offset)
        query = select(IncidentRow)
        if status is not None:
            query = query.where(IncidentRow.status == status)
        if active_only:
            query = query.where(IncidentRow.status != "resolved")
        async with self.sessions() as session:
            rows = await session.scalars(
                query.order_by(IncidentRow.last_seen_at.desc(), IncidentRow.id.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_decode(Incident, row) for row in rows]

    async def counts(self) -> dict[str, int]:
        async with self.sessions() as session:
            rows = await session.execute(
                select(IncidentRow.status, func.count()).group_by(IncidentRow.status)
            )
            return {str(status): int(count) for status, count in rows}

    async def change_status(
        self,
        identifier: UUID,
        status: IncidentStatus,
        *,
        expected_revision: int,
        reason: str,
        at: datetime | None = None,
    ) -> Incident:
        async with self.sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            incident = await self._current(session, identifier, expected_revision)
            allowed = {
                ("open", "acknowledged"),
                ("open", "resolved"),
                ("acknowledged", "resolved"),
                ("resolved", "open"),
            }
            if (incident.status, status) not in allowed:
                raise ValueError("Invalid incident state transition")
            timestamp = at or utc_now()
            if timestamp < incident.last_seen_at:
                raise ValueError("Operator action cannot precede the latest observation")
            updated = incident.model_copy(
                update=dict(
                    status=status,
                    revision=incident.revision + 1,
                    resolved_at=timestamp if status == "resolved" else None,
                )
            )
            if status == "open":
                occurrence = Occurrence(
                    incident_id=incident.id,
                    number=incident.occurrence_count + 1,
                    started_at=timestamp,
                    last_seen_at=None,
                    observation_count=0,
                )
                # Manual reopening has no anomalous measurement of its own.
                updated = updated.model_copy(
                    update=dict(
                        current_occurrence_id=occurrence.id,
                        occurrence_count=occurrence.number,
                        last_reopened_at=timestamp,
                    )
                )
                await _put_occurrence(session, occurrence)
            action = "reopened" if status == "open" else status
            _transition(
                session, updated, incident.status, action, reason, timestamp, actor="operator"
            )
            await _put_incident(session, updated)
            await session.commit()
            return updated

    async def add_note(
        self,
        identifier: UUID,
        body: str,
        *,
        expected_revision: int,
        supersedes_id: UUID | None = None,
    ) -> IncidentNote:
        note = IncidentNote(incident_id=identifier, body=body, supersedes_id=supersedes_id)
        async with self.sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            incident = await self._current(session, identifier, expected_revision)
            if supersedes_id is not None:
                previous = await session.get(NoteRow, str(supersedes_id))
                if previous is None or previous.incident_id != str(identifier):
                    raise ValueError("Superseded note must belong to the same incident")
                if (
                    await session.scalar(
                        select(NoteRow.id).where(NoteRow.supersedes_id == str(supersedes_id))
                    )
                    is not None
                ):
                    raise ValueError("This note already has a correction")
            session.add(
                NoteRow(
                    id=str(note.id),
                    incident_id=str(identifier),
                    at=_ts(note.at),
                    supersedes_id=str(supersedes_id) if supersedes_id else None,
                    data_json=note.model_dump_json(),
                )
            )
            await _put_incident(
                session, incident.model_copy(update={"revision": incident.revision + 1})
            )
            await session.commit()
        return note

    async def _current(self, session: AsyncSession, identifier: UUID, revision: int) -> Incident:
        row = await session.get(IncidentRow, str(identifier))
        if row is None:
            raise KeyError(str(identifier))
        incident = _decode(Incident, row)
        if incident.revision != revision:
            raise ValueError("Incident changed; reload before applying this action")
        return incident

    async def occurrences(
        self, identifier: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Occurrence]:
        _page(limit, offset)
        async with self.sessions() as session:
            rows = await session.scalars(
                select(OccurrenceRow)
                .where(OccurrenceRow.incident_id == str(identifier))
                .order_by(OccurrenceRow.number)
                .limit(limit)
                .offset(offset)
            )
            return [_decode(Occurrence, row) for row in rows]

    async def transitions(
        self, identifier: UUID, *, limit: int = 100, offset: int = 0, newest_first: bool = False
    ) -> list[Transition]:
        _page(limit, offset)
        async with self.sessions() as session:
            rows = await session.scalars(
                select(TransitionRow)
                .where(TransitionRow.incident_id == str(identifier))
                .order_by(TransitionRow.revision.desc() if newest_first else TransitionRow.revision)
                .limit(limit)
                .offset(offset)
            )
            return [_decode(Transition, row) for row in rows]

    async def notes(
        self, identifier: UUID, *, limit: int = 100, offset: int = 0, newest_first: bool = False
    ) -> list[IncidentNote]:
        _page(limit, offset)
        async with self.sessions() as session:
            rows = await session.scalars(
                select(NoteRow)
                .where(NoteRow.incident_id == str(identifier))
                .order_by(
                    NoteRow.at.desc() if newest_first else NoteRow.at,
                    NoteRow.id.desc() if newest_first else NoteRow.id,
                )
                .limit(limit)
                .offset(offset)
            )
            return [_decode(IncidentNote, row) for row in rows]

    async def links(
        self, identifier: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[IncidentLink]:
        _page(limit, offset)
        async with self.sessions() as session:
            rows = await session.scalars(
                select(IncidentLinkRow)
                .where(IncidentLinkRow.incident_id == str(identifier))
                .order_by(IncidentLinkRow.event_id)
                .limit(limit)
                .offset(offset)
            )
            return [_decode(IncidentLink, row) for row in rows]

    async def create_suppression(self, rule: SuppressionRule) -> SuppressionRule:
        rule = SuppressionRule.model_validate(rule.model_dump())
        if rule.disabled_at is not None:
            raise ValueError("New suppression must be enabled")
        async with self.sessions() as session:
            session.add(
                SuppressionRow(
                    id=str(rule.id),
                    enabled=True,
                    starts_at=_ts(rule.starts_at),
                    expires_at=_ts(rule.expires_at),
                    data_json=rule.model_dump_json(),
                )
            )
            await session.commit()
        return rule

    async def disable_suppression(self, identifier: UUID, reason: str) -> SuppressionRule:
        async with self.sessions() as session:
            await session.execute(text("BEGIN IMMEDIATE"))
            row = await session.get(SuppressionRow, str(identifier))
            if row is None:
                raise KeyError(str(identifier))
            rule = _decode(SuppressionRule, row)
            if rule.disabled_at is not None:
                raise ValueError("Suppression is already disabled")
            updated = SuppressionRule.model_validate(
                rule.model_copy(
                    update={"disabled_at": utc_now(), "disabled_reason": reason}
                ).model_dump()
            )
            row.enabled = False
            row.data_json = updated.model_dump_json()
            await session.commit()
            return updated

    async def suppressions(self, *, limit: int = 100, offset: int = 0) -> list[SuppressionRule]:
        _page(limit, offset)
        async with self.sessions() as session:
            rows = await session.scalars(
                select(SuppressionRow)
                .order_by(SuppressionRow.starts_at.desc(), SuppressionRow.id)
                .limit(limit)
                .offset(offset)
            )
            return [_decode(SuppressionRule, row) for row in rows]

    async def suppression_decisions(self, event_id: UUID) -> list[SuppressionDecision]:
        async with self.sessions() as session:
            rows = await session.scalars(
                select(SuppressionDecisionRow).where(
                    SuppressionDecisionRow.event_id == str(event_id)
                )
            )
            return [_decode(SuppressionDecision, row) for row in rows]


def _page(limit: int, offset: int) -> None:
    if not 1 <= limit <= 200 or offset < 0:
        raise ValueError("Incident page requires limit 1-200 and a nonnegative offset")


async def validate_incidents(session: AsyncSession) -> None:
    """Check both payloads and relational projections during migration/doctor."""
    async for row in await session.stream_scalars(select(IncidentRow)):
        item = _decode(Incident, row)
        if (
            str(item.id),
            item.correlation_key,
            item.status,
            item.revision,
            str(item.rule_version),
            _ts(item.last_seen_at),
        ) != (
            row.id,
            row.correlation_key,
            row.status,
            row.revision,
            row.rule_version,
            row.last_seen_at,
        ):
            raise ValueError("incident projection does not match its payload")
        current = await session.get(OccurrenceRow, str(item.current_occurrence_id))
        if (
            current is None
            or current.incident_id != row.id
            or current.number != item.occurrence_count
        ):
            raise ValueError("invalid current incident occurrence")
        count = await session.scalar(
            select(func.count())
            .select_from(OccurrenceRow)
            .where(OccurrenceRow.incident_id == row.id)
        )
        if count != item.occurrence_count:
            raise ValueError("incident occurrence count mismatch")
        observations = await session.scalar(
            select(func.count())
            .select_from(IncidentLinkRow)
            .where(
                IncidentLinkRow.incident_id == row.id,
                func.json_extract(IncidentLinkRow.data_json, "$.kind") == "anomaly",
            )
        )
        if observations != item.observation_count:
            raise ValueError("incident observation count mismatch")
        if item.previous_incident_id is not None:
            previous = await session.get(IncidentRow, str(item.previous_incident_id))
            if (
                previous is None
                or previous.id == row.id
                or previous.correlation_key != row.correlation_key
            ):
                raise ValueError("invalid previous incident relationship")
    async for row in await session.stream_scalars(select(OccurrenceRow)):
        occurrence = _decode(Occurrence, row)
        if (str(occurrence.id), str(occurrence.incident_id), occurrence.number) != (
            row.id,
            row.incident_id,
            row.number,
        ):
            raise ValueError("occurrence projection mismatch")
        observations = await session.scalar(
            select(func.count())
            .select_from(IncidentLinkRow)
            .where(
                IncidentLinkRow.occurrence_id == row.id,
                func.json_extract(IncidentLinkRow.data_json, "$.kind") == "anomaly",
            )
        )
        if observations != occurrence.observation_count:
            raise ValueError("occurrence observation count mismatch")
    async for row in await session.stream_scalars(select(IncidentLinkRow)):
        link = _decode(IncidentLink, row)
        occurrence_row = await session.get(OccurrenceRow, row.occurrence_id)
        if (
            (str(link.incident_id), str(link.event_id), str(link.occurrence_id))
            != (row.incident_id, row.event_id, row.occurrence_id)
            or occurrence_row is None
            or occurrence_row.incident_id != row.incident_id
        ):
            raise ValueError("incident evidence relationship mismatch")
    async for row in await session.stream_scalars(select(TransitionRow)):
        transition = _decode(Transition, row)
        parent = await session.get(IncidentRow, row.incident_id)
        if (
            (str(transition.id), str(transition.incident_id), transition.revision)
            != (row.id, row.incident_id, row.revision)
            or parent is None
            or transition.revision > parent.revision
        ):
            raise ValueError("incident transition mismatch")
    async for row in await session.stream_scalars(select(NoteRow)):
        note = _decode(IncidentNote, row)
        supersedes = str(note.supersedes_id) if note.supersedes_id else None
        if (str(note.id), str(note.incident_id), supersedes, _ts(note.at)) != (
            row.id,
            row.incident_id,
            row.supersedes_id,
            row.at,
        ):
            raise ValueError("incident note mismatch")
        if row.supersedes_id is not None:
            previous_note = await session.get(NoteRow, row.supersedes_id)
            if previous_note is None or previous_note.incident_id != row.incident_id:
                raise ValueError("note correction crosses incident boundary")
    async for row in await session.stream_scalars(select(SuppressionRow)):
        rule = _decode(SuppressionRule, row)
        if (str(rule.id), rule.disabled_at is None, _ts(rule.starts_at), _ts(rule.expires_at)) != (
            row.id,
            row.enabled,
            row.starts_at,
            row.expires_at,
        ):
            raise ValueError("suppression projection mismatch")
    async for row in await session.stream_scalars(select(SuppressionDecisionRow)):
        decision = _decode(SuppressionDecision, row)
        if (str(decision.event_id), str(decision.suppression_id), decision.family) != (
            row.event_id,
            row.suppression_id,
            row.family,
        ):
            raise ValueError("suppression decision identity mismatch")


async def read_history(session: AsyncSession, identifier: UUID) -> IncidentHistory | None:
    """Read the complete history inside the caller's SQLite snapshot transaction."""
    row = await session.get(IncidentRow, str(identifier))
    if row is None:
        return None
    occurrences = await session.scalars(
        select(OccurrenceRow)
        .where(OccurrenceRow.incident_id == str(identifier))
        .order_by(OccurrenceRow.number)
    )
    transitions = await session.scalars(
        select(TransitionRow)
        .where(TransitionRow.incident_id == str(identifier))
        .order_by(TransitionRow.revision)
    )
    notes = await session.scalars(
        select(NoteRow)
        .where(NoteRow.incident_id == str(identifier))
        .order_by(NoteRow.at, NoteRow.id)
    )
    links = await session.scalars(
        select(IncidentLinkRow)
        .where(IncidentLinkRow.incident_id == str(identifier))
        .order_by(IncidentLinkRow.event_id)
    )
    return IncidentHistory(
        incident=_decode(Incident, row),
        occurrences=tuple(_decode(Occurrence, item) for item in occurrences),
        transitions=tuple(_decode(Transition, item) for item in transitions),
        notes=tuple(_decode(IncidentNote, item) for item in notes),
        links=tuple(_decode(IncidentLink, item) for item in links),
    )
