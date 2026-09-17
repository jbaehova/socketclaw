"""Operational incident facts, independent of immutable security observations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain import Severity, severity_for_score, utc_now
from .rules import RulePoints

IncidentStatus = Literal["open", "acknowledged", "resolved"]
Family = Literal[
    "availability", "exposure", "authentication", "firewall", "privilege", "malware", "collector"
]
POLICY = {"version": 1, "reopen_within_seconds": 86400, "automatic_resolution": False}


class Fact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def aware_time(cls, value: object) -> object:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("incident timestamps require a timezone")
            return value.astimezone(UTC)
        return value


class Incident(Fact):
    id: UUID = Field(default_factory=uuid4)
    correlation_key: str = Field(min_length=1, max_length=2000)
    family: Family
    target: str | None = None
    title: str = Field(min_length=1, max_length=200)
    status: IncidentStatus = "open"
    first_seen_at: datetime
    last_seen_at: datetime
    highest_score: int = Field(ge=0, le=100)
    occurrence_count: int = Field(default=1, ge=1)
    observation_count: int = Field(default=1, ge=1)
    revision: int = Field(default=1, ge=1)
    rule_version: UUID
    policy_version: Literal[1] = 1
    reopen_within_seconds: Literal[86400] = 86400
    automatic_resolution: Literal[False] = False
    current_occurrence_id: UUID
    resolved_at: datetime | None = None
    last_reopened_at: datetime | None = None
    previous_incident_id: UUID | None = None

    @property
    def highest_severity(self) -> Severity:
        return severity_for_score(self.highest_score)

    @model_validator(mode="after")
    def valid_projection(self) -> Incident:
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last occurrence cannot precede the first")
        if (self.status == "resolved") != (self.resolved_at is not None):
            raise ValueError("resolved status requires a resolution timestamp")
        return self


class Occurrence(Fact):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    number: int = Field(ge=1)
    started_at: datetime
    last_seen_at: datetime | None = None
    observation_count: int = Field(default=1, ge=0)
    recovered_at: datetime | None = None
    affected_ports: tuple[int, ...] = ()

    @model_validator(mode="after")
    def valid_occurrence(self) -> Occurrence:
        if (self.observation_count == 0) != (self.last_seen_at is None):
            raise ValueError("occurrence measurements and last-seen time must agree")
        if self.last_seen_at is not None and self.last_seen_at < self.started_at:
            raise ValueError("last occurrence measurement precedes its start")
        if self.recovered_at is not None and (
            self.last_seen_at is None or self.recovered_at < self.started_at
        ):
            raise ValueError("recovery cannot precede the occurrence start")
        if any(not 1 <= port <= 65535 for port in self.affected_ports):
            raise ValueError("invalid affected port")
        return self


class IncidentLink(Fact):
    incident_id: UUID
    event_id: UUID
    occurrence_id: UUID
    kind: Literal["anomaly", "observed_recovery"]
    reason: str = Field(min_length=1, max_length=1000)
    linked_at: datetime


class Transition(Fact):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    revision: int = Field(ge=1)
    previous: IncidentStatus | None
    current: IncidentStatus
    action: Literal[
        "opened", "acknowledged", "resolved", "reopened", "recurred", "observed_recovery"
    ]
    reason: str = Field(min_length=1, max_length=2000)
    actor: Literal["operator", "system"]
    at: datetime = Field(default_factory=utc_now)


class IncidentNote(Fact):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    body: str = Field(min_length=1, max_length=4000)
    at: datetime = Field(default_factory=utc_now)
    actor: Literal["operator"] = "operator"
    supersedes_id: UUID | None = None


class SuppressionRule(Fact):
    id: UUID = Field(default_factory=uuid4)
    family: Family | None = None
    rule_code: str | None = Field(default=None, min_length=1, max_length=80)
    target: str | None = Field(default=None, min_length=1, max_length=253)
    log_path: str | None = Field(default=None, min_length=1, max_length=4096)
    starts_at: datetime
    expires_at: datetime
    reason: str = Field(min_length=1, max_length=2000)
    created_at: datetime = Field(default_factory=utc_now)
    disabled_at: datetime | None = None
    disabled_reason: str | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def limited_scope(self) -> SuppressionRule:
        known_codes = {field.replace("_", ".", 1) for field in RulePoints.model_fields}
        if self.rule_code is not None and self.rule_code not in known_codes | {
            "system.probe_error"
        }:
            raise ValueError("unknown suppression rule code")
        if not any((self.family, self.rule_code, self.target, self.log_path)):
            raise ValueError("suppression requires a target, path, family or rule selector")
        if not timedelta(0) < self.expires_at - self.starts_at <= timedelta(days=30):
            raise ValueError("suppression duration must be positive and at most 30 days")
        if (self.disabled_at is None) != (self.disabled_reason is None):
            raise ValueError("disabling suppression requires a reason and timestamp")
        return self


class SuppressionDecision(Fact):
    event_id: UUID
    suppression_id: UUID
    family: Family
    rule_codes: tuple[str, ...]
    reason: str
    starts_at: datetime
    expires_at: datetime
    applied_at: datetime


class IncidentHistory(Fact):
    incident: Incident
    occurrences: tuple[Occurrence, ...]
    transitions: tuple[Transition, ...]
    notes: tuple[IncidentNote, ...]
    links: tuple[IncidentLink, ...]
