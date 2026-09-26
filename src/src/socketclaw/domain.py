"""Typed domain records shared by monitoring, storage, OpenAI, and UI."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

_RationaleItem = Annotated[str, Field(min_length=1, max_length=1000)]
_ActionItem = Annotated[str, Field(min_length=1, max_length=1000)]


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObservationOutcome(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"
    ERROR = "error"


class EventSource(StrEnum):
    PING = "ping"
    PORT_SCAN = "port_scan"
    LOG = "log"
    MANUAL = "manual"
    SYSTEM = "system"


class InvestigationState(StrEnum):
    NOT_REQUESTED = "not_requested"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class DetectionSignal(BaseModel):
    """One explainable rule that contributed to an event score."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    code: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)
    points: int = Field(ge=0, le=100)
    detail: str = Field(min_length=1, max_length=500)


class DetectionResult(BaseModel):
    """Deterministic severity and the exact signals behind it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    score: int = Field(ge=0, le=100)
    severity: Severity
    signals: tuple[DetectionSignal, ...] = ()

    @model_validator(mode="after")
    def validate_explanation(self) -> DetectionResult:
        expected_score = min(100, sum(signal.points for signal in self.signals))
        if self.score != expected_score:
            raise ValueError("score must equal the capped sum of signal points")
        expected_severity = severity_for_score(self.score)
        if self.severity is not expected_severity:
            raise ValueError("severity must match the score")
        codes = [signal.code for signal in self.signals]
        if len(codes) != len(set(codes)):
            raise ValueError("detection signal codes must be unique")
        return self


class SecurityEvent(BaseModel):
    """A normalized observation emitted by any SocketClaw source."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    id: UUID = Field(default_factory=uuid4)
    observed_at: datetime = Field(default_factory=utc_now)
    ingested_at: datetime | None = None
    source_at: datetime | None = None
    collected_at: datetime | None = None
    committed_at: datetime | None = None
    correlation_at: datetime | None = None
    time_basis: str = "legacy_collection"
    rule_version: UUID | None = None
    source_key: str | None = Field(default=None, min_length=1, max_length=200)
    outcome: ObservationOutcome = ObservationOutcome.UNKNOWN
    observed_quality: Literal["recorded", "legacy_unknown"] = "recorded"
    source: EventSource
    event_type: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=2000)
    target: str | None = Field(default=None, min_length=1, max_length=253)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    score: int = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.INFO
    investigation_state: InvestigationState = InvestigationState.NOT_REQUESTED
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("ingested_at", "source_at", "collected_at", "committed_at", "correlation_at")
    @classmethod
    def require_optional_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("observed_at", "created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)


class ResponseProposal(BaseModel):
    """A reviewable response; execution is a separate, explicit operation."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    action: Literal["block", "monitor", "notify"]
    target_ip: str | None = Field(default=None, min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=1000)
    command: str | None = Field(default=None, min_length=1, max_length=2000)
    platform: str | None = Field(default=None, min_length=1, max_length=80)
    reversible: bool = True
    requires_approval: Literal[True] = True

    @model_validator(mode="after")
    def validate_block_target(self) -> ResponseProposal:
        if self.target_ip is None:
            if self.action == "block":
                raise ValueError("a block proposal requires an IP address")
            return self
        try:
            address = ipaddress.ip_address(self.target_ip)
        except ValueError as exc:
            raise ValueError("target_ip must be a valid IP address") from exc
        if self.action == "block" and (
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
            or address.is_reserved
            or getattr(address, "scope_id", None) is not None
            or (address.version == 4 and address.packed[-1] == 255)
        ):
            raise ValueError("the proposed IP address is unsafe to block")
        object.__setattr__(self, "target_ip", str(address))
        return self


class Assessment(BaseModel):
    """A validated incident assessment returned by a curated model."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    classification: Literal["benign", "suspicious", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=2000)
    rationale: tuple[_RationaleItem, ...] = Field(min_length=1, max_length=12)
    recommended_actions: tuple[_ActionItem, ...] = Field(default_factory=tuple, max_length=12)
    response_proposal: ResponseProposal | None = None

    @model_validator(mode="after")
    def reject_benign_block(self) -> Assessment:
        if (
            self.classification == "benign"
            and self.response_proposal is not None
            and self.response_proposal.action == "block"
        ):
            raise ValueError("a benign assessment cannot propose blocking an address")
        return self


class ModelUsage(BaseModel):
    """OpenAI token usage and estimated billing for one investigation."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)
    provider_request_id: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def calculate_total(self) -> ModelUsage:
        expected_total = self.prompt_tokens + self.completion_tokens
        if self.total_tokens is None:
            object.__setattr__(self, "total_tokens", expected_total)
        elif self.total_tokens != expected_total:
            raise ValueError("total_tokens must equal prompt_tokens plus completion_tokens")
        if self.reasoning_tokens > self.completion_tokens:
            raise ValueError("reasoning_tokens cannot exceed completion_tokens")
        return self


class InvestigationResult(BaseModel):
    """Assessment plus the OpenAI contract and accounting used."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    assessment: Assessment
    usage: ModelUsage
    model_id: str = Field(min_length=1, max_length=200)
    requested_effort: str = Field(min_length=1, max_length=20)


def severity_for_score(score: int) -> Severity:
    """Map a normalized detection score to its canonical severity."""
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def response_actor_target(event: SecurityEvent) -> str | None:
    """Select a recorded actor; never mistake a structured log's victim for it."""
    actors = {
        str(value)
        for key in ("actor_ip", "source_ip")
        if isinstance(value := event.evidence.get(key), str) and value
    }
    if len(actors) > 1:
        return None
    if actors:
        return next(iter(actors))
    if event.source == EventSource.LOG and event.evidence.get("asset") is not None:
        return None
    return event.target
