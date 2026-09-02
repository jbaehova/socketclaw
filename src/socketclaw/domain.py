"""Typed domain records shared by monitoring, storage, OpenAI, and UI."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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

    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)
    points: int = Field(ge=0, le=100)
    detail: str = Field(min_length=1, max_length=500)


class DetectionResult(BaseModel):
    """Deterministic severity and the exact signals behind it."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    severity: Severity
    signals: tuple[DetectionSignal, ...] = ()


class SecurityEvent(BaseModel):
    """A normalized observation emitted by any SocketClaw source."""

    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    observed_at: datetime = Field(default_factory=utc_now)
    source: EventSource
    event_type: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=2000)
    target: str | None = Field(default=None, max_length=253)
    evidence: dict[str, Any] = Field(default_factory=dict)
    score: int = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.INFO
    investigation_state: InvestigationState = InvestigationState.NOT_REQUESTED
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("observed_at", "created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)


class ResponseProposal(BaseModel):
    """A reviewable response; execution is a separate, explicit operation."""

    model_config = ConfigDict(frozen=True)

    action: Literal["block", "monitor", "notify"]
    target_ip: str | None = None
    reason: str = Field(min_length=1, max_length=1000)
    command: str | None = Field(default=None, max_length=2000)
    platform: str | None = Field(default=None, max_length=80)
    reversible: bool = True
    requires_approval: bool = True

    @model_validator(mode="after")
    def validate_block_target(self) -> ResponseProposal:
        if self.action != "block":
            return self
        if self.target_ip is None:
            raise ValueError("a block proposal requires an IP address")
        try:
            address = ipaddress.ip_address(self.target_ip)
        except ValueError as exc:
            raise ValueError("a block proposal requires a valid IP address") from exc
        if (
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
            or address.is_reserved
            or (address.version == 4 and address.packed[-1] == 255)
        ):
            raise ValueError("the proposed IP address is unsafe to block")
        return self


class Assessment(BaseModel):
    """A validated incident assessment returned by a curated model."""

    model_config = ConfigDict(frozen=True)

    classification: Literal["benign", "suspicious", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=2000)
    rationale: list[str] = Field(min_length=1, max_length=12)
    recommended_actions: list[str] = Field(default_factory=list, max_length=12)
    response_proposal: ResponseProposal | None = None


class ModelUsage(BaseModel):
    """OpenAI token usage and estimated billing for one investigation."""

    model_config = ConfigDict(frozen=True)

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)
    provider_request_id: str | None = None

    @model_validator(mode="after")
    def calculate_total(self) -> ModelUsage:
        if self.total_tokens is None:
            object.__setattr__(
                self,
                "total_tokens",
                self.prompt_tokens + self.completion_tokens,
            )
        return self


class InvestigationResult(BaseModel):
    """Assessment plus the OpenAI contract and accounting used."""

    model_config = ConfigDict(frozen=True)

    assessment: Assessment
    usage: ModelUsage
    model_id: str
    requested_effort: str
