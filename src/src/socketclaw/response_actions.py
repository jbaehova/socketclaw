"""Operator-reported response outcomes, distinct from proposal approval."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain import utc_now


class ActionRecord(BaseModel):
    """An append-only operator statement; never an automatic execution receipt."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    status: Literal["user_performed", "failed", "rolled_back", "verified"]
    summary: str = Field(min_length=1, max_length=4000)
    evidence_ids: tuple[UUID, ...] = Field(default=(), max_length=100)
    proposal_id: UUID | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("action timestamps require a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def verification_needs_evidence(self) -> ActionRecord:
        if self.status == "verified" and not self.evidence_ids:
            raise ValueError("verification requires subsequent observation evidence IDs")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("action evidence IDs must be unique")
        return self


def incident_runbook(family: str) -> tuple[str, ...]:
    common = (
        "Record any action you perform and its actual outcome; approval alone executes nothing.",
        "Compare subsequent observations with the same asset and occurrence before "
        "recording verification.",
        "If the action fails, record the failure and any rollback. Recovery "
        "observation and operator resolution are separate.",
    )
    specific = {
        "availability": (
            "Confirm the expected service endpoint and maintenance window.",
            "Check the service locally, then test its TCP or HTTP endpoint; ICMP "
            "alone cannot verify service health.",
            "After an authorized repair, wait for the configured recovery confirmation count.",
        ),
        "exposure": (
            "Compare the changed port with the intended binding address and allowed exposure.",
            "Identify the listening process and executable if collected; missing "
            "process evidence is unknown.",
            "After an authorized binding or service change, rescan and confirm the "
            "unexpected listener is absent.",
        ),
        "authentication": (
            "Match asset, account and actor address before linking failed and "
            "successful authentication.",
            "Confirm whether a success or session-open observation actually "
            "exists; failures alone do not prove entry.",
            "Review any proposed actor block separately from the victim server and "
            "preserve an administrative access path.",
        ),
        "collector": (
            "Check source permissions, path, collector status and the last "
            "successful collection time.",
            "Restore collection and verify a fresh successful observation; zero "
            "events alone do not prove safety.",
        ),
    }.get(family, ("Review the linked raw observations and the active detection rules.",))
    return (*specific, *common)
