"""Bounded candidate batches and durable collector checkpoint contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from .domain import SecurityEvent, utc_now
from .health import ProbeHealthSignal


class CheckpointChange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(min_length=1, max_length=200)
    expected_revision: int = Field(ge=0)
    state: dict[str, JsonValue]


class IngestGap(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    probe_id: str = Field(min_length=1, max_length=200)
    generation: str = Field(min_length=1, max_length=32)
    from_offset: int = Field(ge=0)
    reason: Literal["rotated_source_unavailable", "incomplete_rotated_line"]
    detected_at: datetime = Field(default_factory=utc_now)
    recoverability: Literal["unrecoverable"] = "unrecoverable"


class ProbeBatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    batch_id: UUID = Field(default_factory=uuid4)
    collected_at: datetime = Field(default_factory=utc_now)
    observations: tuple[SecurityEvent, ...] = Field(default=(), max_length=1000)
    checkpoints: tuple[CheckpointChange, ...] = Field(default=(), max_length=256)
    gaps: tuple[IngestGap, ...] = Field(default=(), max_length=256)
    health: tuple[ProbeHealthSignal, ...] = Field(default=(), max_length=256)

    @field_validator("collected_at")
    @classmethod
    def aware_collection_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("batch collection time requires a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def unique_checkpoints(self) -> ProbeBatch:
        ids = [item.probe_id for item in self.checkpoints]
        if len(ids) != len(set(ids)):
            raise ValueError("batch checkpoint IDs must be unique")
        return self


class LogCheckpointState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    parser_version: int = Field(default=2, ge=1, le=2)
    inode: int | None = Field(default=None, ge=0)
    device: int = Field(default=0, ge=0)
    generation: str = Field(default="", max_length=32)
    offset: int = Field(default=0, ge=0)
    head_hash: str = Field(default="", max_length=64)
    head_size: int = Field(default=0, ge=0, le=128)
    tail_hash: str = Field(default="", max_length=64)
    rotation_pending: bool = False
    continuing_line: bool = False
    missing: bool = False
    error: str | None = Field(default=None, max_length=2000)
    read_policy: Literal["tail", "resume", "rotation"] = "tail"
    sampled_size: int = Field(default=0, ge=0)
    backlog_bytes: int = Field(default=0, ge=0)
    last_read_at: datetime | None = None
    last_match_count: int = Field(default=0, ge=0)
    truncated_lines: int = Field(default=0, ge=0)
    gap_count: int = Field(default=0, ge=0)

    @field_validator("head_hash", "tail_hash")
    @classmethod
    def valid_hex(cls, value: str) -> str:
        if value and len(bytes.fromhex(value)) != 32:
            raise ValueError("checkpoint fingerprint must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def valid_identity(self) -> LogCheckpointState:
        if self.inode is not None and len(self.generation) != 32:
            raise ValueError("a file checkpoint requires a generation identity")
        return self


class PortBaselineState(BaseModel):
    """Only committed, individually confirmed port states are comparison evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: tuple[Annotated[int, Field(strict=True, ge=1, le=65535)], ...] = ()
    opened: tuple[int, ...] = ()
    confirmed_at: dict[int, datetime] = Field(default_factory=lambda: dict[int, datetime]())

    @model_validator(mode="after")
    def valid_baseline(self) -> PortBaselineState:
        scope = set(self.scope)
        if len(scope) != len(self.scope) or len(scope) > 1024:
            raise ValueError("baseline scope must contain at most 1024 unique ports")
        if not set(self.opened) <= self.confirmed_at.keys() <= scope:
            raise ValueError("baseline states must belong to the confirmed watch scope")
        if any(value.tzinfo is None for value in self.confirmed_at.values()):
            raise ValueError("baseline confirmation times must have a timezone")
        return self
