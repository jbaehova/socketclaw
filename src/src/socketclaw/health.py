"""Typed collector health and monotonic scheduling calculations."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .domain import utc_now


class ProbeHealthSignal(BaseModel):
    """A collector can report degradation without throwing an exception."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(min_length=1, max_length=300)
    state: Literal["healthy", "degraded"]
    error_kind: str | None = Field(default=None, max_length=80)
    detail: str | None = Field(default=None, max_length=2000)


class ProbeHealth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    probe_id: str = Field(min_length=1, max_length=300)
    state: Literal["unknown", "healthy", "degraded"] = "unknown"
    activity: Literal["idle", "scheduled", "manual", "interrupted"] = "idle"
    interval_seconds: float = Field(gt=0)
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_observation_at: datetime | None = None
    next_due_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)
    error_kind: str | None = Field(default=None, max_length=80)
    error: str | None = Field(default=None, max_length=2000)
    consecutive_errors: int = Field(default=0, ge=0)
    skipped_ticks: int = Field(default=0, ge=0)
    lag_ms: float = Field(default=0, ge=0)
    duration_ms: float = Field(default=0, ge=0)
    pending_observations: int = Field(default=0, ge=0)

    @field_validator(
        "last_attempt_at", "last_success_at", "last_observation_at", "next_due_at", "updated_at"
    )
    @classmethod
    def aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("health timestamps require a timezone")
            return value.astimezone(UTC)
        return value

    def is_stale(self, now: datetime) -> bool:
        """Allow three scheduled intervals, with a ten-second startup floor."""
        return self.last_success_at is None or not (
            0 <= (now - self.last_success_at).total_seconds() <= max(10, 3 * self.interval_seconds)
        )


def initial_jitter(probe_id: str, interval: float) -> float:
    """Stable startup spread, bounded to 10% of an interval and 100 ms."""
    fraction = int.from_bytes(hashlib.sha256(probe_id.encode()).digest()[:2], "big") / 65536
    return fraction * min(0.1, interval * 0.1)


def next_tick(due: float, interval: float, finished: float) -> tuple[float, int]:
    """Advance on the original start grid, skipping elapsed ticks without overlap."""
    following = due + interval
    skipped = max(0, math.floor((finished - following) / interval) + 1)
    return following + skipped * interval, skipped


def coverage_summary(config: object, health: tuple[ProbeHealth, ...]) -> str:
    """Describe configured coverage separately from recent collector success."""
    targets = getattr(config, "targets", ())
    logs = getattr(config, "log_paths", ())
    services = getattr(config, "services", ())
    fresh = sum(not item.is_stale(utc_now()) for item in health)
    base = (
        f"{len(targets)} ICMP/TCP targets, {len(services)} explicit services, "
        f"{len(logs)} file log sources. "
        f"{fresh}/{len(health)} collectors have recent successful reads."
    )
    if not logs:
        base += " Authentication and security logs are not monitored."
    if not services:
        base += " No required-service availability policy is configured."
    return base


def source_coverage(health: ProbeHealth, *, configured: bool = True) -> dict[str, object]:
    """Keep source access, parser coverage and freshness as independent dimensions."""
    kind = health.error_kind
    supported = kind not in {"unsupported", "unsupported_format"}
    readable = kind not in {"missing_source", "permission", "permission_denied", "read_error"}
    return {
        "configured": configured,
        "supported": supported,
        "readable": readable if health.last_attempt_at is not None else None,
        "collecting": health.activity in {"scheduled", "manual"},
        "fresh": not health.is_stale(utc_now()),
        "partial": kind in {"partial", "partial_format", "unparsed_lines"},
        "last_success_at": health.last_success_at.isoformat() if health.last_success_at else None,
        "reason": health.error,
    }
