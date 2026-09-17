"""Validated numeric rule policy and immutable, reproducible version snapshots."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .probes.log_parser import PARSER_VERSION

Points = Annotated[int, Field(strict=True, ge=0, le=100)]
Count = Annotated[int, Field(strict=True, ge=2, le=10000)]
Percentage = Annotated[int, Field(strict=True, ge=1, le=100)]


class RulePoints(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ping_total_loss: Points = 70
    ping_high_loss: Points = 45
    ping_degraded: Points = 25
    ping_sustained_loss: Points = 25
    port_sensitive_exposure: Points = 35
    port_newly_opened: Points = 20
    port_sensitive_opened: Points = 35
    port_open_burst: Points = 60
    port_closed: Points = 0
    log_malware_indicator: Points = 80
    log_auth_failure: Points = 25
    log_auth_burst: Points = 75
    log_privilege_escalation: Points = 45
    log_firewall_denial: Points = 15
    log_firewall_denial_burst: Points = 40

    def for_code(self, code: str) -> int:
        return int(self.model_dump()[code.replace(".", "_")])


class RuleConfig(BaseModel):
    """Units are seconds, percentages, or inclusive observation counts."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    preset: Literal["balanced"] = "balanced"
    window_seconds: int = Field(default=300, strict=True, ge=1, le=86400)
    ping_degraded_percent: Percentage = 20
    ping_high_loss_percent: Percentage = 50
    ping_sustained_count: Count = 4
    auth_failure_count: Count = 6
    firewall_denial_count: Count = 10
    port_open_count: int = Field(default=5, strict=True, ge=2, le=1024)
    points: RulePoints = Field(default_factory=RulePoints)

    @model_validator(mode="after")
    def ordered_loss_thresholds(self) -> RuleConfig:
        if not self.ping_degraded_percent < self.ping_high_loss_percent < 100:
            raise ValueError("loss thresholds must satisfy degraded < high < 100 percent")
        return self

    def snapshot(self) -> str:
        return json.dumps(
            {"engine_version": 2, "parser_version": PARSER_VERSION, "config": self.model_dump()},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.snapshot().encode()).hexdigest()


class RuleVersion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    applied_at: datetime
    snapshot_json: str
    fingerprint: str

    @model_validator(mode="after")
    def validate_snapshot(self) -> RuleVersion:
        if self.applied_at.tzinfo is None:
            raise ValueError("rule activation time requires a timezone")
        if hashlib.sha256(self.snapshot_json.encode()).hexdigest() != self.fingerprint:
            raise ValueError("rule snapshot hash mismatch")
        snapshot = json.loads(self.snapshot_json)
        if set(snapshot) != {"engine_version", "parser_version", "config"}:
            raise ValueError("invalid rule snapshot fields")
        if snapshot["engine_version"] != 2 or snapshot["parser_version"] != PARSER_VERSION:
            raise ValueError("unsupported rule snapshot version")
        RuleConfig.model_validate(snapshot["config"])
        return self
