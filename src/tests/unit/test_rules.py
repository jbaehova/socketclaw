from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from socketclaw.config import AppConfig, ConfigStore
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.rules import RuleConfig, RulePoints


@pytest.mark.parametrize(
    "changes",
    [
        {"window_seconds": 0},
        {"window_seconds": 86401},
        {"window_seconds": True},
        {"auth_failure_count": 1},
        {"auth_failure_count": 1.5},
        {"auth_failure_count": True},
        {"firewall_denial_count": 10001},
        {"ping_high_loss_percent": 100},
        {"ping_high_loss_percent": 20},
        {"ping_degraded_percent": 60},
        {"preset": "shell"},
        {"script": "echo nope"},
    ],
)
def test_invalid_units_ranges_and_executable_settings_are_rejected(changes):
    with pytest.raises(ValidationError):
        RuleConfig.model_validate(changes)


def test_custom_rule_settings_survive_toml_roundtrip(tmp_path: Path):
    config = AppConfig(
        rules=RuleConfig(
            window_seconds=120, auth_failure_count=3, points=RulePoints(log_auth_failure=40)
        )
    )
    store = ConfigStore(tmp_path)
    store.save(config)
    assert store.load() == config
    assert "[rules.points]" in store.config_path.read_text()
    assert config.rules.fingerprint != RuleConfig().fingerprint


def test_rule_thresholds_points_and_explanations_match_the_active_policy():
    detector = Detector(RuleConfig(ping_high_loss_percent=70, points=RulePoints(ping_degraded=7)))
    event = SecurityEvent(
        source="ping",
        event_type="ping.result",
        title="Ping",
        summary="Measured loss",
        evidence={"packet_loss": 60},
    )
    assert detector.score(event, []).score == 7
    with pytest.raises(ValidationError):
        RulePoints(ping_total_loss=True)


def test_legacy_snapshot_validates_without_rewriting_its_bytes():
    import hashlib
    import json
    from datetime import UTC, datetime
    from uuid import uuid4

    from socketclaw.rules import RuleVersion

    snapshot = json.loads(RuleConfig().snapshot())
    snapshot["engine_version"] = 2
    snapshot["parser_version"] = 2
    for code in (
        "service_failed",
        "port_unexpected_exposure",
        "service_unknown",
        "log_unverified_indicator",
        "log_sudo_execution",
        "log_auth_after_failures",
    ):
        snapshot["config"]["points"].pop(code)
    original = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    decoded = RuleVersion(
        id=uuid4(),
        applied_at=datetime(2026, 9, 1, tzinfo=UTC),
        snapshot_json=original,
        fingerprint=hashlib.sha256(original.encode()).hexdigest(),
    )
    assert decoded.snapshot_json == original
    assert "service_failed" not in decoded.snapshot_json
    unknown = original.replace('"engine_version":2', '"engine_version":999')
    with pytest.raises(ValidationError, match="unsupported rule snapshot version"):
        RuleVersion(
            id=uuid4(),
            applied_at=datetime(2026, 9, 1, tzinfo=UTC),
            snapshot_json=unknown,
            fingerprint=hashlib.sha256(unknown.encode()).hexdigest(),
        )
