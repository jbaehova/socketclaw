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
