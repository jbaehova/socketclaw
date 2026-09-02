from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from socketclaw.domain import (
    Assessment,
    ModelUsage,
    ResponseProposal,
    SecurityEvent,
    Severity,
)


def test_security_event_generates_stable_identity_and_utc_timestamps() -> None:
    event = SecurityEvent(
        source="manual",
        event_type="manual.ping",
        title="Manual ping",
        summary="Ping requested by operator",
        target="1.1.1.1",
    )

    assert event.id.version == 4
    assert event.observed_at.tzinfo is UTC
    assert event.created_at.tzinfo is UTC
    assert event.severity is Severity.INFO


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_assessment_rejects_confidence_outside_probability_range(
    confidence: float,
) -> None:
    with pytest.raises(ValidationError):
        Assessment(
            classification="suspicious",
            confidence=confidence,
            summary="Repeated authentication failures",
            rationale=["Six failures in under five minutes"],
            recommended_actions=["Review the source address"],
        )


@pytest.mark.parametrize(
    "target",
    [
        "not-an-ip",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "ff02::1",
    ],
)
def test_response_proposal_rejects_unsafe_block_target(target: str) -> None:
    with pytest.raises(ValidationError):
        ResponseProposal(
            action="block",
            target_ip=target,
            reason="Synthetic threat",
        )


def test_response_proposal_accepts_reviewable_private_target() -> None:
    proposal = ResponseProposal(
        action="block",
        target_ip="192.168.1.42",
        reason="Repeated failed logins",
    )

    assert proposal.target_ip == "192.168.1.42"
    assert proposal.requires_approval is True


def test_model_usage_calculates_total_when_provider_omits_it() -> None:
    usage = ModelUsage(
        prompt_tokens=120,
        completion_tokens=30,
        reasoning_tokens=10,
        cost_usd=0.003,
        latency_ms=840,
    )

    assert usage.total_tokens == 150


def test_model_usage_rejects_negative_billing_values() -> None:
    with pytest.raises(ValidationError):
        ModelUsage(prompt_tokens=-1)
