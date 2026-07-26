from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from socketclaw.config import MODEL_PRESETS, ConfigStore
from socketclaw.domain import SecurityEvent
from socketclaw.openrouter import OpenRouterClient


def _live_key() -> str:
    if os.getenv("SOCKETCLAW_LIVE_OPENROUTER") != "1":
        pytest.skip("set SOCKETCLAW_LIVE_OPENROUTER=1 to spend OpenRouter credits")
    direct = os.getenv("OPENROUTER_API_KEY")
    if direct:
        return direct
    env_file = os.getenv("SOCKETCLAW_LIVE_ENV_FILE")
    if not env_file:
        pytest.skip("no OpenRouter key or SOCKETCLAW_LIVE_ENV_FILE configured")
    path = Path(env_file)
    if path.name != ".env":
        pytest.fail("SOCKETCLAW_LIVE_ENV_FILE must point to an .env file")
    key = ConfigStore(path.parent).load_api_key()
    if not key:
        pytest.skip("the selected .env file has no OPENROUTER_API_KEY")
    return key


@pytest.mark.asyncio
@pytest.mark.parametrize("preset_key", ["terra", "kimi", "qwen"])
async def test_curated_model_can_assess_a_minimal_paid_event(
    preset_key: str,
) -> None:
    key = _live_key()
    preset = MODEL_PRESETS[preset_key]
    client = OpenRouterClient(key, timeout=90.0)
    event = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        title="New administrative port",
        summary="TCP port 22 became reachable on the configured test target.",
        target="198.51.100.24",
        evidence={"newly_opened": [22], "open_ports": [22]},
        score=55,
        severity="medium",
    )

    result = await client.investigate(event, preset)

    assert result.assessment.summary.strip()
    assert result.assessment.rationale
    assert result.model_id
    assert result.requested_effort == preset.effort
    assert result.usage.latency_ms > 0
    assert result.usage.total_tokens is not None
    assert result.usage.total_tokens > 0
    assert result.usage.cost_usd >= 0

    evidence_directory = Path("artifacts/live-openrouter")
    evidence_directory.mkdir(parents=True, exist_ok=True)
    evidence = {
        "preset": preset.key,
        "requested_model_id": preset.model_id,
        "provider_model_id": result.model_id,
        "requested_effort": result.requested_effort,
        "classification": result.assessment.classification,
        "latency_ms": result.usage.latency_ms,
        "prompt_tokens": result.usage.prompt_tokens,
        "completion_tokens": result.usage.completion_tokens,
        "reasoning_tokens": result.usage.reasoning_tokens,
        "total_tokens": result.usage.total_tokens,
        "cost_usd": result.usage.cost_usd,
        "provider_request_id": result.usage.provider_request_id,
    }
    (evidence_directory / f"{preset.key}.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
