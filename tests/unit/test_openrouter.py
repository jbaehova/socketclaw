from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from socketclaw.config import MODEL_PRESETS
from socketclaw.domain import SecurityEvent
from socketclaw.openrouter import (
    ErrorKind,
    OpenRouterClient,
    OpenRouterError,
    redact_secrets,
)


def event_fixture() -> SecurityEvent:
    return SecurityEvent(
        source="log",
        event_type="log.auth_failure",
        title="Authentication failure burst",
        summary="Six failed SSH logins from one source",
        target="198.51.100.24",
        evidence={
            "message": "Failed password for root from 198.51.100.24",
            "attempts": 6,
        },
        score=100,
        severity="critical",
    )


def assessment_content() -> dict[str, Any]:
    return {
        "classification": "critical",
        "confidence": 0.97,
        "summary": "A concentrated SSH authentication attack is in progress.",
        "rationale": [
            "Six failed root logins originated from one address.",
            "The deterministic event score is 100.",
        ],
        "recommended_actions": [
            "Review SSH authentication logs.",
            "Temporarily block the source after operator approval.",
        ],
        "response_proposal": {
            "action": "block",
            "target_ip": "198.51.100.24",
            "reason": "Concentrated SSH authentication failures",
        },
    }


def success_response(*, content: str | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "gen-test-request",
            "model": "moonshotai/kimi-k3",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content or json.dumps(assessment_content()),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 180,
                "completion_tokens": 70,
                "total_tokens": 270,
                "cost": 0.0042,
                "completion_tokens_details": {"reasoning_tokens": 20},
            },
        },
    )


class SequenceTransport:
    def __init__(
        self,
        responses: list[httpx.Response | Exception | Callable[[httpx.Request], httpx.Response]],
    ) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        current = self.responses.pop(0)
        if isinstance(current, Exception):
            raise current
        if callable(current):
            return current(request)
        return current


def mock_transport(sequence: SequenceTransport) -> httpx.MockTransport:
    return httpx.MockTransport(sequence)


@pytest.mark.asyncio
async def test_validate_key_uses_current_key_endpoint_and_parses_status() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                200,
                json={
                    "data": {
                        "label": "socketclaw-test",
                        "is_free_tier": False,
                        "limit": 25.0,
                        "limit_remaining": 21.5,
                        "usage": 3.5,
                    }
                },
            )
        ]
    )
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    status = await client.validate_key()

    request = sequence.requests[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v1/key"
    assert request.headers["Authorization"] == "Bearer sk-or-v1-secret"
    assert status.label == "socketclaw-test"
    assert status.limit_remaining == 21.5
    assert status.is_free_tier is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("preset_key", "model_id", "effort"),
    [
        ("terra", "openai/gpt-5.6-terra", "high"),
        ("kimi", "moonshotai/kimi-k3", "max"),
        ("qwen", "qwen/qwen3.7-max", "high"),
    ],
)
async def test_investigation_sends_exact_model_effort_and_schema(
    preset_key: str,
    model_id: str,
    effort: str,
) -> None:
    sequence = SequenceTransport([success_response()])
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    await client.investigate(event_fixture(), MODEL_PRESETS[preset_key])

    request = sequence.requests[0]
    body = json.loads(request.content)
    assert request.url.path == "/api/v1/chat/completions"
    assert request.headers["HTTP-Referer"] == "https://github.com/jbaehova/SocketClaw"
    assert request.headers["X-Title"] == "SocketClaw"
    assert body["model"] == model_id
    assert body["reasoning"] == {"effort": effort, "exclude": True}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["name"] == ("socketclaw_incident_assessment")
    schema = body["response_format"]["json_schema"]["schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    proposal_schema = schema["$defs"]["ResponseProposal"]
    assert proposal_schema["additionalProperties"] is False
    assert set(proposal_schema["required"]) == set(proposal_schema["properties"])
    assert body["stream"] is False
    assert body["max_tokens"] == 1200


@pytest.mark.asyncio
async def test_investigation_parses_assessment_usage_cost_and_request_id() -> None:
    sequence = SequenceTransport([success_response()])
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    result = await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])

    assert result.assessment.classification == "critical"
    assert result.assessment.confidence == 0.97
    assert result.assessment.response_proposal is not None
    assert result.assessment.response_proposal.target_ip == "198.51.100.24"
    assert result.model_id == "moonshotai/kimi-k3"
    assert result.requested_effort == "max"
    assert result.usage.prompt_tokens == 180
    assert result.usage.completion_tokens == 70
    assert result.usage.reasoning_tokens == 20
    assert result.usage.total_tokens == 270
    assert result.usage.cost_usd == 0.0042
    assert result.usage.provider_request_id == "gen-test-request"
    assert result.usage.latency_ms >= 0


@pytest.mark.asyncio
async def test_fenced_json_response_is_parsed_without_relaxing_schema() -> None:
    fenced = f"```json\n{json.dumps(assessment_content())}\n```"
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(SequenceTransport([success_response(content=fenced)])),
    )

    result = await client.investigate(event_fixture(), MODEL_PRESETS["terra"])

    assert result.assessment.summary.startswith("A concentrated SSH")


@pytest.mark.asyncio
async def test_401_is_non_retryable_and_secret_is_redacted() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                401,
                json={
                    "error": {
                        "code": 401,
                        "message": "Invalid key sk-or-v1-secret",
                    }
                },
            )
        ]
    )
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    with pytest.raises(OpenRouterError) as caught:
        await client.validate_key()

    assert caught.value.kind is ErrorKind.AUTHENTICATION
    assert caught.value.status_code == 401
    assert "sk-or-v1-secret" not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
async def test_402_is_reported_as_insufficient_credits() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                402,
                json={"error": {"code": 402, "message": "Insufficient credits"}},
            )
        ]
    )
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    with pytest.raises(OpenRouterError) as caught:
        await client.investigate(event_fixture(), MODEL_PRESETS["terra"])

    assert caught.value.kind is ErrorKind.CREDITS
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
async def test_403_is_non_retryable_and_reported_as_forbidden() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                403,
                json={"error": {"code": 403, "message": "Guardrail rejected request"}},
            )
        ]
    )
    client = OpenRouterClient("sk-or-v1-secret", transport=mock_transport(sequence))

    with pytest.raises(OpenRouterError) as caught:
        await client.investigate(event_fixture(), MODEL_PRESETS["terra"])

    assert caught.value.kind is ErrorKind.FORBIDDEN
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
async def test_429_honors_bounded_retry_after_then_succeeds() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    sequence = SequenceTransport(
        [
            httpx.Response(
                429,
                headers={"Retry-After": "45"},
                json={"error": {"code": 429, "message": "Slow down"}},
            ),
            success_response(),
        ]
    )
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    result = await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])

    assert result.assessment.classification == "critical"
    assert delays == [30.0]
    assert len(sequence.requests) == 2


@pytest.mark.asyncio
async def test_503_retries_three_total_attempts_then_reports_unavailable() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={"error": {"code": 503, "message": "No provider available"}},
        )

    sequence = SequenceTransport([unavailable, unavailable, unavailable])
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    with pytest.raises(OpenRouterError) as caught:
        await client.investigate(event_fixture(), MODEL_PRESETS["qwen"])

    assert caught.value.kind is ErrorKind.UNAVAILABLE
    assert len(sequence.requests) == 3
    assert delays == [0.25, 0.5]


@pytest.mark.asyncio
async def test_timeout_is_retried_then_can_recover() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    sequence = SequenceTransport(
        [
            httpx.ReadTimeout("provider timed out"),
            success_response(),
        ]
    )
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    result = await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])

    assert result.assessment.classification == "critical"
    assert delays == [0.25]


@pytest.mark.asyncio
async def test_missing_usage_is_normalized_to_zero() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload.pop("usage")
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    result = await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])

    assert result.usage.prompt_tokens == 0
    assert result.usage.completion_tokens == 0
    assert result.usage.total_tokens == 0
    assert result.usage.cost_usd == 0


@pytest.mark.asyncio
async def test_malformed_usage_is_reported_as_response_error() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["usage"]["prompt_tokens"] = "not-a-number"
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenRouterError) as caught:
        await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])

    assert caught.value.kind is ErrorKind.RESPONSE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"choices": []}),
        httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "not json"}}]},
        ),
        httpx.Response(
            200,
            json={"error": {"code": 502, "message": "Provider failed"}},
        ),
    ],
)
async def test_unusable_200_response_is_reported_as_response_error(
    response: httpx.Response,
) -> None:
    client = OpenRouterClient(
        "sk-or-v1-secret",
        transport=mock_transport(SequenceTransport([response])),
    )

    with pytest.raises(OpenRouterError) as caught:
        await client.investigate(event_fixture(), MODEL_PRESETS["terra"])

    assert caught.value.kind is ErrorKind.RESPONSE


def test_redaction_removes_explicit_and_openrouter_shaped_secrets() -> None:
    rendered = redact_secrets(
        "explicit=my-secret automatic=sk-or-v1-abcdefghijklmnopqrstuvwxyz",
        ["my-secret"],
    )

    assert rendered == "explicit=[REDACTED] automatic=[REDACTED]"
