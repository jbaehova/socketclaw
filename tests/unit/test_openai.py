from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from socketclaw.domain import SecurityEvent
from socketclaw.openai import ErrorKind, OpenAIClient, OpenAIError, redact_secrets


def event_fixture(*, severity: str = "critical") -> SecurityEvent:
    return SecurityEvent(
        source="log",
        event_type="log.auth_failure",
        title="Repeated SSH authentication failures",
        summary="Twelve failed root logins were observed in sixty seconds.",
        target="198.51.100.24",
        evidence={"attempts": 12},
        score=95,
        severity=severity,
    )


def assessment_content() -> dict[str, object]:
    return {
        "classification": "critical",
        "confidence": 0.97,
        "summary": "A concentrated SSH authentication attack is likely.",
        "rationale": ["Repeated root authentication failures were observed."],
        "recommended_actions": ["Review the source before blocking it."],
        "response_proposal": {
            "action": "block",
            "target_ip": "198.51.100.24",
            "reason": "Concentrated SSH authentication failures",
            "command": None,
            "platform": None,
            "reversible": True,
            "requires_approval": True,
        },
    }


def success_response(*, content: str | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "resp_test_request",
            "object": "response",
            "status": "completed",
            "model": "gpt-5.6-luna",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {
                            "type": "output_text",
                            "text": content or json.dumps(assessment_content()),
                            "annotations": [],
                        }
                    ],
                }
            ],
            "usage": {
                "input_tokens": 180,
                "input_tokens_details": {
                    "cached_tokens": 0,
                    "cache_write_tokens": 0,
                },
                "output_tokens": 70,
                "output_tokens_details": {"reasoning_tokens": 20},
                "total_tokens": 250,
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
async def test_validate_key_retrieves_the_fixed_luna_model() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                200,
                json={
                    "id": "gpt-5.6-luna",
                    "object": "model",
                    "created": 1,
                    "owned_by": "openai",
                },
            )
        ]
    )
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    access = await client.validate_key()

    request = sequence.requests[0]
    assert request.method == "GET"
    assert request.url == "https://api.openai.com/v1/models/gpt-5.6-luna"
    assert request.headers["Authorization"] == "Bearer sk-proj-secret-value"
    assert access.id == "gpt-5.6-luna"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("severity", "effort"),
    [("medium", "medium"), ("high", "high"), ("critical", "high")],
)
async def test_investigation_uses_luna_and_severity_aware_effort(
    severity: str,
    effort: str,
) -> None:
    sequence = SequenceTransport([success_response()])
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    await client.investigate(event_fixture(severity=severity))

    request = sequence.requests[0]
    body = json.loads(request.content)
    assert request.url == "https://api.openai.com/v1/responses"
    assert "HTTP-Referer" not in request.headers
    assert "X-Title" not in request.headers
    assert body["model"] == "gpt-5.6-luna"
    assert body["reasoning"] == {"effort": effort}
    assert body["store"] is False
    assert body["max_output_tokens"] == 4000
    assert body["text"]["verbosity"] == "low"
    response_format = body["text"]["format"]
    assert response_format["type"] == "json_schema"
    assert response_format["strict"] is True
    assert response_format["name"] == "socketclaw_incident_assessment"
    schema = response_format["schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    proposal_schema = schema["$defs"]["ResponseProposal"]
    assert proposal_schema["additionalProperties"] is False
    assert set(proposal_schema["required"]) == set(proposal_schema["properties"])


@pytest.mark.asyncio
async def test_investigation_parses_assessment_usage_and_estimated_cost() -> None:
    sequence = SequenceTransport([success_response()])
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    result = await client.investigate(event_fixture())

    assert result.assessment.classification == "critical"
    assert result.assessment.confidence == 0.97
    assert result.assessment.response_proposal is not None
    assert result.assessment.response_proposal.target_ip == "198.51.100.24"
    assert result.model_id == "gpt-5.6-luna"
    assert result.requested_effort == "high"
    assert result.usage.prompt_tokens == 180
    assert result.usage.completion_tokens == 70
    assert result.usage.reasoning_tokens == 20
    assert result.usage.total_tokens == 250
    assert result.usage.cost_usd == pytest.approx(0.00012)
    assert result.usage.provider_request_id == "resp_test_request"
    assert result.usage.latency_ms >= 0


@pytest.mark.asyncio
async def test_fenced_json_response_is_parsed_without_relaxing_schema() -> None:
    fenced = f"```json\n{json.dumps(assessment_content())}\n```"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([success_response(content=fenced)])),
    )

    result = await client.investigate(event_fixture())

    assert result.assessment.summary.startswith("A concentrated SSH")


@pytest.mark.asyncio
async def test_401_is_non_retryable_and_secret_is_redacted() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                401,
                json={"error": {"message": "Invalid key sk-proj-secret-value"}},
            )
        ]
    )
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    with pytest.raises(OpenAIError) as caught:
        await client.validate_key()

    assert caught.value.kind is ErrorKind.AUTHENTICATION
    assert caught.value.status_code == 401
    assert "sk-proj-secret-value" not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "kind"),
    [(402, ErrorKind.CREDITS), (403, ErrorKind.FORBIDDEN), (422, ErrorKind.INVALID_REQUEST)],
)
async def test_non_retryable_http_errors_are_classified(
    status_code: int,
    kind: ErrorKind,
) -> None:
    sequence = SequenceTransport(
        [httpx.Response(status_code, json={"error": {"message": "Request rejected"}})]
    )
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is kind
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
                json={"error": {"message": "Slow down"}},
            ),
            success_response(),
        ]
    )
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    result = await client.investigate(event_fixture())

    assert result.assessment.classification == "critical"
    assert delays == [30.0]
    assert len(sequence.requests) == 2


@pytest.mark.asyncio
async def test_503_retries_three_total_attempts_then_reports_unavailable() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "Service unavailable"}})

    sequence = SequenceTransport([unavailable, unavailable, unavailable])
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.UNAVAILABLE
    assert len(sequence.requests) == 3
    assert delays == [0.25, 0.5]


@pytest.mark.asyncio
async def test_timeout_is_retried_then_can_recover() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    sequence = SequenceTransport([httpx.ReadTimeout("API timed out"), success_response()])
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    result = await client.investigate(event_fixture())

    assert result.assessment.classification == "critical"
    assert delays == [0.25]


@pytest.mark.asyncio
async def test_missing_usage_is_normalized_to_zero() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload.pop("usage")
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    result = await client.investigate(event_fixture())

    assert result.usage.prompt_tokens == 0
    assert result.usage.completion_tokens == 0
    assert result.usage.total_tokens == 0
    assert result.usage.cost_usd == 0


@pytest.mark.asyncio
async def test_malformed_usage_is_reported_as_response_error() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["usage"]["input_tokens"] = "not-a-number"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.RESPONSE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"status": "completed", "output": []},
        {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}},
        {"status": "completed", "error": {"message": "Request failed"}},
    ],
)
async def test_unusable_success_response_is_reported_as_response_error(
    payload: dict[str, object],
) -> None:
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.RESPONSE


def test_redaction_removes_explicit_and_openai_shaped_secrets() -> None:
    rendered = redact_secrets(
        "explicit=my-secret automatic=sk-proj-abcdefghijklmnopqrstuvwxyz",
        ["my-secret"],
    )

    assert rendered == "explicit=[REDACTED] automatic=[REDACTED]"
