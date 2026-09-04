from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from socketclaw.domain import SecurityEvent
from socketclaw.openai import (
    OPENAI_BASE_URL,
    ErrorKind,
    OpenAIClient,
    OpenAIError,
    redact_secrets,
)


def event_fixture(
    *,
    severity: str = "critical",
    target: str = "198.51.100.24",
    evidence: dict[str, object] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        source="log",
        event_type="log.auth_failure",
        title="Repeated SSH authentication failures",
        summary="Twelve failed root logins were observed in sixty seconds.",
        target=target,
        evidence=evidence or {"attempts": 12},
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


def model_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "gpt-5.6-luna",
            "object": "model",
            "created": 1,
            "owned_by": "openai",
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
    assert "untrusted evidence" in body["instructions"]
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
async def test_event_credentials_are_redacted_before_provider_serialization() -> None:
    api_key = "sk-proj-secret-value"
    bearer = "Bearer another-sensitive-token"
    sequence = SequenceTransport([success_response()])
    client = OpenAIClient(api_key, transport=mock_transport(sequence))
    event = event_fixture(
        evidence={
            "nested": [
                api_key,
                {
                    api_key: f"prefix {bearer} suffix",
                    "[REDACTED]": "literal collision value",
                },
            ],
            "count": 12,
            "enabled": True,
        }
    )

    await client.investigate(event)

    request_content = sequence.requests[0].content
    assert api_key.encode() not in request_content
    assert bearer.encode() not in request_content
    body = json.loads(request_content)
    assert "[REDACTED]" in body["input"]
    assert '"count":12' in body["input"]
    assert '"enabled":true' in body["input"]
    event_payload = json.loads(body["input"].split("\n", 1)[1])
    nested_mapping = event_payload["evidence"]["nested"][1]
    assert set(nested_mapping.values()) == {
        "prefix Bearer [REDACTED] suffix",
        "literal collision value",
    }


@pytest.mark.asyncio
async def test_event_size_limit_applies_after_credential_redaction() -> None:
    api_key = "sk-proj-secret-value"
    raw_secret_payload = api_key * 4000
    assert len(raw_secret_payload.encode()) > 64 * 1024
    sequence = SequenceTransport([success_response()])
    client = OpenAIClient(api_key, transport=mock_transport(sequence))

    result = await client.investigate(
        event_fixture(evidence={"accidental_secret_dump": raw_secret_payload})
    )

    assert result.assessment.classification == "critical"
    assert api_key.encode() not in sequence.requests[0].content


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
async def test_incomplete_json_fence_is_rejected() -> None:
    content = f"```json\n{json.dumps(assessment_content())}"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([success_response(content=content)])),
    )

    with pytest.raises(OpenAIError, match="invalid JSON code fence"):
        await client.investigate(event_fixture())


@pytest.mark.asyncio
async def test_assessment_rejects_trailing_content_and_mismatched_block_target() -> None:
    trailing = json.dumps(assessment_content()) + " trailing"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([success_response(content=trailing)])),
    )
    with pytest.raises(OpenAIError, match="trailing content"):
        await client.investigate(event_fixture())

    mismatched = assessment_content()
    proposal = mismatched["response_proposal"]
    assert isinstance(proposal, dict)
    proposal["target_ip"] = "203.0.113.10"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(
            SequenceTransport([success_response(content=json.dumps(mismatched))])
        ),
    )
    with pytest.raises(OpenAIError, match="does not match"):
        await client.investigate(event_fixture())


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
async def test_generation_429_is_not_automatically_retried() -> None:
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

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.RATE_LIMIT
    assert delays == []
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
async def test_429_quota_error_is_not_retried_and_is_classified_as_credits() -> None:
    sequence = SequenceTransport(
        [
            httpx.Response(
                429,
                json={
                    "error": {
                        "message": "Organization spend limit reached",
                        "code": "billing_hard_limit_reached",
                    }
                },
            )
        ]
    )
    client = OpenAIClient("sk-proj-secret-value", transport=mock_transport(sequence))

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.CREDITS
    assert len(sequence.requests) == 1


@pytest.mark.asyncio
async def test_safe_get_retry_honors_retry_after_and_reuses_trace_id() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    sequence = SequenceTransport(
        [
            httpx.Response(503, headers={"retry-after-ms": "1500"}),
            model_response(),
        ]
    )
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    access = await client.validate_key()

    assert access.id == "gpt-5.6-luna"
    assert delays == [1.5]
    assert len(sequence.requests) == 2
    trace_ids = [request.headers["X-Client-Request-Id"] for request in sequence.requests]
    assert trace_ids[0] == trace_ids[1]
    assert str(UUID(trace_ids[0])) == trace_ids[0]
    assert trace_ids[0].isascii()


@pytest.mark.asyncio
async def test_generation_503_is_not_automatically_retried() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "Service unavailable"}})

    sequence = SequenceTransport([unavailable])
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.UNAVAILABLE
    assert len(sequence.requests) == 1
    assert delays == []


@pytest.mark.asyncio
async def test_ambiguous_generation_timeout_is_not_retried() -> None:
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    sequence = SequenceTransport([httpx.ReadTimeout("API timed out"), success_response()])
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(sequence),
        sleep=record_sleep,
    )

    with pytest.raises(OpenAIError) as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.TIMEOUT
    assert caught.value.client_request_id == sequence.requests[0].headers["X-Client-Request-Id"]
    assert "may have accepted" in str(caught.value)
    assert "retry manually" in str(caught.value)
    assert caught.value.client_request_id in str(caught.value)
    assert len(sequence.requests) == 1
    assert delays == []


@pytest.mark.asyncio
async def test_missing_usage_is_rejected_instead_of_undercounting_cost() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload.pop("usage")
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match="no usage metadata") as caught:
        await client.investigate(event_fixture())

    assert caught.value.kind is ErrorKind.RESPONSE


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
@pytest.mark.parametrize("invalid_value", [True, 1.5, "12"])
async def test_usage_requires_json_integers(invalid_value: object) -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["usage"]["input_tokens"] = invalid_value
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match="expected an integer"):
        await client.investigate(event_fixture())


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["input_tokens", "output_tokens"])
async def test_required_usage_tokens_reject_null(field: str) -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["usage"][field] = None
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match=f"{field} must be an integer"):
        await client.investigate(event_fixture())


@pytest.mark.asyncio
async def test_response_from_unexpected_model_is_rejected() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["model"] = "gpt-other"
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match="unexpected model"):
        await client.investigate(event_fixture())


@pytest.mark.asyncio
async def test_mixed_output_text_and_refusal_is_rejected() -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["output"][0]["content"].append(
        {"type": "refusal", "refusal": "I cannot assess this event."}
    )
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match="refused"):
        await client.investigate(event_fixture())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [("role", "tool"), ("status", "in_progress"), ("type", "reasoning")],
)
async def test_output_text_requires_a_completed_assistant_message(
    field: str,
    value: str,
) -> None:
    response = success_response()
    payload = json.loads(response.content)
    payload["output"][0][field] = value
    client = OpenAIClient(
        "sk-proj-secret-value",
        transport=mock_transport(SequenceTransport([httpx.Response(200, json=payload)])),
    )

    with pytest.raises(OpenAIError, match="no output text"):
        await client.investigate(event_fixture())


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


def test_redaction_removes_bearer_tokens() -> None:
    rendered = redact_secrets("Authorization: Bearer opaque-secret-token")

    assert rendered == "Authorization: Bearer [REDACTED]"


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("inf"), float("nan"), True])
def test_client_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        OpenAIClient("sk-proj-secret-value", timeout=timeout)


def test_runtime_has_one_fixed_openai_provider_boundary() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(Path("src/socketclaw").rglob("*.py"))
    ).casefold()
    forbidden_markers = (
        "openrouter_api_key",
        "anthropic_api_key",
        "google_api_key",
        "gemini_api_key",
        "mistral_api_key",
        "groq_api_key",
        "openrouter.ai",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.groq.com",
    )

    assert OPENAI_BASE_URL == "https://api.openai.com/v1"
    assert all(marker not in source for marker in forbidden_markers)
