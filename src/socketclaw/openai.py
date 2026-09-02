"""Direct OpenAI Platform incident investigation boundary."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from enum import StrEnum
from typing import Any, Literal, cast

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from .config import OPENAI_MODEL
from .domain import Assessment, InvestigationResult, ModelUsage, SecurityEvent

OPENAI_BASE_URL = "https://api.openai.com/v1"

INCIDENT_SYSTEM_PROMPT = """You are SocketClaw's network security analyst.
Assess only the supplied normalized event and its evidence. Do not claim facts
that are absent. Return the required JSON assessment. A block action is only a
proposal for operator review, never a claim that a firewall was changed."""

_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")

_INPUT_USD_PER_TOKEN = 0.20 / 1_000_000
_CACHED_INPUT_USD_PER_TOKEN = 0.02 / 1_000_000
_CACHE_WRITE_USD_PER_TOKEN = _INPUT_USD_PER_TOKEN * 1.25
_OUTPUT_USD_PER_TOKEN = 1.20 / 1_000_000
_LONG_CONTEXT_THRESHOLD = 272_000


class ErrorKind(StrEnum):
    AUTHENTICATION = "authentication"
    CREDITS = "credits"
    FORBIDDEN = "forbidden"
    RATE_LIMIT = "rate_limit"
    INVALID_REQUEST = "invalid_request"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    NETWORK = "network"
    RESPONSE = "response"


class OpenAIError(RuntimeError):
    """A safe, user-actionable OpenAI Platform failure."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


class ModelAccess(BaseModel):
    """Non-secret metadata proving access to the configured OpenAI model."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str
    object: Literal["model"]
    created: int = 0
    owned_by: str = "openai"


Sleep = Callable[[float], Awaitable[None]]


class OpenAIClient:
    """Small async OpenAI Responses API client with bounded retries."""

    def __init__(
        self,
        api_key: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        timeout: float = 45.0,
    ) -> None:
        if not api_key.strip():
            raise ValueError("OpenAI API key is required")
        self._api_key = api_key
        self._transport = transport
        self._sleep = sleep
        self._timeout = timeout
        self._base_url = OPENAI_BASE_URL

    async def validate_key(self) -> ModelAccess:
        """Validate authentication and Luna access without generating tokens."""
        payload, _ = await self._request("GET", f"/models/{OPENAI_MODEL.model_id}")
        try:
            access = ModelAccess.model_validate(payload)
        except ValidationError as exc:
            raise self._response_error(f"OpenAI model response is invalid: {exc}") from exc
        if access.id != OPENAI_MODEL.model_id:
            raise self._response_error("OpenAI returned metadata for an unexpected model")
        return access

    async def investigate(
        self,
        event: SecurityEvent,
    ) -> InvestigationResult:
        """Request and validate a structured incident assessment."""
        preset = OPENAI_MODEL
        effort = preset.effort_for(event.severity)
        request_body = {
            "model": preset.model_id,
            "instructions": INCIDENT_SYSTEM_PROMPT,
            "input": f"Assess this SocketClaw security event:\n{event.model_dump_json()}",
            "reasoning": {"effort": effort},
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "socketclaw_incident_assessment",
                    "strict": True,
                    "schema": _strict_response_schema(),
                },
                "verbosity": "low",
            },
            "max_output_tokens": 4000,
            "store": False,
        }

        started = time.perf_counter()
        payload, response = await self._request(
            "POST",
            "/responses",
            json_body=request_body,
        )
        latency_ms = max(0, round((time.perf_counter() - started) * 1000))

        status = payload.get("status")
        if status != "completed":
            detail = _incomplete_message(payload)
            raise self._response_error(f"OpenAI response did not complete: {detail}")

        content = _output_text(payload)
        try:
            assessment_data = _extract_json_object(content)
            assessment = Assessment.model_validate(assessment_data)
        except (ValueError, json.JSONDecodeError, ValidationError) as exc:
            raise self._response_error(f"OpenAI assessment is invalid: {exc}") from exc

        usage_value = payload.get("usage")
        usage_data = cast(dict[str, object], usage_value) if isinstance(usage_value, dict) else {}
        input_details = _mapping(usage_data.get("input_tokens_details"))
        output_details = _mapping(usage_data.get("output_tokens_details"))

        try:
            input_tokens = _integer(usage_data.get("input_tokens"))
            output_tokens = _integer(usage_data.get("output_tokens"))
            cached_tokens = _integer(input_details.get("cached_tokens"))
            cache_write_tokens = _integer(input_details.get("cache_write_tokens"))
            usage = ModelUsage(
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                reasoning_tokens=_integer(output_details.get("reasoning_tokens")),
                total_tokens=_optional_integer(usage_data.get("total_tokens")),
                cost_usd=_estimated_cost(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cached_tokens=cached_tokens,
                    cache_write_tokens=cache_write_tokens,
                ),
                latency_ms=latency_ms,
                provider_request_id=_request_id(payload, response),
            )
        except (ValidationError, ValueError, TypeError, OverflowError) as exc:
            raise self._response_error(f"OpenAI usage metadata is invalid: {exc}") from exc

        provider_model = payload.get("model")
        return InvestigationResult(
            assessment=assessment,
            usage=usage,
            model_id=provider_model if isinstance(provider_model, str) else preset.model_id,
            requested_effort=effort,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[dict[str, object], httpx.Response]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=self._timeout,
            transport=self._transport,
        ) as client:
            for attempt in range(3):
                try:
                    response = await client.request(method, path, json=json_body)
                except httpx.TimeoutException as exc:
                    if attempt < 2:
                        await self._sleep(_backoff(attempt))
                        continue
                    message = redact_secrets(str(exc), [self._api_key])
                    raise OpenAIError(ErrorKind.TIMEOUT, message) from exc
                except httpx.TransportError as exc:
                    if attempt < 2:
                        await self._sleep(_backoff(attempt))
                        continue
                    message = redact_secrets(str(exc), [self._api_key])
                    raise OpenAIError(ErrorKind.NETWORK, message) from exc

                if response.status_code in {408, 409, 429, 500, 502, 503, 504} and attempt < 2:
                    await self._sleep(_retry_delay(response, attempt))
                    continue
                if not response.is_success:
                    raise self._http_error(response)

                try:
                    payload_value: object = response.json()
                except (json.JSONDecodeError, ValueError) as exc:
                    raise self._response_error("OpenAI returned malformed JSON") from exc
                if not isinstance(payload_value, dict):
                    raise self._response_error("OpenAI returned a non-object response")
                payload = cast(dict[str, object], payload_value)
                if payload.get("error") is not None:
                    message = _error_message(payload)
                    raise self._response_error(f"OpenAI API error: {message}")
                return payload, response

        raise OpenAIError(ErrorKind.NETWORK, "OpenAI request did not complete")

    def _http_error(self, response: httpx.Response) -> OpenAIError:
        message = redact_secrets(_error_message_from_response(response), [self._api_key])
        kind = _error_kind(response.status_code)
        return OpenAIError(kind, message, status_code=response.status_code)

    def _response_error(self, message: str) -> OpenAIError:
        return OpenAIError(
            ErrorKind.RESPONSE,
            redact_secrets(message, [self._api_key]),
        )


def redact_secrets(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove explicit credentials and recognizable OpenAI keys."""
    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return _OPENAI_KEY.sub("[REDACTED]", redacted)


def _output_text(payload: dict[str, object]) -> str:
    output = payload.get("output")
    if not isinstance(output, list):
        raise OpenAIError(ErrorKind.RESPONSE, "OpenAI response has no output array")
    texts: list[str] = []
    for item_value in cast(list[object], output):
        if not isinstance(item_value, dict):
            continue
        item = cast(dict[str, object], item_value)
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part_value in cast(list[object], content):
            if not isinstance(part_value, dict):
                continue
            part = cast(dict[str, object], part_value)
            text = part.get("text")
            if part.get("type") == "output_text" and isinstance(text, str):
                texts.append(text)
    joined = "\n".join(texts).strip()
    if not joined:
        raise OpenAIError(ErrorKind.RESPONSE, "OpenAI response has no output text")
    return joined


def _extract_json_object(content: str) -> dict[str, object]:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, count=1)
        stripped = re.sub(r"\s*```$", "", stripped, count=1)
    start = stripped.find("{")
    if start < 0:
        raise ValueError("assessment does not contain a JSON object")
    decoded_value: object
    decoded_value, _ = json.JSONDecoder().raw_decode(stripped[start:])
    if not isinstance(decoded_value, dict):
        raise ValueError("assessment JSON is not an object")
    return cast(dict[str, object], decoded_value)


def _strict_response_schema() -> dict[str, Any]:
    """Build the subset required by strict structured outputs."""
    schema = Assessment.model_json_schema()
    _require_all_object_properties(schema)
    return schema


def _require_all_object_properties(node: object) -> None:
    if isinstance(node, dict):
        mapping = cast(dict[str, object], node)
        mapping.pop("default", None)
        properties = mapping.get("properties")
        if mapping.get("type") == "object" and isinstance(properties, dict):
            typed_properties = cast(dict[str, object], properties)
            mapping["additionalProperties"] = False
            mapping["required"] = list(typed_properties)
        for value in mapping.values():
            _require_all_object_properties(value)
    elif isinstance(node, list):
        for value in cast(list[object], node):
            _require_all_object_properties(value)


def _mapping(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _error_kind(status_code: int) -> ErrorKind:
    return {
        400: ErrorKind.INVALID_REQUEST,
        401: ErrorKind.AUTHENTICATION,
        402: ErrorKind.CREDITS,
        403: ErrorKind.FORBIDDEN,
        404: ErrorKind.INVALID_REQUEST,
        408: ErrorKind.TIMEOUT,
        422: ErrorKind.INVALID_REQUEST,
        429: ErrorKind.RATE_LIMIT,
        500: ErrorKind.UNAVAILABLE,
        502: ErrorKind.UNAVAILABLE,
        503: ErrorKind.UNAVAILABLE,
        504: ErrorKind.UNAVAILABLE,
    }.get(status_code, ErrorKind.NETWORK)


def _error_message_from_response(response: httpx.Response) -> str:
    try:
        payload: object = response.json()
    except (json.JSONDecodeError, ValueError):
        return f"OpenAI returned HTTP {response.status_code}"
    return _error_message(payload)


def _error_message(payload: object) -> str:
    if isinstance(payload, dict):
        typed_payload = cast(dict[str, object], payload)
        error = typed_payload.get("error")
        if isinstance(error, dict):
            message = cast(dict[str, object], error).get("message")
            if isinstance(message, str):
                return message
        if isinstance(error, str):
            return error
    return "OpenAI returned an unspecified error"


def _incomplete_message(payload: dict[str, object]) -> str:
    error = payload.get("error")
    if error is not None:
        return _error_message(payload)
    details = _mapping(payload.get("incomplete_details"))
    reason = details.get("reason")
    return reason if isinstance(reason, str) else str(payload.get("status", "unknown status"))


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After")
    if header is not None:
        try:
            return min(30.0, max(0.0, float(header)))
        except ValueError:
            pass
    return _backoff(attempt)


def _backoff(attempt: int) -> float:
    return 0.25 * (2**attempt)


def _integer(value: object) -> int:
    if value is None:
        return 0
    if not isinstance(value, int | float | str):
        raise ValueError("expected an integer-compatible value")
    return int(value)


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int | float | str):
        raise ValueError("expected an integer-compatible value")
    return int(value)


def _estimated_cost(
    *,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int,
    cache_write_tokens: int,
) -> float:
    if min(input_tokens, output_tokens, cached_tokens, cache_write_tokens) < 0:
        raise ValueError("token counts cannot be negative")
    if cached_tokens + cache_write_tokens > input_tokens:
        raise ValueError("cached input token details exceed total input tokens")
    ordinary_input = input_tokens - cached_tokens - cache_write_tokens
    input_multiplier = 2.0 if input_tokens > _LONG_CONTEXT_THRESHOLD else 1.0
    output_multiplier = 1.5 if input_tokens > _LONG_CONTEXT_THRESHOLD else 1.0
    return (
        ordinary_input * _INPUT_USD_PER_TOKEN * input_multiplier
        + cached_tokens * _CACHED_INPUT_USD_PER_TOKEN * input_multiplier
        + cache_write_tokens * _CACHE_WRITE_USD_PER_TOKEN * input_multiplier
        + output_tokens * _OUTPUT_USD_PER_TOKEN * output_multiplier
    )


def _request_id(payload: dict[str, object], response: httpx.Response) -> str | None:
    request_id = payload.get("id")
    if isinstance(request_id, str):
        return request_id
    header = response.headers.get("X-Request-ID")
    return header or None
