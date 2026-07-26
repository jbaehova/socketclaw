"""OpenRouter-only incident investigation boundary."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from .config import ModelPreset
from .domain import Assessment, InvestigationResult, ModelUsage, SecurityEvent

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
SOCKETCLAW_REFERER = "https://github.com/jbaehova/SocketClaw"

INCIDENT_SYSTEM_PROMPT = """You are SocketClaw's network security analyst.
Assess only the supplied normalized event and its evidence. Do not claim facts
that are absent. Return the required JSON assessment. A block action is only a
proposal for operator review, never a claim that a firewall was changed."""

_OPENROUTER_KEY = re.compile(r"sk-or-v1-[A-Za-z0-9_-]{8,}")


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


class OpenRouterError(RuntimeError):
    """A safe, user-actionable OpenRouter failure."""

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


class KeyStatus(BaseModel):
    """Non-secret metadata returned for the current API key."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    label: str | None = None
    is_free_tier: bool = False
    limit: float | None = None
    limit_remaining: float | None = None
    usage: float = 0.0


Sleep = Callable[[float], Awaitable[None]]


class OpenRouterClient:
    """Small async OpenRouter client with bounded, classified retries."""

    def __init__(
        self,
        api_key: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        timeout: float = 45.0,
        base_url: str = OPENROUTER_BASE_URL,
    ) -> None:
        if not api_key.strip():
            raise ValueError("OpenRouter API key is required")
        self._api_key = api_key
        self._transport = transport
        self._sleep = sleep
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")

    async def validate_key(self) -> KeyStatus:
        """Validate authentication without spending model credits."""
        payload, _ = await self._request("GET", "/key")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise self._response_error("OpenRouter key response has no data object")
        try:
            return KeyStatus.model_validate(data)
        except ValidationError as exc:
            raise self._response_error(f"OpenRouter key response is invalid: {exc}") from exc

    async def investigate(
        self,
        event: SecurityEvent,
        preset: ModelPreset,
    ) -> InvestigationResult:
        """Request and validate a structured incident assessment."""
        request_body = {
            "model": preset.model_id,
            "messages": [
                {"role": "system", "content": INCIDENT_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Assess this SocketClaw security event:\n{event.model_dump_json()}"
                    ),
                },
            ],
            "reasoning": {"effort": preset.effort, "exclude": True},
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "socketclaw_incident_assessment",
                    "strict": True,
                    "schema": Assessment.model_json_schema(),
                },
            },
            "max_tokens": 1200,
            "stream": False,
        }

        started = time.perf_counter()
        payload, response = await self._request(
            "POST",
            "/chat/completions",
            json_body=request_body,
        )
        latency_ms = max(0, round((time.perf_counter() - started) * 1000))

        content = _assistant_content(payload)
        try:
            assessment_data = _extract_json_object(content)
            assessment = Assessment.model_validate(assessment_data)
        except (ValueError, json.JSONDecodeError, ValidationError) as exc:
            raise self._response_error(f"OpenRouter assessment is invalid: {exc}") from exc

        usage_data = payload.get("usage")
        if not isinstance(usage_data, dict):
            usage_data = {}
        completion_details = usage_data.get("completion_tokens_details")
        if not isinstance(completion_details, dict):
            completion_details = {}

        try:
            usage = ModelUsage(
                prompt_tokens=_integer(usage_data.get("prompt_tokens")),
                completion_tokens=_integer(usage_data.get("completion_tokens")),
                reasoning_tokens=_integer(
                    completion_details.get(
                        "reasoning_tokens",
                        usage_data.get("reasoning_tokens"),
                    )
                ),
                total_tokens=_optional_integer(usage_data.get("total_tokens")),
                cost_usd=_number(usage_data.get("cost")),
                latency_ms=latency_ms,
                provider_request_id=_request_id(payload, response),
            )
        except (ValidationError, ValueError, TypeError, OverflowError) as exc:
            raise self._response_error(f"OpenRouter usage metadata is invalid: {exc}") from exc

        provider_model = payload.get("model")
        return InvestigationResult(
            assessment=assessment,
            usage=usage,
            model_id=provider_model if isinstance(provider_model, str) else preset.model_id,
            requested_effort=preset.effort,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], httpx.Response]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": SOCKETCLAW_REFERER,
            "X-Title": "SocketClaw",
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
                    raise OpenRouterError(ErrorKind.TIMEOUT, message) from exc
                except httpx.TransportError as exc:
                    if attempt < 2:
                        await self._sleep(_backoff(attempt))
                        continue
                    message = redact_secrets(str(exc), [self._api_key])
                    raise OpenRouterError(ErrorKind.NETWORK, message) from exc

                if response.status_code in {429, 502, 503} and attempt < 2:
                    await self._sleep(_retry_delay(response, attempt))
                    continue
                if not response.is_success:
                    raise self._http_error(response)

                try:
                    payload = response.json()
                except (json.JSONDecodeError, ValueError) as exc:
                    raise self._response_error("OpenRouter returned malformed JSON") from exc
                if not isinstance(payload, dict):
                    raise self._response_error("OpenRouter returned a non-object response")
                if payload.get("error") is not None:
                    message = _error_message(payload)
                    raise self._response_error(f"OpenRouter provider error: {message}")
                return payload, response

        raise OpenRouterError(ErrorKind.NETWORK, "OpenRouter request did not complete")

    def _http_error(self, response: httpx.Response) -> OpenRouterError:
        message = redact_secrets(_error_message_from_response(response), [self._api_key])
        kind = _error_kind(response.status_code)
        return OpenRouterError(kind, message, status_code=response.status_code)

    def _response_error(self, message: str) -> OpenRouterError:
        return OpenRouterError(
            ErrorKind.RESPONSE,
            redact_secrets(message, [self._api_key]),
        )


def redact_secrets(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove explicit credentials and recognizable OpenRouter keys."""
    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return _OPENROUTER_KEY.sub("[REDACTED]", redacted)


def _assistant_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise OpenRouterError(ErrorKind.RESPONSE, "OpenRouter response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise OpenRouterError(ErrorKind.RESPONSE, "OpenRouter choice is invalid")
    message = first.get("message")
    if not isinstance(message, dict):
        raise OpenRouterError(ErrorKind.RESPONSE, "OpenRouter choice has no message")
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        texts = [
            item.get("text")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ]
        joined = "\n".join(texts).strip()
        if joined:
            return joined
    raise OpenRouterError(ErrorKind.RESPONSE, "OpenRouter message has no text content")


def _extract_json_object(content: str) -> dict[str, Any]:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, count=1)
        stripped = re.sub(r"\s*```$", "", stripped, count=1)
    start = stripped.find("{")
    if start < 0:
        raise ValueError("assessment does not contain a JSON object")
    decoded, _ = json.JSONDecoder().raw_decode(stripped[start:])
    if not isinstance(decoded, dict):
        raise ValueError("assessment JSON is not an object")
    return decoded


def _error_kind(status_code: int) -> ErrorKind:
    return {
        400: ErrorKind.INVALID_REQUEST,
        401: ErrorKind.AUTHENTICATION,
        402: ErrorKind.CREDITS,
        403: ErrorKind.FORBIDDEN,
        408: ErrorKind.TIMEOUT,
        429: ErrorKind.RATE_LIMIT,
        502: ErrorKind.UNAVAILABLE,
        503: ErrorKind.UNAVAILABLE,
    }.get(status_code, ErrorKind.NETWORK)


def _error_message_from_response(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        return f"OpenRouter returned HTTP {response.status_code}"
    return _error_message(payload)


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str):
                return message
        if isinstance(error, str):
            return error
    return "OpenRouter returned an unspecified error"


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


def _integer(value: Any) -> int:
    if value is None:
        return 0
    return int(value)


def _optional_integer(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _number(value: Any) -> float:
    if value is None:
        return 0.0
    return float(value)


def _request_id(payload: dict[str, Any], response: httpx.Response) -> str | None:
    request_id = payload.get("id")
    if isinstance(request_id, str):
        return request_id
    header = response.headers.get("X-Request-ID")
    return header or None
