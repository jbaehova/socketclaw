"""Explicit required TCP/HTTP checks with transactional confirmation streaks."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from typing import Literal

import httpx

from ..collection import ProbeBatch
from ..config import ServiceConfig
from ..domain import EventSource, ObservationOutcome, SecurityEvent
from ..storage import Repository
from .ports import tcp_connect

ServiceState = Literal["available", "closed", "unknown", "http_mismatch"]
ServiceCheck = Callable[[ServiceConfig], Awaitable[tuple[ServiceState, str]]]


class ServiceProbe:
    def __init__(self, repository: Repository, *, check: ServiceCheck | None = None) -> None:
        self.repository = repository
        self.check = check or check_service

    async def collect(self, service: ServiceConfig) -> ProbeBatch:
        checkpoint = await self.repository.load_checkpoint(f"service:{service.id}")
        policy = service.model_dump(mode="json", exclude={"name", "interval", "timeout"})
        scope = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
        prior = checkpoint.state if checkpoint.state.get("scope") == scope else {}
        status, detail = await self.check(service)
        available = status == "available"
        failures = 0 if available else int(str(prior.get("failures", 0))) + 1
        successes = int(str(prior.get("successes", 0))) + 1 if available else 0
        confirmed = (
            successes >= service.recovery_threshold
            if available
            else failures >= service.failure_threshold
        )
        endpoint = f"{service.protocol}://{service.host}:{service.port}"
        if service.protocol != "tcp":
            endpoint += service.path
        event = SecurityEvent(
            source=EventSource.SYSTEM,
            event_type="service.available"
            if available
            else "service.unknown"
            if status == "unknown"
            else "service.failed",
            target=service.host,
            title=f"{service.name}: {status}"[:200],
            summary=f"{endpoint}: {detail}"[:2000],
            outcome=ObservationOutcome.OK
            if available
            else ObservationOutcome.UNKNOWN
            if status == "unknown"
            else ObservationOutcome.UNREACHABLE,
            evidence={
                "service_id": service.id,
                "service_name": service.name,
                "endpoint": endpoint,
                "status": status,
                "required": service.required,
                "confirmed": confirmed,
                "expected_status": service.expected_status,
                "allowed_exposure": service.allowed_exposure,
                "consecutive_failures": failures,
                "consecutive_successes": successes,
                "failure_threshold": service.failure_threshold,
                "recovery_threshold": service.recovery_threshold,
                "detail": detail[:2000],
            },
        )
        return ProbeBatch(
            observations=(event,),
            checkpoints=(
                checkpoint.model_copy(
                    update={
                        "state": {
                            "failures": failures,
                            "successes": successes,
                            "status": status,
                            "scope": scope,
                        }
                    }
                ),
            ),
        )


async def check_service(service: ServiceConfig) -> tuple[ServiceState, str]:
    if service.protocol == "tcp":
        state = await tcp_connect(service.host, service.port, service.timeout)
        if state is True:
            return "available", "TCP connection established"
        if state is False:
            return "closed", "TCP connection explicitly refused"
        return "unknown", "TCP measurement unavailable or timed out"
    host = f"[{service.host}]" if ":" in service.host else service.host
    url = f"{service.protocol}://{host}:{service.port}{service.path}"
    try:
        async with httpx.AsyncClient(
            timeout=service.timeout, follow_redirects=False, trust_env=False
        ) as client:
            async with asyncio.timeout(service.timeout):
                async with client.stream("GET", url) as response:
                    if response.status_code != service.expected_status:
                        return (
                            "http_mismatch",
                            f"HTTP {response.status_code}, expected {service.expected_status}",
                        )
                    if service.body_contains is not None:
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk[: 65536 - len(body)])
                            if len(body) >= 65536:
                                break
                        if service.body_contains not in body.decode(errors="replace"):
                            return (
                                "http_mismatch",
                                "Expected response content absent in first 64 KiB",
                            )
        return "available", "HTTP status and configured response conditions matched"
    except (httpx.HTTPError, OSError, TimeoutError) as exc:
        return "unknown", f"HTTP measurement unavailable ({type(exc).__name__})"
