"""Adapters for the same operations in independent and attached terminals."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from collections.abc import AsyncIterator
from contextlib import suppress
from typing import Any, get_type_hints
from uuid import UUID

from pydantic import TypeAdapter

from .application import (
    INCIDENT_READS,
    INCIDENT_WRITES,
    REPOSITORY_READS,
    REPOSITORY_WRITES,
    ApplicationService,
)
from .config import AppConfig
from .control import ControlClient
from .domain import SecurityEvent
from .incident_store import IncidentStore
from .monitor import MonitorStatus
from .storage import Repository, StoredEvent, StoredInvestigation

HEALTH_TIMEOUT = 5.0


class RemoteMethods:
    """Only explicitly allowlisted repository contracts are exposed."""

    def __init__(
        self, client: ControlClient, prefix: str, prototype: type[Any], allowed: frozenset[str]
    ) -> None:
        self.client, self.prefix, self.prototype, self.allowed = client, prefix, prototype, allowed

    def __getattr__(self, name: str) -> Any:
        if name not in self.allowed:
            raise AttributeError(name)
        function = getattr(self.prototype, name)
        signature = inspect.signature(function)
        adapter: TypeAdapter[Any] = TypeAdapter(get_type_hints(function)["return"])

        async def invoke(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(None, *args, **kwargs)
            params = {key: value for key, value in bound.arguments.items() if key != "self"}
            return adapter.validate_python(await self.client.call(f"{self.prefix}.{name}", params))

        return invoke


class RemoteRepository(RemoteMethods):
    def __init__(self, client: ControlClient) -> None:
        super().__init__(client, "repository", Repository, REPOSITORY_READS | REPOSITORY_WRITES)
        self.incidents = RemoteMethods(
            client, "incidents", IncidentStore, INCIDENT_READS | INCIDENT_WRITES
        )


class RemoteApplication:
    def __init__(self, client: ControlClient, repository: RemoteRepository) -> None:
        self.client, self.repository = client, repository

    async def execute(self, method: str, params: dict[str, Any]) -> Any:
        return await self.client.call(method, params)

    async def save_config(self, config: AppConfig, previous: AppConfig) -> AppConfig:
        before = previous.model_dump(mode="json")
        changes = {
            key: value
            for key, value in config.model_dump(mode="json").items()
            if before[key] != value
        }
        result = await self.client.call(
            "config.update",
            {
                "base_revision": hashlib.sha256(previous.model_dump_json().encode()).hexdigest(),
                "changes": changes,
            },
        )
        return AppConfig.model_validate(result["config"])

    async def notification_status(self) -> dict[str, object]:
        return await self.client.call("notification.status")

    async def wait_operation(self, value: dict[str, str]) -> Any:
        while True:
            result = await self.client.call("operation.get", {"identifier": value["job_id"]})
            if result["status"] == "complete":
                return result["result"]
            if result["status"] != "running":
                raise RuntimeError(result["error"] or result["status"])
            await asyncio.sleep(0.25)

    async def investigate(self, event_id: UUID) -> StoredInvestigation:
        queued = StoredInvestigation.model_validate(
            await self.client.call("investigation.request", {"event_id": event_id})
        )
        while True:
            current = await self.repository.get_investigation(queued.id)
            if current is None:
                raise KeyError(str(queued.id))
            if current.status == "complete":
                return current
            if current.status == "failed":
                raise RuntimeError(current.error or "Investigation failed")
            await asyncio.sleep(0.5)


class RemoteMonitor:
    def __init__(self, client: ControlClient) -> None:
        self.client = client
        self._status = MonitorStatus(
            running=False,
            paused=False,
            started_at=None,
            active_jobs=0,
            last_error="Connecting to owner",
        )
        self._closed = False
        self._poll: asyncio.Task[None] | None = None
        self._commands: set[asyncio.Task[None]] = set()

    @property
    def status(self) -> MonitorStatus:
        return self._status

    async def refresh(self) -> None:
        try:
            response = await asyncio.wait_for(self.client.call("health.get"), HEALTH_TIMEOUT)
            self._status = MonitorStatus.model_validate(response["monitor"])
        except Exception as exc:
            self.client.connected = False
            message = str(exc) or "Owner unavailable; collection status is unknown"
            self._status = self._status.model_copy(update={"last_error": message, "running": False})

    async def start(self) -> None:
        self._closed = False
        await self.refresh()
        if self._poll is None or self._poll.done():
            self._poll = asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(2)
            await self.refresh()

    async def stop(self) -> None:
        self._closed = True
        if self._poll:
            self._poll.cancel()
            with suppress(asyncio.CancelledError):
                await self._poll
        if self._commands:
            await asyncio.gather(*self._commands, return_exceptions=True)

    def _schedule(self, method: str) -> None:
        async def execute() -> None:
            try:
                self._status = MonitorStatus.model_validate(await self.client.call(method))
            except Exception as exc:
                self._status = self._status.model_copy(update={"last_error": str(exc)})

        task = asyncio.create_task(execute())
        self._commands.add(task)
        task.add_done_callback(self._commands.discard)

    def pause(self) -> None:
        self._schedule("monitor.pause")

    def resume(self) -> None:
        self._schedule("monitor.resume")

    async def run_diagnostic(self, kind: str, target: str) -> StoredEvent:
        value = await self.client.call("diagnostic.request", {"kind": kind, "target": target})
        while True:
            result = await self.client.call("operation.get", {"identifier": value["job_id"]})
            if result["status"] == "complete":
                return StoredEvent.model_validate(result["result"])
            if result["status"] != "running":
                raise RuntimeError(result["error"] or result["status"])
            await asyncio.sleep(0.25)

    async def events(self) -> AsyncIterator[SecurityEvent]:
        seen: UUID | None = None
        while not self._closed:
            try:
                result = await self.client.call("repository.list_events", {"query": {"limit": 1}})
                if result:
                    event = StoredEvent.model_validate(result[0])
                    if event.id != seen:
                        seen = event.id
                        yield event
            except Exception:
                pass
            await asyncio.sleep(2)


ApplicationGateway = ApplicationService | RemoteApplication
