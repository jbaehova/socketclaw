"""Owner-side application operations, shared by local and connected terminals."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import os
from collections.abc import Awaitable, Callable, Collection
from contextlib import suppress
from typing import Any, get_origin, get_type_hints
from uuid import UUID, uuid4

from pydantic import TypeAdapter
from pydantic_core import to_jsonable_python
from sqlalchemy import text

from .config import AppConfig, ConfigStore
from .context import IncidentContext, build_incident_context
from .domain import utc_now
from .export import (
    export_incident_json,
    export_incident_markdown,
    export_json,
    export_markdown,
    write_managed_export,
)
from .maintenance import MaintenanceService, backup_inventory, prune_backups
from .monitor import MonitorService, MonitorStatus
from .notifications import NotificationOutbox
from .openai import OpenAIClient, redact_secrets
from .storage import Repository, StoredInvestigation
from .unit_of_work import command_context

REPOSITORY_READS = frozenset(
    {
        "load_checkpoint",
        "list_events",
        "get_event",
        "get_investigation",
        "latest_service_observations",
        "incident_report",
        "incident_report_for_event",
        "incident_observations",
        "list_investigations",
        "list_response_proposals",
        "session_stats",
        "list_probe_health",
        "list_ingest_gaps",
        "list_health_transitions",
        "get_rule_version",
    }
)
REPOSITORY_WRITES = frozenset({"record_action", "update_response_proposal_status"})
INCIDENT_READS = frozenset(
    {
        "get",
        "list",
        "counts",
        "occurrences",
        "transitions",
        "notes",
        "links",
        "suppressions",
        "suppression_decisions",
    }
)
INCIDENT_WRITES = frozenset(
    {"change_status", "add_note", "create_suppression", "disable_suppression"}
)


def json_value(value: Any) -> Any:
    return to_jsonable_python(value, serialize_unknown=False)


def typed_parameters(function: Callable[..., Any], params: dict[str, Any]) -> dict[str, Any]:
    signature = inspect.signature(function)
    bound = signature.bind(**params)
    hints = get_type_hints(function)
    result: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        annotation = hints.get(name, Any)
        if get_origin(annotation) is Collection:
            annotation = list[str]
        result[name] = TypeAdapter(annotation).validate_python(value)
    return result


class ApplicationService:
    def __init__(
        self,
        store: ConfigStore,
        repository: Repository,
        monitor: MonitorService,
        reconfigure: Callable[[AppConfig], Awaitable[None]],
        stop: asyncio.Event | None = None,
    ) -> None:
        self.store = store
        self.repository = repository
        self.monitor = monitor
        self.reconfigure = reconfigure
        self.stop_event = stop or asyncio.Event()
        self.config = store.load()
        self.configuration_error: str | None = None
        self._command_lock = asyncio.Lock()
        self._investigations: dict[UUID, asyncio.Task[None]] = {}
        self._scope_records: dict[UUID, UUID] = {}
        self._deferred: list[Callable[[], None]] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closing = False
        self.maintenance = MaintenanceService(repository)

    async def identity(self) -> dict[str, str]:
        async with self.repository.sessions() as session:
            rows = await session.execute(
                text(
                    "SELECT key,value FROM schema_meta WHERE key IN "
                    "('database_identity','restore_generation')"
                )
            )
            return dict(rows.tuples().all())

    @property
    def config_revision(self) -> str:
        return hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()

    def methods(self) -> dict[str, Callable[..., Awaitable[Any]]]:
        mapping: dict[str, Callable[..., Awaitable[Any]]] = {
            "config.get": self.get_config,
            "config.update": self.change_config,
            "credential.set": self.set_credential,
            "health.get": self.health,
            "monitor.pause": self.pause,
            "monitor.resume": self.resume,
            "diagnostic.request": self.diagnostic,
            "owner.stop": self.stop,
            "investigation.context": self.investigation_context,
            "investigation.request": self.queue_investigation,
            "investigation.retry": self.queue_investigation,
            "export.request": self.queue_export,
            "operation.get": self.operation_result,
            "retention.preview": self.maintenance.preview,
            "retention.apply": self.retention_apply,
            "retention.get": self.maintenance.get,
            "retention.list": self.maintenance.list,
            "retention.cancel": self.maintenance.cancel,
            "retention.resume": self.maintenance.resume,
            "backups.list": self.list_backups,
            "backups.prune": self.prune_backups,
            "request.get": self.request_result,
            "notification.status": self.notification_status,
            "notification.reconcile": self.notification_reconcile,
            "notification.resolve": self.notification_resolve,
        }
        for name in REPOSITORY_READS | REPOSITORY_WRITES:
            mapping[f"repository.{name}"] = getattr(self.repository, name)
        for name in INCIDENT_READS | INCIDENT_WRITES:
            mapping[f"incidents.{name}"] = getattr(self.repository.incidents, name)
        return mapping

    async def request_result(self, identifier: UUID) -> dict[str, Any]:
        async with self.repository.sessions() as session:
            row = (
                await session.execute(
                    text("SELECT status,result_json FROM command_receipts WHERE id=:id"),
                    {"id": str(identifier)},
                )
            ).first()
            if row is None:
                return {"status": "not_found"}
            return {"status": row[0], "result": json.loads(row[1]) if row[1] else None}

    async def execute(
        self, method: str, params: dict[str, Any], request_id: UUID | None = None
    ) -> Any:
        function = self.methods().get(method)
        if function is None:
            raise ValueError("Unsupported operation")
        values = typed_parameters(function, params)
        readonly = (
            method
            in {
                "config.get",
                "health.get",
                "request.get",
                "investigation.context",
                "notification.status",
                "operation.get",
                "retention.preview",
                "retention.get",
                "retention.list",
                "backups.list",
            }
            or (method.startswith("repository.") and method.split(".")[1] in REPOSITORY_READS)
            or (method.startswith("incidents.") and method.split(".")[1] in INCIDENT_READS)
        )
        if readonly:
            return json_value(await function(**values))
        if self._closing:
            raise RuntimeError("Owner is stopping")
        identifier = str(request_id or uuid4())
        encoded = json.dumps(json_value(params), sort_keys=True, separators=(",", ":"))
        if method == "credential.set":
            secret = self.store.home / ".command-secret"
            if secret.is_symlink():
                raise OSError("credential receipt key must not be a link")
            if not secret.exists():
                fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(os.urandom(32))
            digest = hmac.new(secret.read_bytes(), encoded.encode(), "sha256").hexdigest()
        else:
            digest = hashlib.sha256(encoded.encode()).hexdigest()
        atomic = (
            method.startswith("incidents.")
            or method.startswith("repository.")
            or method.startswith("investigation.")
            or method in {"diagnostic.request", "export.request", "retention.apply"}
        )
        async with self._command_lock:
            self._deferred = []
            async with self.repository.sessions() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                row = (
                    await session.execute(
                        text(
                            "SELECT method,input_hash,status,result_json FROM "
                            "command_receipts WHERE id=:id"
                        ),
                        {"id": identifier},
                    )
                ).first()
                if row:
                    if row[0] != method or row[1] != digest:
                        raise ValueError("Request ID reused with different content")
                    if row[2] != "complete":
                        raise RuntimeError(
                            "Previous operation outcome is uncertain; inspect current "
                            "state before a new request"
                        )
                    return json.loads(row[3])
                await session.execute(
                    text(
                        "INSERT INTO command_receipts "
                        "VALUES(:id,:method,:digest,'accepted',NULL,:at)"
                    ),
                    {
                        "id": identifier,
                        "method": method,
                        "digest": digest,
                        "at": utc_now().isoformat(),
                    },
                )
                token = None
                if atomic:
                    token = command_context.set((asyncio.current_task(), session))
                else:
                    await session.commit()
                try:
                    result = json_value(await function(**values))
                finally:
                    if token is not None:
                        command_context.reset(token)
                await session.execute(
                    text(
                        "UPDATE command_receipts SET "
                        "status='complete',result_json=:result WHERE id=:id"
                    ),
                    {"id": identifier, "result": json.dumps(result)},
                )
                await session.commit()
            for action in self._deferred:
                action()
            self._deferred = []
            return result

    async def get_config(self) -> dict[str, Any]:
        return {
            "config": self.config.model_dump(mode="json"),
            "revision": self.config_revision,
            "key_configured": self.store.load_api_key() is not None,
        }

    async def change_config(self, base_revision: str, changes: dict[str, Any]) -> dict[str, Any]:
        if base_revision != self.config_revision:
            raise ValueError("Configuration changed. Reload saved settings and review your draft.")
        previous = self.config
        candidate = AppConfig.model_validate({**previous.model_dump(), **changes})
        self.store.save(candidate)
        try:
            await self.reconfigure(candidate)
        except BaseException:
            self.configuration_error = (
                "Settings could not be reconciled with collection. "
                "Review saved settings and restart the owner."
            )
            with suppress(Exception):
                self.store.save(previous)
                await self.reconfigure(previous)
                self.configuration_error = None
            raise
        self.config = candidate
        self.configuration_error = None
        return await self.get_config()

    async def save_config(self, config: AppConfig, previous: AppConfig) -> AppConfig:
        changed = {
            key: value
            for key, value in config.model_dump(mode="json").items()
            if value != previous.model_dump(mode="json")[key]
        }
        revision = hashlib.sha256(previous.model_dump_json().encode()).hexdigest()
        result = await self.execute(
            "config.update", {"base_revision": revision, "changes": changed}
        )
        return AppConfig.model_validate(result["config"])

    async def set_credential(self, key: str | None) -> dict[str, bool]:
        if key is None:
            self.store.clear_api_key()
        else:
            self.store.save_api_key(key)
        return {"configured": key is not None}

    async def health(self) -> dict[str, Any]:
        return {
            "monitor": self.monitor.status.model_dump(mode="json"),
            "notifications": await self.notification_status(),
            "config_revision": self.config_revision,
            "configuration_error": self.configuration_error,
        }

    async def notification_status(self) -> dict[str, object]:
        return await asyncio.to_thread(
            NotificationOutbox(self.store.database_path, self.config.notifications).status
        )

    async def notification_reconcile(self, send_history: bool) -> None:
        await asyncio.to_thread(
            NotificationOutbox(self.store.database_path, self.config.notifications).reconcile,
            send_history=send_history,
        )

    async def notification_resolve(self, identifier: str, cancel: bool) -> None:
        await asyncio.to_thread(
            NotificationOutbox(
                self.store.database_path, self.config.notifications
            ).resolve_delivery,
            identifier,
            cancel=cancel,
        )

    async def pause(self) -> MonitorStatus:
        self.monitor.pause()
        return self.monitor.status

    async def resume(self) -> MonitorStatus:
        self.monitor.resume()
        return self.monitor.status

    async def stop(self) -> None:
        self.stop_event.set()

    async def recover_jobs(self) -> None:
        async with self.repository.sessions() as session:
            await session.execute(
                text(
                    "UPDATE owner_jobs SET status='interrupted',error='Owner "
                    "stopped before completion; inspect evidence before retrying' "
                    "WHERE status='running'"
                )
            )
            await session.commit()

    async def operation_result(self, identifier: UUID) -> dict[str, Any]:
        async with self.repository.sessions() as session:
            row = (
                await session.execute(
                    text("SELECT status,result_json,error FROM owner_jobs WHERE id=:id"),
                    {"id": str(identifier)},
                )
            ).first()
        if row is None:
            raise KeyError(str(identifier))
        return {"status": row[0], "result": json.loads(row[1]) if row[1] else None, "error": row[2]}

    async def _queue_operation(self, operation: Callable[[], Awaitable[Any]]) -> dict[str, str]:
        identifier = uuid4()
        async with self.repository.sessions() as session:
            await session.execute(
                text("INSERT INTO owner_jobs VALUES(:id,'running',NULL,NULL)"),
                {"id": str(identifier)},
            )
            await session.commit()

        async def run() -> None:
            result, error, status = None, None, "complete"
            try:
                result = json.dumps(json_value(await operation()))
            except BaseException as exc:
                status = "interrupted" if isinstance(exc, asyncio.CancelledError) else "failed"
                key = self.store.load_api_key()
                error = redact_secrets(str(exc) or type(exc).__name__, [key] if key else ())
            async with self.repository.sessions() as session:
                await session.execute(
                    text(
                        "UPDATE owner_jobs SET "
                        "status=:status,result_json=:result,error=:error WHERE id=:id"
                    ),
                    {"status": status, "result": result, "error": error, "id": str(identifier)},
                )
                await session.commit()

        self._deferred.append(lambda: self._track(asyncio.create_task(run())))
        return {"job_id": str(identifier)}

    async def wait_operation(self, value: dict[str, str]) -> Any:
        while True:
            result = await self.operation_result(UUID(value["job_id"]))
            if result["status"] == "complete":
                return result["result"]
            if result["status"] != "running":
                raise RuntimeError(result["error"] or result["status"])
            await asyncio.sleep(0.25)

    async def diagnostic(self, kind: str, target: str) -> dict[str, str]:
        return await self._queue_operation(lambda: self.monitor.run_diagnostic(kind, target))

    async def queue_export(
        self, identifier: UUID, incident: bool = True, format_: str = "markdown"
    ) -> dict[str, str]:
        return await self._queue_operation(lambda: self.export(identifier, incident, format_))

    async def retention_apply(self, days: int = 30) -> dict[str, Any]:
        job = await self.maintenance.create(days)
        self._deferred.append(lambda: self.maintenance.launch(job.id))
        return job.model_dump(mode="json")

    async def list_backups(self) -> list[dict[str, Any]]:
        return await asyncio.to_thread(backup_inventory, self.store.database_path)

    async def prune_backups(
        self, keep_last: int = 3, older_than_days: int = 30, apply: bool = False
    ) -> list[str]:
        return await asyncio.to_thread(
            prune_backups,
            self.store.database_path,
            keep_last=keep_last,
            older_than_days=older_than_days,
            apply=apply,
        )

    def _track(self, task: asyncio.Task[Any]) -> None:
        self._tasks.add(task)

        def finish(done: asyncio.Task[Any]) -> None:
            self._tasks.discard(done)
            if not done.cancelled():
                done.exception()

        task.add_done_callback(finish)

    async def investigation_context(self, event_id: UUID) -> IncidentContext:
        event = await self.repository.get_event(event_id)
        if event is None:
            raise KeyError(str(event_id))
        report = await self.repository.incident_report_for_event(event_id)
        return build_incident_context(report, focus_event=event)

    async def queue_investigation(self, event_id: UUID) -> StoredInvestigation:
        event = await self.repository.get_event(event_id)
        if event is None:
            raise KeyError(str(event_id))
        if self.store.load_api_key() is None:
            raise RuntimeError("OpenAI API key is not configured")
        report = await self.repository.incident_report_for_event(event_id)
        scope = report.history.incident.id if report else event_id
        if scope in self._investigations:
            current = await self.repository.get_investigation(self._scope_records[scope])
            if current is not None and current.status in {"queued", "running"}:
                return current
        queued = await self.repository.queue_investigation(
            event_id,
            model_id=self.config.preset.model_id,
            requested_effort=self.config.preset.effort_for(event.severity),
        )

        def begin() -> None:
            task = asyncio.create_task(
                self._run_investigation(queued), name=f"investigation-{queued.id}"
            )
            self._investigations[scope] = task
            self._scope_records[scope] = queued.id
            self._track(task)
            task.add_done_callback(lambda _: self._investigations.pop(scope, None))

        self._deferred.append(begin)
        return queued

    async def _run_investigation(self, queued: StoredInvestigation) -> None:
        key = self.store.load_api_key()
        try:
            if key is None:
                raise RuntimeError("OpenAI key is unavailable")
            event = await self.repository.get_event(queued.event_id)
            if event is None:
                raise KeyError(str(queued.event_id))
            await self.repository.start_investigation(queued.id)
            result = await OpenAIClient(key).investigate(
                event, context=await self.investigation_context(event.id)
            )
            completion = asyncio.create_task(
                self.repository.complete_investigation(queued.id, result)
            )
            try:
                await asyncio.shield(completion)
            except asyncio.CancelledError:
                await completion
                raise
        except BaseException as exc:
            current = await self.repository.get_investigation(queued.id)
            if current and current.status in {"queued", "running"}:
                message = (
                    "Investigation interrupted; provider outcome may be unknown"
                    if isinstance(exc, asyncio.CancelledError)
                    else redact_secrets(str(exc), [key] if key else ())
                )
                await self.repository.fail_investigation(queued.id, error=message)
            if isinstance(exc, asyncio.CancelledError):
                raise

    async def investigate(self, event_id: UUID) -> StoredInvestigation:
        queued = StoredInvestigation.model_validate(
            await self.execute("investigation.request", {"event_id": str(event_id)})
        )
        return await self.wait_investigation(queued)

    async def wait_investigation(self, queued: StoredInvestigation) -> StoredInvestigation:
        while True:
            current = await self.repository.get_investigation(queued.id)
            if current is None:
                raise KeyError(str(queued.id))
            if current.status == "complete":
                return current
            if current.status == "failed":
                raise RuntimeError(current.error or "Investigation failed")
            await asyncio.sleep(0.25)

    async def export(
        self, identifier: UUID, incident: bool = True, format_: str = "markdown"
    ) -> str:
        if format_ not in {"markdown", "json"}:
            raise ValueError("Export format must be markdown or json")
        key = self.store.load_api_key()
        secrets = [key] if key else ()
        if incident:
            report = await self.repository.incident_report(identifier)
            if report is None:
                raise KeyError(str(identifier))
            rendered = (export_incident_json if format_ == "json" else export_incident_markdown)(
                report, secrets=secrets
            )
        else:
            event = await self.repository.get_event(identifier)
            if event is None:
                raise KeyError(str(identifier))
            investigations = await self.repository.list_investigations(event_id=identifier, limit=1)
            investigation = investigations[0] if investigations else None
            proposals = await self.repository.list_response_proposals(
                event_id=identifier, limit=500
            )
            proposal = next(
                (p for p in proposals if investigation and p.investigation_id == investigation.id),
                None,
            )
            suppressions = await self.repository.incidents.suppression_decisions(identifier)
            rendered = (export_json if format_ == "json" else export_markdown)(
                event,
                investigation,
                response_proposal=proposal,
                suppressions=suppressions,
                secrets=secrets,
            )
        suffix = "json" if format_ == "json" else "md"
        path = await asyncio.to_thread(
            write_managed_export,
            self.store.home,
            f"{'incident' if incident else 'event'}-{identifier}.{suffix}",
            rendered,
        )
        return str(path)

    async def close(self) -> None:
        self._closing = True
        await self.maintenance.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
