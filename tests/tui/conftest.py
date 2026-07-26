from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from socketclaw.config import AppConfig, ConfigStore
from socketclaw.domain import Assessment, DetectionSignal, ModelUsage
from socketclaw.monitor import MonitorStatus
from socketclaw.openrouter import KeyStatus
from socketclaw.storage import (
    EventQuery,
    SessionStats,
    StoredEvent,
    StoredInvestigation,
    StoredResponseProposal,
)
from socketclaw.ui.app import AppServices, SocketClawApp


class TestMonitor:
    __test__ = False

    def __init__(self, repository: FakeRepository) -> None:
        self.repository = repository
        self.running = False
        self.paused = False
        self.started = 0
        self.stopped = 0
        self.diagnostics: list[tuple[str, str]] = []
        self._subscribers: set[asyncio.Queue[StoredEvent]] = set()

    @property
    def status(self) -> MonitorStatus:
        return MonitorStatus(
            running=self.running,
            paused=self.paused,
            started_at=datetime.now().astimezone() if self.running else None,
            active_jobs=2 if self.running else 0,
            last_error=None,
        )

    async def start(self) -> None:
        self.running = True
        self.started += 1

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    async def stop(self) -> None:
        self.running = False
        self.stopped += 1

    async def events(self) -> AsyncIterator[StoredEvent]:
        queue: asyncio.Queue[StoredEvent] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    async def publish(self, event: StoredEvent) -> None:
        self.repository.events_data.insert(0, event)
        for queue in tuple(self._subscribers):
            queue.put_nowait(event)

    async def run_diagnostic(self, kind: str, target: str) -> StoredEvent:
        self.diagnostics.append((kind, target))
        event = event_fixture(
            title=f"{kind.title()} diagnostic completed",
            target=target,
            source="manual",
            event_type=f"manual.{kind}",
        )
        await self.publish(event)
        return event


class FakeRepository:
    def __init__(
        self,
        events: list[StoredEvent] | None = None,
        investigations: list[StoredInvestigation] | None = None,
        proposals: list[StoredResponseProposal] | None = None,
    ) -> None:
        self.events_data = list(events or [])
        self.investigations_data = list(investigations or [])
        self.proposals_data = list(proposals or [])

    async def list_events(self, query: EventQuery | None = None) -> list[StoredEvent]:
        query = query or EventQuery()
        rows = self.events_data
        if query.severity is not None:
            rows = [row for row in rows if row.severity == query.severity]
        if query.source is not None:
            rows = [row for row in rows if row.source == query.source]
        if query.text:
            needle = query.text.casefold()
            rows = [
                row
                for row in rows
                if needle in f"{row.title} {row.summary} {row.target or ''}".casefold()
            ]
        return rows[query.offset : query.offset + query.limit]

    async def get_event(self, event_id: UUID) -> StoredEvent | None:
        return next((row for row in self.events_data if row.id == event_id), None)

    async def list_investigations(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
    ) -> list[StoredInvestigation]:
        rows = self.investigations_data
        if event_id is not None:
            rows = [row for row in rows if row.event_id == event_id]
        return rows[:limit]

    async def list_response_proposals(
        self,
        *,
        event_id: UUID | None = None,
        limit: int = 100,
    ) -> list[StoredResponseProposal]:
        rows = self.proposals_data
        if event_id is not None:
            rows = [row for row in rows if row.event_id == event_id]
        return rows[:limit]

    async def update_response_proposal_status(
        self,
        proposal_id: UUID,
        status: str,
    ) -> StoredResponseProposal:
        index = next(
            (
                position
                for position, item in enumerate(self.proposals_data)
                if item.id == proposal_id
            ),
            None,
        )
        if index is None:
            raise KeyError(str(proposal_id))
        current = self.proposals_data[index]
        allowed = {
            "pending": {"simulated", "approved", "rejected"},
            "approved": {"executed", "rejected"},
            "simulated": set(),
            "executed": set(),
            "rejected": set(),
        }
        if status not in allowed[current.status]:
            raise ValueError(f"cannot transition {current.status} to {status}")
        updated = current.model_copy(update={"status": status})
        self.proposals_data[index] = updated
        return updated

    async def session_stats(self) -> SessionStats:
        complete = [item for item in self.investigations_data if item.status == "complete"]
        return SessionStats(
            total_events=len(self.events_data),
            by_severity={
                severity: sum(item.severity.value == severity for item in self.events_data)
                for severity in ("info", "low", "medium", "high", "critical")
            },
            completed_investigations=len(complete),
            failed_investigations=sum(item.status == "failed" for item in self.investigations_data),
            total_tokens=sum((item.usage.total_tokens or 0) for item in complete if item.usage),
            cost_usd=sum(item.usage.cost_usd for item in complete if item.usage),
        )


KeyValidator = Callable[[str], Awaitable[KeyStatus]]


async def valid_key(_key: str) -> KeyStatus:
    return KeyStatus(
        label="socketclaw-test",
        is_free_tier=False,
        limit=10,
        limit_remaining=9,
        usage=1,
    )


@dataclass
class AppFixture:
    app: SocketClawApp
    store: ConfigStore
    monitor: TestMonitor
    repository: FakeRepository


def event_fixture(
    *,
    title: str = "Repeated SSH authentication failures",
    target: str = "198.51.100.24",
    severity: str = "critical",
    source: str = "log",
    event_type: str = "log.auth_failure",
) -> StoredEvent:
    now = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
    return StoredEvent(
        id=uuid4(),
        observed_at=now,
        source=source,
        event_type=event_type,
        title=title,
        summary="Twelve failed root logins were observed in sixty seconds.",
        target=target,
        evidence={"attempts": 12},
        score=95 if severity == "critical" else 10,
        severity=severity,
        investigation_state="not_requested",
        created_at=now,
        signals=(
            DetectionSignal(
                code="auth.burst",
                label="Authentication burst",
                points=95,
                detail="Twelve failures exceeded the configured threshold.",
            ),
        ),
    )


def investigation_fixture(
    event_id: UUID,
    *,
    status: str = "complete",
) -> StoredInvestigation:
    now = datetime(2026, 7, 27, 12, 1, tzinfo=UTC)
    return StoredInvestigation(
        id=uuid4(),
        event_id=event_id,
        status=status,
        assessment=(
            Assessment(
                classification="critical",
                confidence=0.97,
                summary="The source is likely attacking SSH.",
                rationale=["Repeated root authentication failures were observed."],
                recommended_actions=["Review and block the source if confirmed."],
            )
            if status == "complete"
            else None
        ),
        usage=(
            ModelUsage(
                prompt_tokens=120,
                completion_tokens=40,
                reasoning_tokens=20,
                cost_usd=0.0042,
                latency_ms=810,
            )
            if status == "complete"
            else None
        ),
        model_id="openai/gpt-5.6-terra",
        requested_effort="high",
        error="Provider unavailable" if status == "failed" else None,
        created_at=now,
        completed_at=now,
    )


@pytest.fixture
def app_factory(
    tmp_path: Path,
) -> Callable[..., AppFixture]:
    counter = 0

    def make(
        *,
        configured: bool,
        validator: KeyValidator = valid_key,
        events: list[StoredEvent] | None = None,
        investigations: list[StoredInvestigation] | None = None,
        proposals: list[StoredResponseProposal] | None = None,
        config: AppConfig | None = None,
        investigation_result: StoredInvestigation | None = None,
    ) -> AppFixture:
        nonlocal counter
        counter += 1
        store = ConfigStore(tmp_path / f"home-{counter}")
        if configured:
            store.save(config or AppConfig())
            store.save_api_key("sk-or-v1-configured")
        repository = FakeRepository(events, investigations, proposals)
        monitor = TestMonitor(repository)

        async def investigate(event_id: UUID) -> StoredInvestigation:
            result = investigation_result or investigation_fixture(event_id)
            result = result.model_copy(update={"id": uuid4(), "event_id": event_id})
            repository.investigations_data.insert(0, result)
            return result

        services = AppServices(
            config_store=store,
            monitor=monitor,
            validate_key=validator,
            repository=repository,
            investigate=investigate,
        )
        return AppFixture(
            app=SocketClawApp(services),
            store=store,
            monitor=monitor,
            repository=repository,
        )

    return make
