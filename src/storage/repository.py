"""Event/decision CRUD repository.

Reads and writes data using async SQLAlchemy sessions backed by aiosqlite.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .models import AgentDecision, Base, Event

logger = logging.getLogger(__name__)


class Repository:
    """Event and agent decision CRUD."""

    def __init__(self, db_url: str = "sqlite+aiosqlite:///netagent.db") -> None:
        self._engine = create_async_engine(db_url, echo=False)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def init_db(self) -> None:
        """Create tables."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized")

    async def close(self) -> None:
        """Dispose the engine."""
        await self._engine.dispose()

    # ── Event CRUD ────────────────────────────────────────────────────────

    async def save_event(self, event_data: dict[str, Any]) -> Event:
        """Save an event to the database."""
        event = Event(
            timestamp=event_data.get("timestamp", 0.0),
            source=event_data.get("source", "unknown"),
            event_type=event_data.get("type", "unknown"),
            severity=self._extract_severity(event_data),
            payload_json=json.dumps(event_data),
        )
        async with self._session_factory() as session:
            session.add(event)
            await session.commit()
            await session.refresh(event)
        return event

    async def get_events(
        self,
        limit: int = 50,
        severity: str | None = None,
        source: str | None = None,
    ) -> list[Event]:
        """Query the event list."""
        stmt = select(Event).order_by(Event.id.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Event.severity == severity)
        if source:
            stmt = stmt.where(Event.source == source)

        async with self._session_factory() as session:
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_event_by_id(self, event_id: int) -> Event | None:
        """Query an event by ID."""
        async with self._session_factory() as session:
            return await session.get(Event, event_id)

    # ── AgentDecision CRUD ────────────────────────────────────────────────

    async def save_decision(
        self,
        event_id: int,
        classification: str,
        analysis: str,
        action: str,
        tool_results: list[dict] | None = None,
    ) -> AgentDecision:
        """Save an agent decision to the database."""
        decision = AgentDecision(
            event_id=event_id,
            classification=classification,
            analysis=analysis,
            action=action,
            tool_results_json=json.dumps(tool_results) if tool_results else None,
        )
        async with self._session_factory() as session:
            session.add(decision)
            await session.commit()
            await session.refresh(decision)
        return decision

    async def get_decisions(
        self,
        limit: int = 50,
        classification: str | None = None,
    ) -> list[AgentDecision]:
        """Query the agent decision list."""
        stmt = select(AgentDecision).order_by(AgentDecision.id.desc()).limit(limit)
        if classification:
            stmt = stmt.where(AgentDecision.classification == classification)

        async with self._session_factory() as session:
            result = await session.execute(stmt)
            return list(result.scalars().all())

    @staticmethod
    def _extract_severity(event_data: dict[str, Any]) -> str:
        """Extract severity from event data."""
        if "severity" in event_data:
            return event_data["severity"]
        # Highest severity among results array
        results = event_data.get("results", [])
        severities = [r.get("severity", "normal") for r in results if isinstance(r, dict)]
        if "critical" in severities:
            return "critical"
        if "warning" in severities:
            return "warning"
        return "normal"
