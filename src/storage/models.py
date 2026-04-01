"""SQLAlchemy models — Event and AgentDecision tables."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Event(Base):
    """Network event log."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # probe name
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="normal")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    decisions: Mapped[list[AgentDecision]] = relationship(back_populates="event")

    @property
    def payload(self) -> dict:
        return json.loads(self.payload_json)

    @payload.setter
    def payload(self, value: dict) -> None:
        self.payload_json = json.dumps(value)


class AgentDecision(Base):
    """Agent analysis/decision record."""

    __tablename__ = "agent_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(Integer, ForeignKey("events.id"), nullable=False)
    classification: Mapped[str] = mapped_column(String(20), nullable=False)  # normal|suspicious|critical
    analysis: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(30), nullable=False)  # log|alert|block|investigate
    tool_results_json: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    event: Mapped[Event] = relationship(back_populates="decisions")

    @property
    def tool_results(self) -> list[dict] | None:
        if self.tool_results_json:
            return json.loads(self.tool_results_json)
        return None

    @tool_results.setter
    def tool_results(self, value: list[dict] | None) -> None:
        self.tool_results_json = json.dumps(value) if value else None
