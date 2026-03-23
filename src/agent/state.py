"""AgentState — LangGraph state definition + sliding window."""

from __future__ import annotations

import operator
from collections import deque
from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State of the LangGraph agent.

    Attributes:
        event: The network event currently being processed.
        classification: Classification result ("normal" | "suspicious" | "critical").
        analysis: LLM analysis result text.
        action: Response action ("log" | "alert" | "block" | "investigate").
        tool_results: Accumulated tool call results.
        history: Recent N events context (sliding window).
        messages: LLM message history.
    """

    event: dict[str, Any]
    classification: str
    analysis: str
    action: str
    tool_results: Annotated[list[dict[str, Any]], operator.add]
    history: list[dict[str, Any]]
    messages: Annotated[list, add_messages]


class EventWindow:
    """Sliding window maintaining the most recent N events.

    Used by the agent as context when classifying events.
    """

    def __init__(self, max_size: int = 50) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self.max_size = max_size

    def add(self, event: dict[str, Any]) -> None:
        """Add an event."""
        self._buffer.append(event)

    def get_recent(self, n: int | None = None) -> list[dict[str, Any]]:
        """Return the most recent n events (all if None)."""
        if n is None:
            return list(self._buffer)
        return list(self._buffer)[-n:]

    def get_summary(self) -> dict[str, Any]:
        """Summary statistics of events in the window."""
        events = list(self._buffer)
        if not events:
            return {"total": 0, "by_severity": {}, "by_source": {}}

        by_severity: dict[str, int] = {}
        by_source: dict[str, int] = {}

        for ev in events:
            sev = self._extract_severity(ev)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            src = ev.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1

        return {
            "total": len(events),
            "by_severity": by_severity,
            "by_source": by_source,
        }

    @staticmethod
    def _extract_severity(event: dict[str, Any]) -> str:
        if "severity" in event:
            return event["severity"]
        results = event.get("results", [])
        severities = [r.get("severity", "normal") for r in results if isinstance(r, dict)]
        if "critical" in severities:
            return "critical"
        if "warning" in severities:
            return "warning"
        return "normal"

    def __len__(self) -> int:
        return len(self._buffer)
