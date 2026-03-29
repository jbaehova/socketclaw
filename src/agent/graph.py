"""LangGraph StateGraph definition — agent pipeline graph.

Branches from classify_event based on classification result:
  - normal → log_pass → notify
  - suspicious → deep_analyze → decide_action → (notify | execute_response → notify)
  - critical → emergency_response → notify
"""

from __future__ import annotations

import functools
import logging
import os
from typing import Any

from langchain_anthropic import ChatAnthropic
from langgraph.graph import END, START, StateGraph

from .nodes import (
    classify_event,
    decide_action,
    deep_analyze,
    emergency_response,
    execute_response,
    log_pass,
    notify,
)
from .state import AgentState, EventWindow
from .tools import get_all_tools

logger = logging.getLogger(__name__)


def _route_classification(state: AgentState) -> str:
    """Determine the next node based on the classification value."""
    c = state.get("classification", "normal")
    if c == "critical":
        return "emergency_response"
    elif c == "suspicious":
        return "deep_analyze"
    else:
        return "log_pass"


def _route_action(state: AgentState) -> str:
    """Determine execute/notify based on the action value."""
    action = state.get("action", "log")
    if action in ("block", "investigate"):
        return "execute_response"
    return "notify"


def build_graph(
    model_name: str | None = None,
    api_key: str | None = None,
) -> Any:
    """Build and compile the agent StateGraph.

    Args:
        model_name: Claude model to use (default: claude-sonnet-4-20250514).
        api_key: Anthropic API key (default: from environment variable).

    Returns:
        Compiled LangGraph.
    """
    model = model_name or os.getenv("NETAGENT_MODEL", "claude-sonnet-4-20250514")
    key = api_key or os.getenv("ANTHROPIC_API_KEY")

    llm = ChatAnthropic(
        model=model,
        api_key=key,
        max_tokens=2048,
        temperature=0.1,
    )

    tools = get_all_tools()
    llm_with_tools = llm.bind_tools(tools)

    # Inject llm into node functions via partial
    classify_node = functools.partial(classify_event, llm=llm)
    analyze_node = functools.partial(deep_analyze, llm=llm_with_tools)
    decide_node = functools.partial(decide_action, llm=llm)
    execute_node = functools.partial(execute_response, llm=llm)
    emergency_node = functools.partial(emergency_response, llm=llm)

    # ── Graph construction ────────────────────────────────────────────────
    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("classify_event", classify_node)
    graph.add_node("log_pass", log_pass)
    graph.add_node("deep_analyze", analyze_node)
    graph.add_node("decide_action", decide_node)
    graph.add_node("execute_response", execute_node)
    graph.add_node("emergency_response", emergency_node)
    graph.add_node("notify", notify)

    # Edges
    graph.add_edge(START, "classify_event")

    # Branch based on classification
    graph.add_conditional_edges(
        "classify_event",
        _route_classification,
        {
            "log_pass": "log_pass",
            "deep_analyze": "deep_analyze",
            "emergency_response": "emergency_response",
        },
    )

    graph.add_edge("log_pass", "notify")
    graph.add_edge("deep_analyze", "decide_action")

    # Branch based on action
    graph.add_conditional_edges(
        "decide_action",
        _route_action,
        {
            "execute_response": "execute_response",
            "notify": "notify",
        },
    )

    graph.add_edge("execute_response", "notify")
    graph.add_edge("emergency_response", "notify")
    graph.add_edge("notify", END)

    compiled = graph.compile()
    logger.info("Agent graph compiled (model=%s)", model)
    return compiled


class AgentRunner:
    """Agent graph executor.

    Receives events, runs the graph, and returns results.
    Manages sliding window context via EventWindow.
    """

    def __init__(
        self,
        model_name: str | None = None,
        api_key: str | None = None,
        window_size: int = 50,
    ) -> None:
        self.graph = build_graph(model_name=model_name, api_key=api_key)
        self.window = EventWindow(max_size=window_size)

    async def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Process an event through the agent graph.

        Args:
            event: Network event.

        Returns:
            Agent decision result dict.
        """
        # Add event to sliding window
        self.window.add(event)

        initial_state: AgentState = {
            "event": event,
            "classification": "",
            "analysis": "",
            "action": "",
            "tool_results": [],
            "history": self.window.get_recent(10),
            "messages": [],
        }

        result = await self.graph.ainvoke(initial_state)

        return {
            "event": event,
            "classification": result.get("classification", "normal"),
            "action": result.get("action", "log"),
            "analysis": result.get("analysis", ""),
            "tool_results": result.get("tool_results", []),
        }
