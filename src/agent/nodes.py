"""LangGraph node functions — each stage of the agent pipeline.

classify_event → (log_pass | deep_analyze | emergency_response)
deep_analyze → decide_action → (notify | execute_response)
emergency_response → notify
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from .state import AgentState

logger = logging.getLogger(__name__)

# ── System prompts ────────────────────────────────────────────────────────

CLASSIFY_SYSTEM_PROMPT = """You are a network security event classification expert.
Analyze the given network event and recent event history to classify the severity.

Classification criteria:
- "normal": Normal network activity. No anomalies detected.
- "suspicious": Suspicious pattern. Further investigation needed. (e.g. abnormal port opens, high packet loss, repeated login failures)
- "critical": Dangerous situation requiring immediate response. (e.g. many ports opened simultaneously, 100% packet loss, brute-force detected)

You must respond only in the following JSON format:
{"classification": "normal|suspicious|critical", "reason": "reason for classification"}"""

ANALYZE_SYSTEM_PROMPT = """You are a network security analyst.
Perform deep analysis on events classified as suspicious.

Use the provided tools to gather additional information and precisely assess the threat level.
Write a detailed analysis report synthesizing the tool call results."""

DECIDE_SYSTEM_PROMPT = """You are a network security response decision maker.
Based on the analysis results, decide the appropriate response action.

Possible actions:
- "log": Record only (low risk)
- "alert": Notify administrator (attention needed)
- "block": Block IP (confirmed threat)
- "investigate": Further investigation needed (deferred judgment)

You must respond only in the following JSON format:
{"action": "log|alert|block|investigate", "reason": "reason for decision", "details": "additional explanation"}"""

EMERGENCY_SYSTEM_PROMPT = """You are an emergency network security response specialist.
Perform immediate response to events classified as critical.

1. If there is a threat IP, use the block tool.
2. Generate a detailed analysis report.
3. Record the response actions taken."""


# ── Node functions ────────────────────────────────────────────────────────

async def classify_event(state: AgentState, llm: Any) -> dict:
    """Classify an event (normal / suspicious / critical).

    The LLM judges severity based on the event + sliding window history.
    """
    event = state["event"]
    history = state.get("history", [])

    history_summary = ""
    if history:
        history_summary = f"\n\nRecent {len(history)} event summary:\n"
        for h in history[-10:]:
            history_summary += f"- [{h.get('source', '?')}] {h.get('type', '?')}: severity={_extract_severity(h)}\n"

    user_msg = f"""Classify the following network event:

```json
{json.dumps(event, ensure_ascii=False, indent=2, default=str)}
```
{history_summary}"""

    messages = [
        SystemMessage(content=CLASSIFY_SYSTEM_PROMPT),
        HumanMessage(content=user_msg),
    ]

    response = await llm.ainvoke(messages)
    content = response.content

    # Parse JSON
    try:
        parsed = _extract_json(content)
        classification = parsed.get("classification", "normal")
        reason = parsed.get("reason", "")
    except (json.JSONDecodeError, ValueError):
        logger.warning("Classification parse failed, defaulting to suspicious: %s", content)
        classification = "suspicious"
        reason = content

    if classification not in ("normal", "suspicious", "critical"):
        classification = "suspicious"

    logger.info("Event classified as: %s (reason: %s)", classification, reason)

    return {
        "classification": classification,
        "analysis": reason,
        "messages": [HumanMessage(content=user_msg), response],
    }


async def log_pass(state: AgentState) -> dict:
    """Normal event — log only and exit."""
    logger.info("Event classified as normal — logging only")
    return {
        "action": "log",
        "analysis": state.get("analysis", "Classified as normal event. No further action required."),
    }


async def deep_analyze(state: AgentState, llm: Any) -> dict:
    """Suspicious event — gather additional information via tool calls.

    The LLM investigates the target host using tools and writes an analysis result.
    """
    event = state["event"]
    hosts = _extract_hosts(event)

    user_msg = f"""This event has been classified as suspicious. Perform deep analysis.

Event:
```json
{json.dumps(event, ensure_ascii=False, indent=2, default=str)}
```

Related hosts: {', '.join(hosts) if hosts else 'none'}

Gather additional information using the available tools and analyze."""

    messages = list(state.get("messages", []))
    messages.append(HumanMessage(content=user_msg))

    # Invoke LLM with tools bound for tool calling
    response = await llm.ainvoke(messages)

    tool_results = state.get("tool_results", [])

    # Collect tool call results if any
    if hasattr(response, "tool_calls") and response.tool_calls:
        for tc in response.tool_calls:
            tool_results.append({
                "tool": tc.get("name", "unknown"),
                "args": tc.get("args", {}),
                "timestamp": time.time(),
            })

    analysis = response.content if isinstance(response.content, str) else str(response.content)

    return {
        "analysis": analysis or "Deep analysis completed.",
        "tool_results": tool_results,
        "messages": [HumanMessage(content=user_msg), response],
    }


async def decide_action(state: AgentState, llm: Any) -> dict:
    """Decide response action based on collected information."""
    event = state["event"]
    analysis = state.get("analysis", "")
    tool_results = state.get("tool_results", [])

    user_msg = f"""Based on the analysis results, decide the response action.

Event:
```json
{json.dumps(event, ensure_ascii=False, indent=2, default=str)}
```

Analysis result:
{analysis}

Tool call results:
{json.dumps(tool_results, ensure_ascii=False, indent=2, default=str) if tool_results else 'none'}
"""

    messages = [
        SystemMessage(content=DECIDE_SYSTEM_PROMPT),
        HumanMessage(content=user_msg),
    ]

    response = await llm.ainvoke(messages)

    try:
        parsed = _extract_json(response.content)
        action = parsed.get("action", "alert")
        reason = parsed.get("reason", "")
        details = parsed.get("details", "")
    except (json.JSONDecodeError, ValueError):
        action = "alert"
        reason = response.content
        details = ""

    if action not in ("log", "alert", "block", "investigate"):
        action = "alert"

    logger.info("Action decided: %s (reason: %s)", action, reason)

    return {
        "action": action,
        "analysis": f"{analysis}\n\nDecision: {action} - {reason}\n{details}".strip(),
        "messages": [HumanMessage(content=user_msg), response],
    }


async def execute_response(state: AgentState, llm: Any) -> dict:
    """Execute block/investigate action (simulation).

    Performs response such as calling the block_ip tool.
    """
    action = state.get("action", "alert")
    event = state["event"]
    hosts = _extract_hosts(event)

    results: list[dict] = []

    if action == "block" and hosts:
        from .tools import block_ip
        for host in hosts:
            try:
                result = await block_ip.ainvoke({"ip": host, "reason": state.get("analysis", "")[:200]})
                results.append({"tool": "block_ip", "host": host, "result": result})
            except Exception as exc:
                results.append({"tool": "block_ip", "host": host, "error": str(exc)})

    return {
        "tool_results": results,
        "analysis": state.get("analysis", "") + f"\n\nResponse executed: {action} ({len(results)} processed)",
    }


async def emergency_response(state: AgentState, llm: Any) -> dict:
    """Critical event — immediate block + detailed report generation."""
    event = state["event"]
    hosts = _extract_hosts(event)

    messages = [
        SystemMessage(content=EMERGENCY_SYSTEM_PROMPT),
        HumanMessage(content=f"""This is a critical event requiring emergency response.

Event:
```json
{json.dumps(event, ensure_ascii=False, indent=2, default=str)}
```

Related hosts: {', '.join(hosts) if hosts else 'none'}

Take immediate response actions and write a detailed report."""),
    ]

    # Immediate block
    results: list[dict] = []
    if hosts:
        from .tools import block_ip
        for host in hosts:
            try:
                result = await block_ip.ainvoke({"ip": host, "reason": "Critical event - emergency block"})
                results.append({"tool": "block_ip", "host": host, "result": result})
            except Exception as exc:
                results.append({"tool": "block_ip", "host": host, "error": str(exc)})

    response = await llm.ainvoke(messages)
    analysis = response.content if isinstance(response.content, str) else str(response.content)

    return {
        "classification": "critical",
        "action": "block",
        "analysis": analysis,
        "tool_results": results,
        "messages": messages + [response],
    }


async def notify(state: AgentState) -> dict:
    """Push results to the dashboard via WebSocket (returns state only — actual push is done by graph caller)."""
    result = {
        "event": state["event"],
        "classification": state.get("classification", "normal"),
        "action": state.get("action", "log"),
        "analysis": state.get("analysis", ""),
        "tool_results": state.get("tool_results", []),
        "timestamp": time.time(),
    }
    logger.info(
        "Notification: classification=%s, action=%s",
        result["classification"],
        result["action"],
    )
    return {"analysis": state.get("analysis", "")}


# ── Helpers ───────────────────────────────────────────────────────────────

def _extract_hosts(event: dict[str, Any]) -> list[str]:
    """Extract host IPs from an event."""
    hosts = []
    if "host" in event:
        hosts.append(event["host"])
    for r in event.get("results", []):
        if isinstance(r, dict) and "host" in r:
            hosts.append(r["host"])
    return list(set(hosts))


def _extract_severity(event: dict[str, Any]) -> str:
    """Extract severity from an event."""
    if "severity" in event:
        return event["severity"]
    results = event.get("results", [])
    severities = [r.get("severity", "normal") for r in results if isinstance(r, dict)]
    if "critical" in severities:
        return "critical"
    if "warning" in severities:
        return "warning"
    return "normal"


def _extract_json(text: str) -> dict:
    """Extract a JSON object from text."""
    # Try ```json ... ``` block first
    import re
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        return json.loads(match.group(1).strip())
    # Try direct JSON
    match = re.search(r"\{[^{}]*\}", text)
    if match:
        return json.loads(match.group(0))
    raise ValueError(f"No JSON found in: {text[:200]}")
