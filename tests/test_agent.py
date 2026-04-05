"""Agent node/graph tests — using mock LLM."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from src.agent.nodes import (
    _extract_hosts,
    _extract_json,
    _extract_severity,
    classify_event,
    decide_action,
    log_pass,
    notify,
)
from src.agent.state import AgentState, EventWindow
from src.agent.tools import block_ip, get_all_tools, get_blocked_ips, _blocked_ips


# ── EventWindow tests ─────────────────────────────────────────────────────


class TestEventWindow:
    def test_add_and_get(self):
        w = EventWindow(max_size=3)
        w.add({"type": "a"})
        w.add({"type": "b"})
        w.add({"type": "c"})
        assert len(w) == 3
        assert w.get_recent(2) == [{"type": "b"}, {"type": "c"}]

    def test_max_size(self):
        w = EventWindow(max_size=2)
        w.add({"type": "a"})
        w.add({"type": "b"})
        w.add({"type": "c"})
        assert len(w) == 2
        assert w.get_recent() == [{"type": "b"}, {"type": "c"}]

    def test_empty(self):
        w = EventWindow()
        assert len(w) == 0
        assert w.get_recent() == []
        summary = w.get_summary()
        assert summary["total"] == 0

    def test_summary(self):
        w = EventWindow()
        w.add({"source": "ping", "severity": "normal"})
        w.add({"source": "ping", "severity": "warning"})
        w.add({"source": "port_scan", "severity": "critical"})
        s = w.get_summary()
        assert s["total"] == 3
        assert s["by_severity"]["normal"] == 1
        assert s["by_severity"]["critical"] == 1
        assert s["by_source"]["ping"] == 2

    def test_summary_nested_severity(self):
        w = EventWindow()
        w.add({"source": "ping", "results": [{"severity": "warning"}, {"severity": "critical"}]})
        s = w.get_summary()
        assert s["by_severity"]["critical"] == 1


# ── Helper function tests ─────────────────────────────────────────────────


class TestHelpers:
    def test_extract_hosts_flat(self):
        hosts = _extract_hosts({"host": "1.2.3.4"})
        assert hosts == ["1.2.3.4"]

    def test_extract_hosts_results(self):
        hosts = _extract_hosts({"results": [{"host": "a"}, {"host": "b"}]})
        assert set(hosts) == {"a", "b"}

    def test_extract_hosts_dedup(self):
        hosts = _extract_hosts({"host": "a", "results": [{"host": "a"}]})
        assert hosts == ["a"]

    def test_extract_hosts_empty(self):
        assert _extract_hosts({}) == []

    def test_extract_severity_direct(self):
        assert _extract_severity({"severity": "critical"}) == "critical"

    def test_extract_severity_nested(self):
        ev = {"results": [{"severity": "normal"}, {"severity": "warning"}]}
        assert _extract_severity(ev) == "warning"

    def test_extract_severity_default(self):
        assert _extract_severity({}) == "normal"

    def test_extract_json_raw(self):
        result = _extract_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_extract_json_codeblock(self):
        text = '```json\n{"classification": "normal"}\n```'
        result = _extract_json(text)
        assert result["classification"] == "normal"

    def test_extract_json_mixed(self):
        text = 'Here is the result: {"action": "block", "reason": "test"} done.'
        result = _extract_json(text)
        assert result["action"] == "block"

    def test_extract_json_invalid(self):
        with pytest.raises(ValueError):
            _extract_json("no json here")


# ── Node function tests (mock LLM) ────────────────────────────────────────


def _make_state(**overrides: Any) -> AgentState:
    """Create an AgentState for testing."""
    base: AgentState = {
        "event": {"type": "ping_result", "source": "ping", "results": [{"host": "8.8.8.8", "severity": "normal"}]},
        "classification": "",
        "analysis": "",
        "action": "",
        "tool_results": [],
        "history": [],
        "messages": [],
    }
    base.update(overrides)
    return base


def _mock_llm(content: str) -> AsyncMock:
    """Create a mock LLM."""
    response = AIMessage(content=content)
    mock = AsyncMock()
    mock.ainvoke = AsyncMock(return_value=response)
    return mock


class TestClassifyEvent:
    @pytest.mark.asyncio
    async def test_normal(self):
        llm = _mock_llm('{"classification": "normal", "reason": "normal traffic"}')
        state = _make_state()
        result = await classify_event(state, llm=llm)
        assert result["classification"] == "normal"

    @pytest.mark.asyncio
    async def test_suspicious(self):
        llm = _mock_llm('{"classification": "suspicious", "reason": "port change detected"}')
        state = _make_state()
        result = await classify_event(state, llm=llm)
        assert result["classification"] == "suspicious"

    @pytest.mark.asyncio
    async def test_critical(self):
        llm = _mock_llm('{"classification": "critical", "reason": "brute-force attack"}')
        state = _make_state()
        result = await classify_event(state, llm=llm)
        assert result["classification"] == "critical"

    @pytest.mark.asyncio
    async def test_invalid_json_defaults_suspicious(self):
        llm = _mock_llm("I think this is suspicious but can't format JSON")
        state = _make_state()
        result = await classify_event(state, llm=llm)
        assert result["classification"] == "suspicious"

    @pytest.mark.asyncio
    async def test_with_history(self):
        llm = _mock_llm('{"classification": "normal", "reason": "analyzed with history"}')
        history = [{"source": "ping", "severity": "normal"} for _ in range(5)]
        state = _make_state(history=history)
        result = await classify_event(state, llm=llm)
        assert result["classification"] == "normal"
        # Verify history was passed to LLM
        call_args = llm.ainvoke.call_args[0][0]
        assert any("Recent" in str(m) for m in call_args)


class TestLogPass:
    @pytest.mark.asyncio
    async def test_log_pass(self):
        state = _make_state(analysis="existing analysis")
        result = await log_pass(state)
        assert result["action"] == "log"


class TestDecideAction:
    @pytest.mark.asyncio
    async def test_block_decision(self):
        llm = _mock_llm('{"action": "block", "reason": "malicious IP", "details": "block immediately"}')
        state = _make_state(analysis="threat confirmed")
        result = await decide_action(state, llm=llm)
        assert result["action"] == "block"

    @pytest.mark.asyncio
    async def test_alert_decision(self):
        llm = _mock_llm('{"action": "alert", "reason": "monitoring needed"}')
        state = _make_state()
        result = await decide_action(state, llm=llm)
        assert result["action"] == "alert"

    @pytest.mark.asyncio
    async def test_invalid_action_defaults_alert(self):
        llm = _mock_llm('{"action": "destroy", "reason": "wrong"}')
        state = _make_state()
        result = await decide_action(state, llm=llm)
        assert result["action"] == "alert"


class TestNotify:
    @pytest.mark.asyncio
    async def test_notify_returns_analysis(self):
        state = _make_state(
            classification="suspicious",
            action="alert",
            analysis="test analysis",
        )
        result = await notify(state)
        assert "analysis" in result


# ── Tools tests ───────────────────────────────────────────────────────────


class TestTools:
    def test_get_all_tools(self):
        tools = get_all_tools()
        assert len(tools) == 6
        names = [t.name for t in tools]
        assert "ping_host" in names
        assert "port_scan" in names
        assert "whois_lookup" in names
        assert "traceroute" in names
        assert "block_ip" in names
        assert "generate_report" in names

    @pytest.mark.asyncio
    async def test_block_ip_simulation(self):
        _blocked_ips.clear()
        result = await block_ip.ainvoke({"ip": "10.0.0.1", "reason": "test"})
        parsed = json.loads(result)
        assert parsed["ip"] == "10.0.0.1"
        assert parsed["simulated"] is True
        assert "10.0.0.1" in get_blocked_ips()
        _blocked_ips.clear()

    @pytest.mark.asyncio
    async def test_ping_host_localhost(self):
        from src.agent.tools import ping_host
        result = await ping_host.ainvoke({"host": "127.0.0.1", "count": 1, "timeout": 2.0})
        parsed = json.loads(result)
        assert parsed["host"] == "127.0.0.1"
        assert "loss_pct" in parsed

    @pytest.mark.asyncio
    async def test_generate_report(self):
        from src.agent.tools import generate_report
        result = await generate_report.ainvoke({
            "event_summary": "test event",
            "analysis": "test analysis",
            "classification": "suspicious",
            "action_taken": "alert sent",
        })
        assert "test event" in result
        assert "SUSPICIOUS" in result


# ── Graph routing tests ───────────────────────────────────────────────────


class TestGraphRouting:
    def test_route_classification(self):
        from src.agent.graph import _route_classification
        assert _route_classification({"classification": "normal"}) == "log_pass"
        assert _route_classification({"classification": "suspicious"}) == "deep_analyze"
        assert _route_classification({"classification": "critical"}) == "emergency_response"
        assert _route_classification({}) == "log_pass"

    def test_route_action(self):
        from src.agent.graph import _route_action
        assert _route_action({"action": "log"}) == "notify"
        assert _route_action({"action": "alert"}) == "notify"
        assert _route_action({"action": "block"}) == "execute_response"
        assert _route_action({"action": "investigate"}) == "execute_response"
