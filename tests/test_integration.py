"""Integration tests — simulator → server → client end-to-end.

Validates the network pipeline without actual LLM calls (agent callback mocked).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.network.client import NetAgentClient
from src.network.multiplexer import Multiplexer
from src.network.server import NetAgentServer
from src.protocol.constants import (
    CH_AGENT,
    CH_MONITORING,
    MSG_AGENT_RESULT,
    MSG_EVENT,
    MSG_HEARTBEAT,
)
from src.protocol.frame import Frame
from src.storage.repository import Repository
from src.ui.dashboard import DashboardState

# Fixed test port to avoid conflicts
TEST_PORT = 18765


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
async def event_queue():
    return asyncio.Queue()


@pytest.fixture
async def server(event_queue):
    """Start/stop server for testing."""
    srv = NetAgentServer(
        host="127.0.0.1",
        port=TEST_PORT,
        event_queue=event_queue,
        heartbeat_interval=60,  # disable heartbeat in tests
    )
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def db_repo(tmp_path):
    """In-memory DB for testing."""
    repo = Repository("sqlite+aiosqlite:///:memory:")
    await repo.init_db()
    yield repo
    await repo.close()


# ── Server-client integration ─────────────────────────────────────────────


class TestServerClientIntegration:
    @pytest.mark.asyncio
    async def test_client_connects_and_receives_event(self, server, event_queue):
        """Verify that the client connects to the server and receives events."""
        received: list[Frame] = []

        async def on_msg(frame: Frame) -> None:
            received.append(frame)

        client = NetAgentClient(
            uri=f"ws://127.0.0.1:{TEST_PORT}",
            on_message=on_msg,
            max_reconnect_attempts=1,
        )
        await client.connect()
        await asyncio.sleep(0.2)  # Wait for connection

        # Inject event
        test_event = {
            "type": "ping_result",
            "source": "ping",
            "timestamp": time.time(),
            "results": [{"host": "8.8.8.8", "rtt_avg": 10.5, "severity": "normal"}],
        }
        await event_queue.put(test_event)
        await asyncio.sleep(0.5)

        await client.disconnect()

        # Verify EVENT frame (and possibly ACK) was received
        event_frames = [f for f in received if f.type == MSG_EVENT]
        assert len(event_frames) >= 1
        assert event_frames[0].payload["type"] == "ping_result"

    @pytest.mark.asyncio
    async def test_multiple_clients(self, server, event_queue):
        """Verify that multiple clients receive events simultaneously."""
        received_1: list[Frame] = []
        received_2: list[Frame] = []

        client1 = NetAgentClient(
            uri=f"ws://127.0.0.1:{TEST_PORT}",
            on_message=lambda f: _append_coro(received_1, f),
            max_reconnect_attempts=1,
        )
        client2 = NetAgentClient(
            uri=f"ws://127.0.0.1:{TEST_PORT}",
            on_message=lambda f: _append_coro(received_2, f),
            max_reconnect_attempts=1,
        )

        await client1.connect()
        await client2.connect()
        await asyncio.sleep(0.3)

        await event_queue.put({"type": "test", "source": "sim", "timestamp": time.time()})
        await asyncio.sleep(0.5)

        await client1.disconnect()
        await client2.disconnect()

        events_1 = [f for f in received_1 if f.type == MSG_EVENT]
        events_2 = [f for f in received_2 if f.type == MSG_EVENT]
        assert len(events_1) >= 1
        assert len(events_2) >= 1

    @pytest.mark.asyncio
    async def test_agent_callback_integration(self, event_queue):
        """Verify that the agent callback is called and results are delivered to the client."""

        async def mock_agent(event: dict) -> dict | None:
            return {
                "classification": "suspicious",
                "action": "alert",
                "analysis": "Mock analysis",
                "timestamp": time.time(),
            }

        srv = NetAgentServer(
            host="127.0.0.1",
            port=TEST_PORT + 1,
            event_queue=event_queue,
            agent_callback=mock_agent,
            heartbeat_interval=60,
        )
        await srv.start()

        received: list[Frame] = []
        client = NetAgentClient(
            uri=f"ws://127.0.0.1:{TEST_PORT + 1}",
            on_message=lambda f: _append_coro(received, f),
            channels=[CH_MONITORING, CH_AGENT],
            max_reconnect_attempts=1,
        )
        await client.connect()
        await asyncio.sleep(0.3)

        # Inject event
        await event_queue.put({
            "type": "ping_result", "source": "ping", "timestamp": time.time(),
            "results": [{"host": "1.2.3.4", "severity": "warning"}],
        })
        await asyncio.sleep(1.0)

        await client.disconnect()
        await srv.stop()

        # Verify AGENT_RESULT was received
        agent_frames = [f for f in received if f.type == MSG_AGENT_RESULT]
        assert len(agent_frames) >= 1
        assert agent_frames[0].payload["classification"] == "suspicious"


# ── Simulator tests ───────────────────────────────────────────────────────


class TestSimulator:
    @pytest.mark.asyncio
    async def test_port_flood_generates_events(self):
        from scripts.simulate_attack import scenario_port_flood
        queue: asyncio.Queue = asyncio.Queue()
        await scenario_port_flood(queue)
        events = _drain_queue(queue)
        assert len(events) == 2
        # Second event should be critical
        assert events[1]["results"][0]["severity"] == "critical"
        assert len(events[1]["results"][0]["newly_opened"]) >= 10

    @pytest.mark.asyncio
    async def test_suspicious_ip_generates_events(self):
        from scripts.simulate_attack import scenario_suspicious_ip
        queue: asyncio.Queue = asyncio.Queue()
        await scenario_suspicious_ip(queue)
        events = _drain_queue(queue)
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_brute_force_escalation(self):
        from scripts.simulate_attack import scenario_brute_force
        queue: asyncio.Queue = asyncio.Queue()
        await scenario_brute_force(queue)
        events = _drain_queue(queue)
        assert len(events) == 7
        # Later events should contain brute_force pattern
        last = events[-1]
        pattern_names = [m["pattern_name"] for m in last.get("matches", [])]
        assert "brute_force" in pattern_names

    @pytest.mark.asyncio
    async def test_gradual_probe_generates_events(self):
        from scripts.simulate_attack import scenario_gradual_probe
        queue: asyncio.Queue = asyncio.Queue()
        await scenario_gradual_probe(queue)
        events = _drain_queue(queue)
        assert len(events) == 6


# ── Storage integration ───────────────────────────────────────────────────


class TestStorageIntegration:
    @pytest.mark.asyncio
    async def test_save_and_retrieve_event(self, db_repo):
        event_data = {
            "type": "ping_result",
            "source": "ping",
            "timestamp": time.time(),
            "severity": "warning",
        }
        saved = await db_repo.save_event(event_data)
        assert saved.id is not None
        assert saved.severity == "warning"

        events = await db_repo.get_events(limit=10)
        assert len(events) == 1
        assert events[0].source == "ping"

    @pytest.mark.asyncio
    async def test_save_and_retrieve_decision(self, db_repo):
        event = await db_repo.save_event({
            "type": "test", "source": "test", "timestamp": time.time(),
        })
        decision = await db_repo.save_decision(
            event_id=event.id,
            classification="suspicious",
            analysis="Test analysis",
            action="alert",
            tool_results=[{"tool": "ping", "result": "ok"}],
        )
        assert decision.id is not None
        assert decision.classification == "suspicious"

        decisions = await db_repo.get_decisions(limit=10)
        assert len(decisions) == 1

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, db_repo):
        for sev in ["normal", "warning", "critical", "normal"]:
            await db_repo.save_event({
                "type": "test", "source": "test",
                "timestamp": time.time(), "severity": sev,
            })

        critical = await db_repo.get_events(severity="critical")
        assert len(critical) == 1
        normal = await db_repo.get_events(severity="normal")
        assert len(normal) == 2


# ── DashboardState tests ──────────────────────────────────────────────────


class TestDashboardState:
    def test_add_event(self):
        state = DashboardState()
        state.add_event({
            "type": "ping_result", "source": "ping", "timestamp": time.time(),
            "results": [{"host": "8.8.8.8", "rtt_avg": 10.0, "loss_pct": 0.0, "severity": "normal"}],
        })
        assert state.stats["total_events"] == 1
        table = state.get_event_table()
        assert len(table) == 1

    def test_add_agent_result(self):
        state = DashboardState()
        state.add_agent_result({
            "classification": "suspicious",
            "action": "alert",
            "analysis": "Test",
            "timestamp": time.time(),
        })
        assert state.stats["suspicious"] == 1
        table = state.get_agent_table()
        assert len(table) == 1

    def test_host_status_tracking(self):
        state = DashboardState()
        state.add_event({
            "type": "ping_result", "source": "ping", "timestamp": time.time(),
            "results": [
                {"host": "8.8.8.8", "rtt_avg": 10.0, "loss_pct": 0.0, "severity": "normal"},
                {"host": "1.1.1.1", "rtt_avg": 5.0, "loss_pct": 50.0, "severity": "warning"},
            ],
        })
        table = state.get_host_table()
        assert len(table) == 2
        hosts = [row[0] for row in table]
        assert "8.8.8.8" in hosts
        assert "1.1.1.1" in hosts

    def test_stats_text(self):
        state = DashboardState()
        state.connected = True
        text = state.get_stats_text()
        assert "Total Events" in text
        assert "✅" in text


# ── Multiplexer integration ───────────────────────────────────────────────


class TestMultiplexerIntegration:
    @pytest.mark.asyncio
    async def test_publish_to_subscribers_only(self, server, event_queue):
        """Verify that only monitoring channel subscribers receive events."""
        monitoring_received: list[Frame] = []
        agent_received: list[Frame] = []

        client_mon = NetAgentClient(
            uri=f"ws://127.0.0.1:{TEST_PORT}",
            on_message=lambda f: _append_coro(monitoring_received, f),
            channels=[CH_MONITORING],
            max_reconnect_attempts=1,
        )
        await client_mon.connect()
        await asyncio.sleep(0.3)

        # Send monitoring event
        await event_queue.put({"type": "test", "source": "sim", "timestamp": time.time()})
        await asyncio.sleep(0.5)

        await client_mon.disconnect()

        events = [f for f in monitoring_received if f.type == MSG_EVENT]
        assert len(events) >= 1


# ── Helpers ───────────────────────────────────────────────────────────────


async def _append_coro(lst: list, frame: Frame) -> None:
    lst.append(frame)


def _drain_queue(queue: asyncio.Queue) -> list[dict]:
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    return events
