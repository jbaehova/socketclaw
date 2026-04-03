"""Gradio real-time dashboard.

Connects to the server via WebSocket client and displays events/agent results in real time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from datetime import datetime
from typing import Any

import gradio as gr

from ..network.client import NetAgentClient
from ..protocol.constants import (
    CH_AGENT,
    CH_CONTROL,
    CH_MONITORING,
    MSG_AGENT_RESULT,
    MSG_CONTROL,
    MSG_EVENT,
)
from ..protocol.frame import Frame

logger = logging.getLogger(__name__)

# ── Dashboard state ───────────────────────────────────────────────────────

MAX_LOG_ENTRIES = 200


class DashboardState:
    """Manages dashboard display state."""

    def __init__(self) -> None:
        self.event_log: deque[dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)
        self.agent_log: deque[dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)
        self.host_status: dict[str, dict[str, Any]] = {}
        self.stats = {"total_events": 0, "normal": 0, "suspicious": 0, "critical": 0}
        self.connected = False

    def add_event(self, event: dict[str, Any]) -> None:
        ts = datetime.fromtimestamp(event.get("timestamp", time.time())).strftime("%H:%M:%S")
        entry = {
            "time": ts,
            "source": event.get("source", "?"),
            "type": event.get("type", "?"),
            "severity": self._extract_severity(event),
            "summary": self._summarize_event(event),
        }
        self.event_log.appendleft(entry)
        self.stats["total_events"] += 1
        self._update_host_status(event)

    def add_agent_result(self, result: dict[str, Any]) -> None:
        ts = datetime.fromtimestamp(result.get("timestamp", time.time())).strftime("%H:%M:%S")
        classification = result.get("classification", "normal")
        entry = {
            "time": ts,
            "classification": classification,
            "action": result.get("action", "log"),
            "analysis": result.get("analysis", "")[:300],
        }
        self.agent_log.appendleft(entry)
        if classification in self.stats:
            self.stats[classification] += 1

    def get_event_table(self) -> list[list[str]]:
        severity_icons = {"normal": "🟢", "warning": "🟡", "critical": "🔴"}
        rows = []
        for e in list(self.event_log)[:50]:
            icon = severity_icons.get(e["severity"], "⚪")
            rows.append([e["time"], e["source"], e["type"], f"{icon} {e['severity']}", e["summary"]])
        return rows

    def get_agent_table(self) -> list[list[str]]:
        class_icons = {"normal": "🟢", "suspicious": "🟡", "critical": "🔴"}
        rows = []
        for a in list(self.agent_log)[:50]:
            icon = class_icons.get(a["classification"], "⚪")
            rows.append([a["time"], f"{icon} {a['classification']}", a["action"], a["analysis"][:150]])
        return rows

    def get_host_table(self) -> list[list[str]]:
        severity_icons = {"normal": "🟢", "warning": "🟡", "critical": "🔴"}
        rows = []
        for host, info in self.host_status.items():
            sev = info.get("severity", "normal")
            icon = severity_icons.get(sev, "⚪")
            rows.append([
                host,
                f"{icon} {sev}",
                str(info.get("last_rtt", "-")),
                str(info.get("loss_pct", "-")),
                info.get("last_seen", "-"),
            ])
        return rows

    def get_stats_text(self) -> str:
        s = self.stats
        return (
            f"Total Events: {s['total_events']}  |  "
            f"🟢 Normal: {s['normal']}  |  "
            f"🟡 Suspicious: {s['suspicious']}  |  "
            f"🔴 Critical: {s['critical']}  |  "
            f"Connected: {'✅' if self.connected else '❌'}"
        )

    def _update_host_status(self, event: dict[str, Any]) -> None:
        for r in event.get("results", []):
            if not isinstance(r, dict) or "host" not in r:
                continue
            host = r["host"]
            self.host_status[host] = {
                "severity": r.get("severity", "normal"),
                "last_rtt": r.get("rtt_avg", "-"),
                "loss_pct": r.get("loss_pct", "-"),
                "last_seen": datetime.now().strftime("%H:%M:%S"),
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

    @staticmethod
    def _summarize_event(event: dict[str, Any]) -> str:
        etype = event.get("type", "")
        results = event.get("results", [])
        if etype == "ping_result" and results:
            hosts = [f"{r.get('host', '?')}({r.get('rtt_avg', '?')}ms)" for r in results if isinstance(r, dict)]
            return f"Ping: {', '.join(hosts)}"
        if etype == "port_scan_result" and results:
            parts = []
            for r in results:
                if not isinstance(r, dict):
                    continue
                opened = r.get("newly_opened", [])
                if opened:
                    parts.append(f"{r.get('host', '?')}: new ports {opened}")
                else:
                    parts.append(f"{r.get('host', '?')}: {len(r.get('open_ports', []))} open")
            return f"Scan: {', '.join(parts)}"
        if etype == "log_match":
            matches = event.get("matches", [])
            return f"Log: {len(matches)} pattern(s) matched"
        return json.dumps(event, ensure_ascii=False, default=str)[:150]


# ── Dashboard build ───────────────────────────────────────────────────────

_state = DashboardState()
_client: NetAgentClient | None = None


async def _on_message(frame: Frame) -> None:
    """WebSocket message receive callback."""
    if frame.type == MSG_EVENT:
        _state.add_event(frame.payload)
    elif frame.type == MSG_AGENT_RESULT:
        _state.add_agent_result(frame.payload)


async def _connect(uri: str) -> str:
    """Connect to the server."""
    global _client
    if _client and _client.is_connected:
        return "Already connected"

    _client = NetAgentClient(
        uri=uri,
        on_message=_on_message,
        channels=[CH_MONITORING, CH_AGENT],
        max_reconnect_attempts=5,
    )
    await _client.connect()
    _state.connected = True
    return f"✅ Connected to {uri}"


async def _disconnect() -> str:
    """Disconnect from the server."""
    global _client
    if _client:
        await _client.disconnect()
        _client = None
    _state.connected = False
    return "❌ Disconnected"


def _refresh() -> tuple:
    """Refresh UI data."""
    return (
        _state.get_stats_text(),
        _state.get_event_table(),
        _state.get_agent_table(),
        _state.get_host_table(),
    )


async def _trigger_scan(host: str) -> str:
    """Trigger a manual scan."""
    if not _client or not _client.is_connected:
        return "Not connected to server"
    await _client.send_control("scan", host=host)
    return f"Scan request sent: {host}"


def build_dashboard() -> gr.Blocks:
    """Build the Gradio dashboard UI."""
    with gr.Blocks(
        title="NetAgent Dashboard",
        theme=gr.themes.Soft(),
    ) as demo:
        gr.Markdown("# 🛡️ NetAgent — Real-time Network Monitoring Dashboard")

        # ── Connection controls ───────────────────────────────────────────
        with gr.Row():
            uri_input = gr.Textbox(
                value="ws://localhost:8765",
                label="Server URI",
                scale=3,
            )
            connect_btn = gr.Button("🔌 Connect", variant="primary", scale=1)
            disconnect_btn = gr.Button("🔌 Disconnect", variant="stop", scale=1)
            conn_status = gr.Textbox(label="Status", interactive=False, scale=2)

        connect_btn.click(_connect, inputs=[uri_input], outputs=[conn_status])
        disconnect_btn.click(_disconnect, outputs=[conn_status])

        # ── Stats bar ─────────────────────────────────────────────────────
        stats_bar = gr.Textbox(label="Statistics", interactive=False)

        # ── Tabs ──────────────────────────────────────────────────────────
        with gr.Tabs():
            # Event feed
            with gr.Tab("📡 Event Feed"):
                event_table = gr.Dataframe(
                    headers=["Time", "Source", "Type", "Severity", "Summary"],
                    label="Live Events",
                    interactive=False,
                    wrap=True,
                )

            # Agent decisions
            with gr.Tab("🤖 Agent Decisions"):
                agent_table = gr.Dataframe(
                    headers=["Time", "Classification", "Action", "Analysis"],
                    label="Agent Decision Log",
                    interactive=False,
                    wrap=True,
                )

            # Host status
            with gr.Tab("🖥️ Host Status"):
                host_table = gr.Dataframe(
                    headers=["Host", "Status", "RTT (ms)", "Loss (%)", "Last Seen"],
                    label="Per-host Status Summary",
                    interactive=False,
                )

            # Manual controls
            with gr.Tab("⚙️ Controls"):
                with gr.Row():
                    scan_host_input = gr.Textbox(
                        value="8.8.8.8",
                        label="Scan Target Host",
                        scale=3,
                    )
                    scan_btn = gr.Button("🔍 Trigger Scan", variant="primary", scale=1)
                    scan_result = gr.Textbox(label="Result", interactive=False, scale=2)
                scan_btn.click(_trigger_scan, inputs=[scan_host_input], outputs=[scan_result])

        # ── Auto-refresh ──────────────────────────────────────────────────
        refresh_btn = gr.Button("🔄 Refresh")
        refresh_btn.click(
            _refresh,
            outputs=[stats_bar, event_table, agent_table, host_table],
        )

        # Timer-based auto-refresh (every 2 seconds)
        timer = gr.Timer(2)
        timer.tick(
            _refresh,
            outputs=[stats_bar, event_table, agent_table, host_table],
        )

    return demo
