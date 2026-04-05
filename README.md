# SocketClaw

**Real-time network monitoring & autonomous threat response agent**

SocketClaw continuously monitors your network via ICMP, TCP, and log probes — then feeds every event through a LangGraph pipeline powered by Claude to classify, investigate, and respond to threats automatically.

---

## Features

- **Multi-probe monitoring** — ICMP ping (raw socket + subprocess fallback), async TCP port scanning, and log file watching with regex pattern matching
- **Autonomous agent pipeline** — LangGraph StateGraph classifies events as `normal / suspicious / critical` and routes them through deep analysis, decision, and response nodes
- **Real-time dashboard** — Gradio UI connected over WebSocket shows live event feed, agent decisions, and per-host status
- **Custom binary protocol** — multiplexed WebSocket frames with CRC32 checksum verification over `monitoring`, `agent`, and `control` channels
- **Persistent storage** — SQLAlchemy + aiosqlite for event logs and agent decision history

---

## Architecture

```
Probes (ICMP · TCP · Log)
        │  asyncio.Queue
        ▼
 WebSocket Server  ──broadcast──▶  Clients / Dashboard
        │
        │  agent_callback
        ▼
  LangGraph Pipeline
  ┌─────────────────────────────────────┐
  │  classify_event  (Claude)           │
  │      ├─ normal   → log_pass         │
  │      ├─ suspicious → deep_analyze   │
  │      │               → decide_action│
  │      │               → execute      │
  │      └─ critical → emergency_response│
  │                    → notify         │
  └─────────────────────────────────────┘
        │
        ▼
   SQLite (events + decisions)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent pipeline | LangGraph · Claude API (claude-sonnet-4) |
| Network tools | LangChain `@tool` — ping, port_scan, whois, traceroute, block_ip |
| Transport | WebSocket (`websockets`) · asyncio |
| Probes | Raw ICMP socket · async TCP connect · log tail |
| Storage | SQLAlchemy 2.0 · aiosqlite |
| Dashboard | Gradio 5 |
| Runtime | Python 3.10 · uv |

---

## Quick Start

### 1. Install dependencies

```bash
uv sync
```

### 2. Set environment variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export NETAGENT_PROBE_TARGETS="8.8.8.8,1.1.1.1"   # comma-separated hosts
```

### 3. Run

```bash
# Start the monitoring server (probes + agent + WebSocket)
python main.py server

# Launch the real-time dashboard (separate terminal)
python main.py dashboard

# Run an attack simulation
python main.py simulate
```

Dashboard is available at `http://localhost:7860`

---

## Configuration

All settings are controlled via environment variables.

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Anthropic API key (required) |
| `NETAGENT_HOST` | `0.0.0.0` | WebSocket server bind address |
| `NETAGENT_PORT` | `8765` | WebSocket server port |
| `NETAGENT_PROBE_TARGETS` | `8.8.8.8` | Comma-separated monitoring targets |
| `NETAGENT_PING_INTERVAL` | `5` | Ping probe interval (seconds) |
| `NETAGENT_SCAN_INTERVAL` | `60` | Port scan interval (seconds) |
| `NETAGENT_LOG_PATH` | `/var/log/system.log` | Log file to watch |
| `NETAGENT_DB_PATH` | `./netagent.db` | SQLite database path |
| `NETAGENT_WINDOW_SIZE` | `50` | Sliding window event buffer size |
| `NETAGENT_MODEL` | `claude-sonnet-4-20250514` | Claude model override |
| `NETAGENT_DASHBOARD_PORT` | `7860` | Gradio dashboard port |

---

## Project Structure

```
socketclaw/
├── main.py                  # CLI entrypoint
├── src/
│   ├── protocol/            # Custom frame protocol (constants, CRC32 encoding)
│   ├── network/             # WebSocket server, client, multiplexer
│   ├── probes/              # BaseProbe, PingProbe, PortScanProbe, LogWatcherProbe
│   ├── agent/               # LangGraph graph, nodes, tools, state
│   ├── storage/             # SQLAlchemy models + async repository
│   └── ui/                  # Gradio dashboard
├── scripts/
│   ├── run_server.py        # Server entrypoint
│   ├── run_dashboard.py     # Dashboard launcher
│   └── simulate_attack.py   # Attack scenario simulator
└── tests/                   # pytest suite
```

---

## Attack Simulation

The built-in simulator injects realistic attack scenarios into the pipeline:

```bash
# Run all scenarios
python main.py simulate

# Run a specific scenario
python scripts/simulate_attack.py --scenario port_flood
python scripts/simulate_attack.py --scenario brute_force
python scripts/simulate_attack.py --scenario suspicious_ip
python scripts/simulate_attack.py --scenario gradual_probe
```

| Scenario | Description |
|---|---|
| `port_flood` | 12 ports opened simultaneously → critical |
| `suspicious_ip` | Access from known malicious IP ranges |
| `brute_force` | Escalating SSH login failures → critical |
| `gradual_probe` | Slow reconnaissance, 1–2 ports at a time |

---

## Tests

```bash
uv run pytest tests/ -v
```

---

## Agent Response Flow

| Classification | Trigger | Actions available |
|---|---|---|
| `normal` | Routine traffic | Log only |
| `suspicious` | Anomalous patterns | Deep analysis → alert / block / investigate |
| `critical` | Active threat | Immediate IP block + incident report |
