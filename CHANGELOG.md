# Changelog

All notable SocketClaw changes are documented here.

## 0.2.0 — 2026-07-27

- Rebuilt SocketClaw as a single-process, local-first Textual SOC cockpit.
- Added secure atomic configuration and private OpenRouter credential storage.
- Added the GPT-5.6 Terra, Kimi K3, and Qwen3.7 Max curated OpenRouter presets.
- Added explainable local detection, resilient ping/port/log monitoring, and
  durable SQLite event history.
- Added structured OpenRouter investigations with retries, redaction, token
  usage, request metadata, and cost accounting.
- Added Events, Hosts, Investigations, Settings, onboarding, help, filtering,
  manual diagnostics, incident exports, and response proposal review.
- Added `doctor`, `config path`, `export`, and `version` CLI commands.
- Removed the supported-product dependency on Claude, LangChain, LangGraph,
  Gradio, and a required WebSocket server/client split.
