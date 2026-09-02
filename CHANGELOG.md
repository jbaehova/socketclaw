# Changelog

All notable SocketClaw changes are documented here.

## 0.3.0 - 2026-09-03

- Pinned all model work to GPT-5.6 Luna on the OpenAI Platform.
- Migrated investigations to the OpenAI Responses API with strict structured
  outputs and severity-aware reasoning effort.
- Removed alternate model choices, provider routing, and stale provider
  artifacts.
- Changed local secret storage to `OPENAI_API_KEY` and added Luna access
  validation through the Models API.

## 0.2.0 - 2026-07-27

- Rebuilt SocketClaw as a single-process, local-first Textual SOC cockpit.
- Added secure atomic configuration and private provider credential storage.
- Added the original curated model presets.
- Added explainable local detection, resilient ping/port/log monitoring, and
  durable SQLite event history.
- Added structured model investigations with retries, redaction, token
  usage, request metadata, and cost accounting.
- Added Events, Hosts, Investigations, Settings, onboarding, help, filtering,
  manual diagnostics, incident exports, and response proposal review.
- Added `doctor`, `config path`, `export`, and `version` CLI commands.
- Removed legacy orchestration dependencies and a required WebSocket
  server/client split.
