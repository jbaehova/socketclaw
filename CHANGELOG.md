# Changelog

All notable SocketClaw changes are documented here.

## Unreleased

- Hardened distribution metadata and limited source archives to release inputs.
- Made the package version use one authoritative source.
- Made TUI capture generation complete, deterministic, and secret checked.
- Removed inert investigation-threshold and response-mode preferences in favor
  of explicit, per-event investigation and per-proposal response review.
- Added persistent offline onboarding so local monitoring can run without an
  OpenAI key and investigations can be enabled later from Settings.
- Hardened the OpenAI-only boundary with strict response parsing, secret-safe
  payloads, traceable failures, and no automatic retry of generation requests.
- Made event, investigation, response-review, and run lifecycles durable and
  concurrency-safe, including cancellation and interrupted-start recovery.
- Preserved probe baselines across live configuration changes while bounding
  concurrency, file reads, subprocess cleanup, and failure isolation.
- Reworked the Textual cockpit for deterministic keyboard operation and usable
  80x24 layouts across all five workspaces and first-run onboarding.
- Hardened managed files, database integrity checks, single-instance locking,
  incident exports, terminal rendering, and response-approval validation.
- Updated locked `idna` from 3.11 to 3.19 to address PYSEC-2026-215.

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
