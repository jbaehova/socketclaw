# Changelog

All notable SocketClaw changes are documented here.

## Unreleased

## 0.5.0 - 2026-09-17

- Replace the framed dashboard with an inline terminal workspace, a plain
  activity feed, and a shared command prompt. Preserve shell scrollback.
- Add searchable slash commands, keyboard completion, and Ctrl+K access from forms.
- Follow terminal colors by default, with saved light/dark choices and Ctrl+T.
- Reflow forms and actions on resize. Keep focused fields visible and reserve
  space for the prompt instead of drawing menus over inputs.
- Unpack the standalone runtime during installation instead of every launch.
  Load the full command stack only when needed.

## 0.4.0 - 2026-09-17

- Publish standalone macOS executables for Apple Silicon and Intel through
  GitHub Releases, with a checksum-verifying installer.
- Add an Incident desk with state filters, a wide-screen context pane, and a
  compact full-screen reader. Record acknowledgement, resolution, reopening,
  and notes with reasons through the same interface.
- Add schema v4 incident lifetimes, occurrences, recovery evidence, and audit
  history in the observation transaction. Preserve raw scores and historical
  rule provenance through backed-up upgrades from versions 1 through 3.
- Add maintenance exception management with explicit scope, reason, expiry,
  and early ending. Show applied decisions in observation details and exports.
- Open exact related observations from incidents with snapshot-stable paging.
  Export full incident activity and evidence through the reader or CLI
  `export --incident UUID`, in Markdown or JSON.

- Add schema v3 with backed-up v1/v2 migration and immutable rule snapshots.
  Preserve historical unknown rule provenance without rescoring observations.
- Correlate only deduplicated observations within the same rule version using
  fixed batch collection timestamps, exact boundaries, and durable history.
- Add a numeric detection rule editor to Settings and the command palette, with
  explicit units, validated thresholds, configurable points, and draft protection.

- Parse explicit authentication and firewall source fields, preserving source
  timestamps only when their timezone is known. Unknown formats retain keyword
  detection without assigning their first IP as the actor.
- Add Hosts Targets/Logs tabs with source management, committed progress, and
  bounded test reads that never advance checkpoints or save preview events.
- Add durable per-probe health and transition history, exposed through H and
  the command palette. Missing logs and typed collection failures stay degraded.
- Schedule from a monotonic start grid with bounded startup spread and global
  concurrency. Count skipped ticks and serialize manual diagnostics with scheduled
  work through final state persistence.
- Preserve the original collection time during storage retries. Suppress repeated
  identical error events, and flush retained measurements before removing jobs.
- Upgrade schema v1 with a verified private SQLite recovery snapshot and an
  atomic migration. Add read-only `db status` and locked `db migrate` commands.
- Persist ingestion sequence and observation provenance without inventing
  historical measurement quality or ingestion timestamps.
- Commit log checkpoints, source deduplication, and observations together.
  Resume after restart, drain verified rotated siblings, and record unavailable
  source gaps. Inspect committed progress and backlog with L.
- Persist per-port confirmations and apply a configurable comparison lifetime.
  Retain failed network batches until storage succeeds, and serialize scheduled
  scans with manual diagnostics for the same target.
- Distinguish measured ICMP loss from command failures and unknown results.
  Preserve the exit code and classification reason without inventing loss or RTT.
- Compare TCP changes only within the common watch scope. Keep unresolved
  results separate from currently open ports and report initial sensitive exposure.
- Query committed correlation history independently of the latest 500 events.
- Open full-screen event and investigation details with Enter and restore list
  position with Esc, including compact terminals.
- Query high-severity observations directly for Overview and open their exact IDs.
- Hold older Events selections during collection, show pending observation counts,
  and provide Live to catch up. Coalesce active-view refreshes at 250 ms.
- Preserve settings drafts across other workspace changes and compare conflicting
  values before applying overlapping edits.

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
