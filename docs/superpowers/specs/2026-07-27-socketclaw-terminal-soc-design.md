# SocketClaw Terminal SOC Design

**Date:** 2026-07-27
**Status:** Approved
**Product:** SocketClaw

## Purpose

SocketClaw is a local-first terminal security operations cockpit for developers,
homelab operators, and small teams that need continuous network visibility
without deploying a full SIEM. It watches configured hosts and logs, turns raw
probe output into a durable incident timeline, and uses one of three curated
OpenRouter models to explain and prioritize suspicious activity.

The product must be useful without an AI connection: probes, history, filtering,
manual diagnostics, exports, and deterministic severity scoring continue to
work offline. AI adds structured investigation and response recommendations; it
does not own the monitoring loop.

## Product Principles

1. One install and one command: `socketclaw`.
2. Terminal-native. No browser dashboard, Gradio service, or separate daemon is
   required for the default experience.
3. OpenRouter only. Anthropic, Claude-specific code, LangChain, and LangGraph
   are removed.
4. Safe by default. Network diagnostics are read-only. A firewall change is
   never performed without an explicit in-product approval unless the user has
   separately enabled an opt-in automatic-response mode.
5. Local and inspectable. Configuration, secrets, database, logs, and exports
   live under `~/.socketclaw` by default.
6. Honest failure modes. Missing binaries, permissions, API credits, malformed
   model output, and disconnected networks surface as actionable messages
   without crashing the TUI.

## Supported Environment

- Python 3.11 or newer.
- macOS and Linux are first-class.
- Windows is supported for monitoring and diagnostics where the required
  operating-system commands are available; firewall mutation is not part of
  the initial implementation.
- Terminal target: 80×24 minimum, with a richer layout at 110 columns or more.

## Runtime Architecture

The default process contains four independently testable services:

1. **Configuration service**
   - Resolves the application directory from
     `SOCKETCLAW_HOME`, defaulting to `~/.socketclaw`.
   - Stores `OPENROUTER_API_KEY` in `~/.socketclaw/.env` with mode `0600`.
   - Stores non-secret settings in `~/.socketclaw/config.toml`.
   - Validates hosts, intervals, port ranges, model presets, and response mode.

2. **Monitoring engine**
   - Runs ping, TCP port, and log watcher probes concurrently.
   - Accepts on-demand ping, port scan, traceroute, and WHOIS diagnostics.
   - Normalizes every result into a typed event.
   - Applies deterministic severity scoring immediately, before any API call.
   - Publishes events to an in-process event bus consumed by storage and UI.

3. **Investigation service**
   - Sends selected or automatically eligible events to OpenRouter.
   - Requests strict JSON output matching the incident assessment schema.
   - Retries transient failures with bounded exponential backoff.
   - Validates and repairs harmless formatting wrappers, but never invents
     missing model fields.
   - Returns a clear failure record when the provider response is unusable.

4. **Persistence service**
   - Uses SQLite with SQLAlchemy async sessions.
   - Stores normalized events, investigations, response proposals, model usage,
     and application runs.
   - Supports filtered history, aggregate statistics, incident detail, and
     Markdown/JSON export.

The TUI coordinates these services directly. The existing custom WebSocket
transport is removed from the default architecture because it adds deployment
complexity without helping the single-user local workflow.

## OpenRouter Model Presets

Only these presets appear in the product:

| Display name | OpenRouter model ID | Reasoning |
|---|---|---|
| GPT-5.6 Terra | `openai/gpt-5.6-terra` | `high` |
| Kimi K3 | `moonshotai/kimi-k3` | `max` |
| Qwen3.7 Max | `qwen/qwen3.7-max` | `high` |

GPT-5.6 Terra is the default. Requests use OpenRouter's OpenAI-compatible
`/api/v1/chat/completions` endpoint with streaming disabled for deterministic
structured incident processing. They include `reasoning.effort`, a JSON schema
response format when the selected model supports it, a bounded output token
limit, `HTTP-Referer`, and `X-Title`.

The API layer records:

- selected model and requested effort;
- prompt, completion, and reasoning token counts when returned;
- reported generation cost when returned;
- request latency and provider request identifier;
- error category without persisting the API key.

API keys are redacted in errors, logs, diagnostics, and exports.

## Event and Incident Model

Every event has:

- stable UUID;
- observed timestamp;
- source (`ping`, `port_scan`, `log`, `manual`, or `system`);
- event type;
- normalized severity (`info`, `low`, `medium`, `high`, `critical`);
- title and human-readable summary;
- optional target and structured evidence;
- deterministic score from 0 to 100;
- investigation state;
- creation timestamp.

Events at or above the configured investigation threshold can be sent to
OpenRouter. An investigation produces:

- classification;
- confidence from 0 to 1;
- concise summary;
- evidence-backed rationale;
- recommended actions;
- optional response proposal;
- model and usage metadata.

Events and investigations form the incident timeline shown in the TUI. Failed
investigations remain visible and can be retried.

## Deterministic Detection

AI is not used to decide whether monitoring output exists. Initial detection
uses explicit rules:

- complete ping loss is high severity; sustained loss escalates;
- new sensitive ports or many newly opened ports are suspicious;
- closed ports and recovery events are informational;
- log patterns cover authentication failure, privilege escalation, malware
  indicators, firewall denial bursts, and generic high-severity terms;
- repeated related events in a sliding time window increase the score;
- local/private addresses are not automatically treated as malicious.

The rule engine returns both a score and named signals so users can understand
why an event was prioritized before opening an AI analysis.

## TUI Experience

Textual provides the application shell, widgets, command palette, asynchronous
workers, keyboard handling, themes, and test pilot.

### First run

If the home `.env` has no key, SocketClaw opens onboarding:

1. Explain what SocketClaw monitors and where data is stored.
2. Accept a masked OpenRouter key.
3. Validate the key with a lightweight authenticated API request.
4. Choose one of the three model presets.
5. Add one or more targets and choose probe intervals.
6. Save and enter the dashboard.

The settings screen allows the same fields to be changed later.

### Main shell

The persistent chrome contains:

- SocketClaw wordmark and current run status;
- active model and reasoning effort;
- live/paused monitoring indicator;
- API health and current-session estimated cost;
- context-sensitive key hints.

Navigation uses tabs and direct bindings:

- `1` Overview
- `2` Events
- `3` Hosts
- `4` Investigations
- `5` Settings
- `Ctrl+P` command palette
- `Space` pause/resume
- `r` run a manual diagnostic
- `i` investigate selected event
- `e` export selected incident
- `?` help
- `q` quit with graceful cleanup

### Screens

**Overview**

- health summary and four compact metrics;
- severity distribution;
- current target status;
- recent high-priority event feed;
- probe activity log.

**Events**

- sortable/filterable data table;
- severity and source filters;
- free-text search;
- detail drawer with raw evidence and named detection signals;
- investigation and export actions.

**Hosts**

- target, reachability, latency, loss, open ports, last seen, and risk;
- add, edit, remove, ping, scan, trace, and WHOIS actions.

**Investigations**

- queued/running/completed/failed status;
- model, confidence, classification, latency, tokens, and cost;
- Markdown detail view;
- retry and response-proposal actions.

**Settings**

- masked API key update and validation;
- three fixed model choices with effort displayed;
- targets, intervals, port list, log path, investigation threshold;
- color theme and response mode;
- all changes validated before atomic save.

### Responsive behavior

At narrow widths the secondary detail pane becomes a modal and low-priority
columns disappear. No primary action depends on a mouse. Focus order, labels,
contrast, empty states, loading states, and error states are explicit.

## Response Safety

The default response mode is `approval`:

1. SocketClaw creates a response proposal.
2. The proposal identifies the exact IP, reason, command, platform, and
   reversibility.
3. The user confirms in a modal before execution.
4. SocketClaw records stdout, stderr, exit code, and rollback instructions.

`simulation` records the action without changing the system. `automatic` is an
advanced opt-in setting with an additional warning. Invalid, loopback,
multicast, broadcast, unspecified, and configured trusted addresses cannot be
blocked. The initial release implements response proposals and simulation
reliably; platform mutation adapters must be covered by explicit integration
tests before they are exposed as available.

## CLI Surface

- `socketclaw` — start the TUI.
- `socketclaw doctor` — non-secret environment and dependency diagnostics.
- `socketclaw config path` — print the effective application directory.
- `socketclaw export --format markdown|json` — export incident history.
- `socketclaw version` — print the installed version.

The package uses a standard `src/socketclaw` layout and a
`[project.scripts]` entry point. A clean `uv sync --dev` followed by
`uv run socketclaw` must work.

## Error Handling

- Configuration writes are atomic and permissions are corrected after replace.
- Database migrations are versioned and idempotent.
- Probe failures become system events and do not stop other probes.
- OpenRouter 401/402/429/5xx, timeouts, and malformed responses map to distinct
  errors with retry guidance.
- Background task exceptions are captured, shown in the activity log, and
  included in `doctor`.
- Shutdown cancels workers, flushes queued database writes, and restores the
  terminal.

## Testing and Completion Evidence

Development follows red-green-refactor. Completion requires fresh evidence for
all of the following:

1. Unit tests for configuration, secret permissions, model presets, redaction,
   scoring, validation, response parsing, retry behavior, and exports.
2. Async integration tests for probes, storage, monitoring orchestration, and
   mocked OpenRouter HTTP boundaries.
3. Textual Pilot tests for onboarding, navigation, model changes, filtering,
   event investigation, error states, pause/resume, and graceful quit.
4. SVG snapshot tests at 80×24 and a wide terminal size, plus manually inspected
   rendered captures for onboarding, overview, events, investigation detail,
   and settings.
5. A PTY smoke test of the installed `socketclaw` command.
6. One real, minimal, paid OpenRouter request for each of the three required
   presets using the provided `.env` key, recording only redacted evidence,
   response metadata, and cost.
7. Full test suite, Ruff, Pyright, package build, wheel installation in a fresh
   environment, `doctor`, and README quick-start verification.
8. A requirement-by-requirement completion audit against this document and the
   original user request.

No claim of completion is made until every item above has current evidence.

## Migration from the Prototype

The new implementation keeps useful probe and storage concepts but is free to
replace their code. It removes:

- `langchain-anthropic`, LangChain, and LangGraph;
- all Claude and `ANTHROPIC_API_KEY` behavior;
- Gradio and the browser dashboard;
- the required WebSocket server/client split;
- NetAgent product naming;
- in-memory-only response state.

The old protocol and distributed server modules may remain only if a current
feature needs them. Otherwise they and their tests are deleted so the supported
surface is coherent and maintainable.
