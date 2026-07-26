# SocketClaw

SocketClaw is a local-first terminal security operations cockpit. It watches
configured hosts and logs, explains why each observation is important, stores
the evidence in SQLite, and uses one explicitly selected OpenRouter model only
when deeper incident analysis is requested.

![SocketClaw overview](docs/screenshots/overview.svg)

## What it does

- Runs cross-platform ping checks, bounded TCP port scans, and rotation-aware
  log watchers in one resilient process.
- Scores every event locally with visible detection signals; monitoring keeps
  working without an API key or network access.
- Presents a keyboard-first Textual interface for posture, events, hosts,
  investigations, and settings.
- Persists events, model usage, costs, failures, and response proposals in a
  local SQLite database with WAL and foreign keys enabled.
- Exports redacted Markdown or JSON incident records.
- Connects only to OpenRouter for AI investigation. There is no Anthropic,
  LangChain, browser dashboard, or background WebSocket service.

## Requirements

- Python 3.11 or newer
- A terminal with color support
- The system `ping` command for reachability checks
- An OpenRouter API key for AI investigations (monitoring itself works without
  one)

## Install

From a checkout, the recommended isolated installation is:

```bash
uv tool install .
```

Or with pipx:

```bash
pipx install .
```

For development:

```bash
uv sync --dev
uv run socketclaw
```

## First run

Launch SocketClaw:

```bash
socketclaw
```

The five-step onboarding flow:

1. explains the local file boundary;
2. validates an OpenRouter key without making a paid model request;
3. selects one of the three curated model contracts;
4. configures initial targets and intervals;
5. starts the local monitor.

The API key field is masked. The key is stored as inert data in
`~/.socketclaw/.env` with mode `0600`; the file is never sourced as shell code.

## Curated OpenRouter models

| UI preset | OpenRouter model ID | Fixed reasoning effort |
|---|---|---|
| GPT-5.6 Terra | `openai/gpt-5.6-terra` | `high` |
| Kimi K3 | `moonshotai/kimi-k3` | `max` |
| Qwen3.7 Max | `qwen/qwen3.7-max` | `high` |

SocketClaw does not silently fall back to another provider or model. A failed
request becomes a durable, retryable investigation failure.

## Keyboard reference

| Key | Action |
|---|---|
| `1`–`5` | Open Overview, Events, Hosts, Investigations, or Settings |
| `Space` | Pause or resume scheduled monitoring |
| `C` / `A` | Show critical events / clear event filters |
| `I` | Investigate the selected event |
| `E` | Export the selected incident as Markdown |
| `R` | Run the context action (host ping or investigation retry) |
| `Ctrl+P` | Open the Textual command palette |
| `?` | Show keyboard help |
| `Q` | Stop monitoring and quit cleanly |

## Response safety

The default response mode is `approval`. Model output can create a response
proposal, but it cannot directly change the machine:

- a proposal records the exact action, target, reason, and reversibility;
- simulation and approval are explicit, durable state transitions;
- approval requires a confirmation modal;
- loopback, multicast, unspecified, broadcast-like, and configured watch
  targets are rejected as block targets;
- this release does **not** ship a firewall mutation adapter. “Approved” means
  reviewed and recorded, not executed on the host.

`simulation` is the safest mode. `automatic` is visible as an advanced opt-in
configuration value, but it still cannot bypass the address safety policy or
invent a platform mutation adapter.

## Local files

The default application home is `~/.socketclaw`. Override it with
`SOCKETCLAW_HOME` for testing or an alternate profile.

```text
~/.socketclaw/
├── .env                 # OpenRouter key, mode 0600
├── config.toml          # validated non-secret settings, mode 0600
├── socketclaw.db        # events, investigations, proposals, runs
└── exports/             # redacted incident Markdown and JSON
```

Configuration and export writes use a temporary file, `fsync`, and atomic
replace. SocketClaw never prints the configured key in doctor output, UI
notifications, exports, or live-test evidence.

## Commands

```bash
socketclaw                       # launch the TUI
socketclaw doctor                # launch-readiness diagnostics
socketclaw config path           # effective application home
socketclaw export --format markdown
socketclaw export --format json --output incident.json
socketclaw export --event EVENT_UUID
socketclaw version
```

`doctor` treats malformed configuration and unusable SQLite storage as launch
blockers. Missing optional system commands are warnings so the rest of the
cockpit remains usable.

## Troubleshooting

**Onboarding says the key is invalid**

Confirm that the key begins with the OpenRouter format and has access to the
selected model. `socketclaw doctor` reports only whether a key is configured;
it never prints its value.

**Ping or traceroute is unavailable**

Run `socketclaw doctor`. Install the operating system networking tools, or use
the port and log views meanwhile. Probe failures become system events instead
of stopping other jobs.

**The config file will not load**

Run `socketclaw config path`, inspect `config.toml`, and correct the first
validation error shown by `socketclaw doctor`. SocketClaw will not overwrite a
malformed file automatically.

**OpenRouter returns 401, 402, 429, or a provider error**

The investigation detail preserves a redacted, classified failure. Correct the
key or credit/rate-limit condition and use Retry. Local monitoring and history
remain available.

**The terminal is small**

SocketClaw supports an 80×24 compact layout. A wider terminal exposes more
detail columns and the secondary incident pane.

## Development and verification

```bash
uv sync --dev
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv build
```

Paid live OpenRouter tests are opt-in and require an explicit env-file path.
The file is parsed as data; it is not sourced:

```bash
SOCKETCLAW_LIVE_OPENROUTER=1 \
SOCKETCLAW_LIVE_ENV_FILE=/absolute/path/to/.env \
uv run pytest tests/live/test_openrouter_models.py -q
```

Live evidence is redacted and written below `artifacts/live-openrouter/`.
