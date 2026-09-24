<h1 align="center">SOCKETCLAW</h1>

<p align="center">
  <strong>Watch the signal. Keep the evidence.</strong>
</p>

<p align="center">
  <em>A local-first security cockpit for hosts, ports, and logs.</em>
</p>

<p align="center">
  <a href="https://github.com/jbaehova/socketclaw/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/jbaehova/socketclaw?style=flat-square&color=805928"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white">
  <img alt="Local-first" src="https://img.shields.io/badge/Local-first-805928?style=flat-square">
  <img alt="Terminal UI" src="https://img.shields.io/badge/Terminal-UI-334155?style=flat-square">
</p>

<p align="center">
  <img src="assets/socketclaw-banner.webp" alt="Pixel-art security desk gathering host and log signals into a protective claw" width="88%">
</p>

SocketClaw watches configured hosts, TCP ports, and log files from one terminal.
It scores observations locally, keeps the evidence in SQLite, and opens an
optional GPT-5.6 Luna investigation when you ask for deeper analysis.

```text
hosts + logs  ->  local detection  ->  SQLite evidence  ->  optional AI investigation  ->  review + export
```

## What It Does

- Runs cross-platform ping checks, bounded TCP port scans, and rotation-aware
  log watchers in one resilient process.
- Scores every event locally with visible detection signals; monitoring keeps
  working without an API key or OpenAI connectivity.
- Runs an inline terminal workspace with a plain activity feed and `/` commands.
  Forms adapt to narrow windows, and colors follow your terminal or a light/dark theme.
- Persists events and model operations in a local SQLite database. This includes
  estimated costs, failures, and response proposals.
- Exports redacted Markdown or JSON incident records.
- Connects only to `https://api.openai.com/v1` for AI investigation. No
  alternate model-provider route or fallback exists.

## Quick Start

On macOS, install the standalone release and launch the cockpit:

```bash
curl -fsSL https://raw.githubusercontent.com/jbaehova/SocketClaw/main/scripts/install.sh | sh
socketclaw
```

The first run guides you through targets and intervals. You can continue
offline and add an OpenAI key later if you want AI investigations. For Python
source installs and installer options, see the [installation details](docs/reference.md#install).

## In Action

Light-theme captures with sample local data.

![SocketClaw overview](src/artifacts/tui/overview-120x36.svg)

![Observation timeline](src/artifacts/tui/events-120x36.svg)

![Observation detail with detection evidence](src/artifacts/tui/events-detail-120x36.svg)

![AI investigation detail](src/artifacts/tui/investigations-detail-120x36.svg)

![Incident detail](src/artifacts/tui/incidents-detail-120x36.svg)

![Host targets](src/artifacts/tui/hosts-120x36.svg)

![Watched log sources](src/artifacts/tui/logs-120x36.svg)

![Collection health](src/artifacts/tui/health-120x36.svg)

![Detection rule settings](src/artifacts/tui/rules-120x36.svg)

## Install from source

With Python 3.11 or newer, install from a checkout:

```bash
uv tool install ./src
```

You can also use `pipx install ./src`. The macOS standalone release includes
Python. See the [installation details](docs/reference.md#install) for installer
options and development setup.

## Everyday use

Type `/` to browse commands. The interface works in an 80×24 terminal and lets
you switch themes with `Ctrl+T`.

| Command | Action |
|---|---|
| `socketclaw doctor` | Check setup and local storage. |
| `socketclaw db status` | Inspect database status without changing it. |
| `socketclaw export --format markdown` | Export a redacted incident record. |
| `socketclaw version` | Show the installed version. |

Monitoring works offline. AI investigations require an OpenAI key, and response
proposals stay in an explicit review flow without changing the host firewall.

## Documentation

- [Full reference](docs/reference.md): installation, keyboard controls, detection
  rules, incident handling, storage recovery, and troubleshooting.
- [Development and verification](docs/reference.md#development-and-verification)
- [Changelog](src/CHANGELOG.md)
