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
source installs and installer options, see [Install](#install).

## In Action

Light-theme captures with sample local data.

![SocketClaw overview](src/artifacts/tui/overview-120x36.svg)

![Observation timeline](src/artifacts/tui/events-120x36.svg)

![AI investigation detail](src/artifacts/tui/investigations-detail-120x36.svg)

![Incident detail](src/artifacts/tui/incidents-detail-120x36.svg)

## Requirements

- Python 3.11 or newer for source installs and development. The macOS
  standalone executable includes its own Python runtime.
- A terminal with color support
- The optional system `ping` command for reachability checks. Other probes keep
  working when it is unavailable.
- An optional OpenAI API key for AI investigations. Monitoring works without
  one.

## Install

### macOS standalone executable

Install the latest [GitHub Release](https://github.com/jbaehova/SocketClaw/releases)
without Python or uv:

```bash
curl -fsSL https://raw.githubusercontent.com/jbaehova/SocketClaw/main/scripts/install.sh | sh
socketclaw
```

The installer selects Apple Silicon or Intel, verifies the release archive's
SHA-256 checksum, and installs `socketclaw` to `~/.local/bin`. If that directory
is not on your `PATH`, add it to your shell profile or run
`~/.local/bin/socketclaw` directly. Set `SOCKETCLAW_INSTALL_DIR` to select a
different destination. Release binaries are ad-hoc signed, not Apple notarized.
The runtime is unpacked once into `~/.local/share/socketclaw/releases`; subsequent
launches do not extract it again. Set `SOCKETCLAW_DATA_DIR` to move this directory.
Run the installer again to update. Existing bundles remain available to running
processes until you remove them after quitting those sessions.

### Install from source

From a checkout, use an isolated Python environment:

```bash
uv tool install ./src
```

Or with pipx:

```bash
pipx install ./src
```

For development:

```bash
cd src
uv sync --dev
uv run socketclaw
```

## First run

Launch SocketClaw:

```bash
socketclaw
```

The four-step onboarding flow:

1. explains the local file boundary;
2. optionally validates an OpenAI key and Luna access without generating
   tokens, or continues offline;
3. selects a local-service, server or file-log profile using discovered readable candidates;
4. checks the selected sources and starts the local monitor.

The API key field is masked. When supplied, the key is stored as inert data in
`~/.socketclaw/.env`; the file is never sourced as shell code. On POSIX
systems, SocketClaw enforces mode `0700` on its home and `0600` on managed
configuration, credential, database, and export files. SQLite WAL/SHM sidecars
remain protected by the non-traversable `0700` home directory. On Windows, the
directory inherits the account ACL of the user profile.
Offline onboarding persists normally. AI investigations remain unavailable
until a validated key is added from Settings.

## OpenAI model policy

| Model | OpenAI model ID | Reasoning effort |
|---|---|---|
| GPT-5.6 Luna | `gpt-5.6-luna` | `medium` for medium and lower events, `high` for high and critical events |

The model cannot be changed in configuration or the UI. Requests use the
OpenAI Responses API with structured outputs. A failed request becomes a
durable, retryable investigation failure instead of falling back.

## Keyboard reference

Type `/` to browse commands. Use `Ctrl+K` to reach the command prompt while editing
a field. Arrow keys select a command, `Tab` completes it, and `Enter` runs it.
`Esc` returns from a workspace to your watch without discarding form drafts.

The default `terminal` appearance uses your terminal's colors. Use `/theme light`,
`/theme dark`, or `/theme terminal` to choose and save an appearance. Existing
installations keep their saved theme until you change it.

| Key | Action |
|---|---|
| `/` or `Ctrl+K` | Open commands |
| `Ctrl+T` | Toggle light and dark |
| `1`–`5` | Open Overview, Events, Hosts, Investigations, or Settings |
| `Space` | Pause or resume scheduled monitoring |
| `C` / `A` | Show critical events / clear event filters |
| `Enter` / `Esc` | Open selected event or investigation detail / return to the list |
| `L` | Open Hosts / Logs to manage sources and inspect collection progress |
| `H` | Inspect collection health, stale probes, and scheduling delays |
| `I` | Investigate the selected event |
| `E` | Export the selected observation as Markdown |
| `R` | Run the context action (host ping, log test read, or investigation retry) |
| `Ctrl+P` | Open the Textual command palette |
| `?` | Show keyboard help |
| `Q` or `Ctrl+C` | Stop monitoring and quit cleanly |

## Response safety

Model output can create a response proposal, but it cannot directly change the
machine:

- a proposal records the exact action, target, reason, and reversibility;
- approval and rejection are explicit, durable state transitions;
- approval requires a confirmation modal;
- unsafe address classes such as loopback and multicast are rejected as block
  targets;
- configured IP watch targets are also rejected;
- this release does **not** ship a firewall mutation adapter. “Approved” means
  reviewed and recorded, not executed on the host.

Every proposal stays in the explicit review workflow. Operators choose whether
to open a review-to-end confirmation step for approval or rejection.

## Local files

The default application home is `~/.socketclaw`. Override it with
`SOCKETCLAW_HOME` for testing or an alternate profile.

```text
~/.socketclaw/
├── .env                 # optional OpenAI key, private file
├── .instance.lock       # private single-process ownership lock
├── config.toml          # validated non-secret settings, private file
├── socketclaw.db        # events, investigations, proposals, runs
├── backups/             # verified private snapshots before schema migration
└── exports/             # redacted incident Markdown and JSON
```

Only one SocketClaw TUI may own an application home at a time. A second launch
is rejected before it can recover or modify work owned by the running process.

Configuration and export writes use a temporary file, `fsync`, and atomic
replace. SocketClaw never prints the configured key in doctor output, UI
notifications, exports, or live-test evidence.

Automatic exports use POSIX directory handles so a replaced export directory
cannot redirect incident data. On platforms without those handles, automatic
exports fail closed; use `socketclaw export --output PATH` with a path you
selected explicitly.

## Commands

```bash
socketclaw                       # launch the TUI
socketclaw doctor                # launch-readiness diagnostics
socketclaw config path           # effective application home
socketclaw db status             # read-only schema and integrity check
socketclaw db migrate            # back up and upgrade storage under the writer lock
socketclaw export --format markdown
socketclaw export --format json --output incident.json
socketclaw export --event EVENT_UUID
socketclaw version
```

`doctor` treats malformed configuration and unusable SQLite storage as launch
blockers. Missing optional system commands are warnings so the rest of the
cockpit remains usable.

### Detection rules

Open **Settings > Detection rules**, or choose **Detection rules** in the command
palette. The balanced preset has editable numeric thresholds and score
contributions. The editor labels seconds, percentages, and counts explicitly.
Counts include the current observation. Each signal contributes 0-100 points;
the combined score is capped at 100. Loss thresholds must satisfy degraded < high
< 100 percent. No scripts or custom regular expressions run from rule settings.

Rules are stored in `[rules]` and `[rules.points]` in `config.toml`. The default
correlation window is 300 seconds. Authentication bursts require six failures,
sustained high loss requires four observations, and firewall bursts require ten
denials. A burst of new ports requires five newly opened ports in one scan.

Logs with a parsed explicit timezone use source time for their correlation window.
Delayed source records are labeled separately; future clocks
fall back to collection time. Missing or ambiguous clocks also use collection
time. A burst always fits within the configured window, including reverse arrival.
Only deduplicated observations from the same rule version, asset, account and
actor contribute. Window endpoints are inclusive. Suppressions use the same
effective event clock. `collected_at`, `committed_at`, `correlation_at` and
`time_basis` make the policy explicit. Historical `ingested_at` is unchanged.

The first observation using a changed policy records an immutable rule version
with its settings, engine/parser versions, and SHA-256 fingerprint. Subsequent
observations reference it; restart resumes its durable window. Changing the
policy starts a separate window, including when reverting to an earlier policy.
Past observations keep their original score and version. Historical records
without rule provenance remain unknown. Exported event metadata includes the
rule version, and Markdown reports show it explicitly.

### Incident desk

Choose **Incidents** in Events or **Incident desk** from the command palette.
Needs attention shows open and acknowledged incidents. Resolved and All provide
access to closed history. The list shows severity, source, and observation counts;
a wide terminal also shows the selected incident beside the list.

Press Enter to read its activity, occurrences, and notes. Acknowledge, Resolve,
and Reopen record a reason. Notes remain in the history. Measured recovery is
recorded separately from operator resolution, and a recurrence can open a new
occurrence while retaining earlier notes. Press Esc to return to the list.

Open **Observations** from an incident to inspect its exact linked evidence and
return with Esc. **Export .md** includes the current state, activity, occurrences and notes. It also
includes related observations, AI investigations, response reviews, operator action
records, suppression decisions and immutable rule snapshots. Reports explicitly
state collection limits; larger histories remain accessible through pagination. The CLI also accepts
`socketclaw export --incident UUID --format json`.

**Exceptions** opens maintenance rules. Create an exception with a scope,
reason, and duration of up to 30 days, or end it early with a reason. Filled
scope fields must all match. Original observations and scores remain available;
applicable decisions appear in observation details and exports.

Use R or Refresh to load new state. Previous and Next traverse 100 incidents at
a time; search applies to the complete stored history. Events and investigations
also provide cursor pagination. Existing observations retain
their original scores. Incident history starts with observations ingested after
the upgrade; historical observations are not retroactively grouped.

### Storage upgrades and collector recovery

Launching the TUI or running `db migrate` upgrades a version 1 through 4 database to
version 5. Before changing its schema, SocketClaw creates a verified SQLite
snapshot, including committed WAL data, in `backups/`. Its JSON manifest records
the schema version and SHA-256 digest. These private backups include local
evidence but do not include the API key file. A failed migration rolls back and
reports the recovery snapshot location. Keep that snapshot until you have
verified the upgraded data. `doctor`, `db status`, and `export` never migrate
storage; they report when an explicit upgrade is needed.

Historical observation timestamps remain unchanged. Unknown historical
collection quality and missing ingestion timestamps remain unknown. A
reconstructed ordering is marked separately from the actual ingestion sequence
assigned to new observations.

The first attachment to an existing log starts at its current end. Subsequent
runs resume the last committed byte position. Matching observations and the
new position commit together, including polls with no pattern matches. Failed
writes retry the candidate batch without advancing the cursor. Renamed sibling
files such as `auth.log.1` are drained when their file identity and fingerprints
match. The sibling search examines at most 256 directory entries. Deleted,
overwritten, or otherwise unavailable generations leave a recovery gap; the
number of lost bytes may be unknown. Press `L` to inspect committed progress.

Hosts has Targets, Logs and Services tabs. The Logs tab adds or removes watched paths and
shows each source's read state and backlog. Enter opens its full progress and
error detail. Removing a source keeps its stored observations and checkpoint;
adding it again resumes that checkpoint. Test read, also available with `R`,
reads at most 64 KiB from the file tail and shows at most 20 matching complete
lines. It does not save observations or advance the collector. Links, devices,
and directories are not accepted as preview files.

The log parser recognizes OpenSSH authentication failures and successes, session
records, sudo executions and PAM authentication failures. Process names and PIDs
are separate fields. Successful sudo execution is contextual evidence, not a
confirmed privilege attack. ClamAV `FOUND` results are structured detections;
generic malware words are low-confidence clues, and clean scans stay informational.
The collector retains bounded adjacent source lines for investigation. It also reads explicit `SRC` and `DST` fields in Linux
firewall denial messages, including UFW BLOCK. The simple
`authentication failure from ADDRESS` fixture format is supported. Source and
destination addresses are validated separately; invalid or duplicate source
fields remain unknown. Other formats retain keyword detection with no inferred
source IP. The first IP mentioned in an arbitrary message is not treated as its
actor.

An ISO timestamp with an explicit UTC offset or `Z` becomes `source_at`.
Yearless syslog timestamps and timestamps without a timezone remain unknown;
SocketClaw does not invent their year or timezone. Evidence records the parser
version and parsing quality. Collection and ingestion timestamps remain separate
from the source's reported time, and existing observations are not rewritten.

Port baselines also commit with their observations and survive restarts.
Only confirmed ports in the common watch scope count as changes. Set
`port_baseline_ttl` in `config.toml` to the comparison lifetime in seconds
(default `86400`, allowed range `1` to `2592000`). Expired values remain reference
evidence and do not produce a new-open or new-close claim. Unknown scans do not
refresh a port's last confirmation time.

Network results are retained in memory for storage retries, with one pending
batch per scheduled job. A job waits for that batch to commit before collecting
again. A forced process exit can still lose uncommitted network measurements;
these cannot be replayed like file logs.

### Collection health and scheduling

Press `H`, or choose Health from the command palette, to inspect each scheduled
probe. Enter opens its last attempt, last successful collection, and last
observation. The detail also shows its next scheduled start, delay, and skipped
ticks. Health describes measurement quality: a measured 100% ping loss is a
successful collection of an unreachable result. Missing logs, unreadable files,
and unclassified probe results remain degraded even when no exception escapes
the collector.

Probe health and meaningful state transitions are saved locally. Repeated
identical exceptions increase the error count without creating an event on
every poll. Stale means no successful collection within three configured
intervals, with a minimum grace of ten seconds. Replaying an old pending batch
does not make its measurement time fresh. An interrupted attempt is identified
on restart; inspect committed observations before inferring what was lost.

Intervals are targets between execution starts, measured with a monotonic
clock. Startup uses a stable spread of up to 10% of the interval, capped at
100 ms. At most eight collection operations run at once by default. An
overrunning operation skips elapsed ticks rather than overlapping itself.
Scheduled and manual work share the same lock for a target and probe.
Pausing prevents new scheduled starts while in-flight work finishes. Manual
diagnostics remain available while paused. Transient storage failures keep a pending
measurement for atomic retry. Deterministically invalid batches are privately
quarantined with their original checkpoints, so the job can be edited or removed.
Use `socketclaw quarantine` to inspect retained candidates.

Health also reports pending batches and dropped UI notifications. A dropped
notification does not delete its stored observation. Mounted views poll persisted
state as well as processing live notifications, preserving selections during reload.

## Troubleshooting

**Onboarding says the key is invalid**

Confirm that the key is an OpenAI Platform key and has access to
`gpt-5.6-luna`. `socketclaw doctor` reports only whether a key is configured;
it never prints its value. You can continue onboarding offline and add a key
later from Settings.

**Ping is unavailable**

Run `socketclaw doctor`. Install the operating system `ping` command, or use the
TCP port scans and log monitoring meanwhile. Probe failures become system
events instead of stopping other jobs.

**The config file will not load**

Run `socketclaw config path`, inspect `config.toml`, and correct the first
validation error shown by `socketclaw doctor`. SocketClaw will not overwrite a
malformed file automatically.

**OpenAI returns 401, 402, 429, or an API error**

The investigation detail preserves a redacted, classified failure. Correct the
key or credit/rate-limit condition and use Retry. Local monitoring and history
remain available.

**The terminal is small**

SocketClaw supports an 80×24 compact layout. A wider terminal exposes more
detail columns and the secondary incident pane. Press Enter on an event or
investigation to open its full detail at any size, then Esc to return to the
same list position. Overview also opens its selected observation with Enter.

When you select an older event or open its detail, the Events list holds its
position while collection continues. The new-observation count shows pending
updates. Choose Live to refresh the list from storage.

Settings preserve unsaved fields when another workspace changes configuration.
If both edits touch the same field, Save shows the loaded, saved, and draft
values. Choose which version to keep before applying the overlapping change.

## Development and verification

From the repository root, enter the development project:

```bash
cd src
uv sync --dev
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv lock --check
uv export --frozen --no-hashes --no-dev --no-emit-project --output-file .audit-requirements.txt
uvx pip-audit --disable-pip --no-deps -r .audit-requirements.txt
uv build
```

From `src/`, regenerate the secret-checked TUI captures after intentional visual
changes:

```bash
uv run python scripts/capture_tui.py
```

The light-theme screenshots used in this README are tracked. Other captures
are generated on demand and ignored by Git. Visual regression baselines remain
in `src/tests/tui/snapshots/`. Generated live OpenAI evidence is also local-only
and ignored by Git.

Paid live OpenAI tests are opt-in. They use `OPENAI_API_KEY` when it is already
present in the environment, or they can read an explicit env-file path. The
file is parsed as data; it is not sourced:

```bash
SOCKETCLAW_LIVE_OPENAI=1 \
SOCKETCLAW_LIVE_ENV_FILE=/absolute/path/to/.env \
uv run pytest tests/live/test_openai_model.py -q
```

Run live tests from `src/`. Live evidence is redacted and written below
`src/artifacts/live-openai/`. The optional checkout `.env` stays at the
repository root and is ignored by Git.

## Repository layout

The root contains `README.md` and `.gitignore`, plus the private `.env`,
`AGENTS.md`, and `.agents/` entries. Git stores its internal data in `.git/`.
All development files live in `src/`, including the package source under
`src/src/socketclaw/`, tests, scripts, dependency metadata, and changelog.
See [the changelog](src/CHANGELOG.md) for release history.

## Required services and continuous operation

Use Hosts / Services to configure a named TCP, HTTP or HTTPS endpoint. HTTP checks
can require a status and a bounded response substring. Consecutive failure and
recovery thresholds are separate. Confirmed connection refusal, HTTP mismatch and
unavailable measurements remain distinct facts. Ping success never overrides a
failed required service. A recovery is linked to the same incident and does not
silently resolve the operator's decision. Unconfigured ports remain exposure
observations rather than required-service outages.

`socketclaw discover` lists readable file candidates and local TCP listeners.
Listener evidence includes process and binding information when available; missing
permissions or executable information remain explicit. Wildcard binding does not
prove Internet reachability. File logs, journald and macOS unified logging are
separate capabilities; native journal and unified-log collection are not supported.
A log-only profile needs no external IP target. Overview states the configured
coverage and the most recent collection health.

Run `socketclaw monitor` for collection independent of a TUI. It owns the same
single-writer home lock. `socketclaw attach` reads stored collector health, and
`socketclaw attach --tui` opens a read-only viewer without starting another writer.
Closing that viewer leaves the collector running. `socketclaw service-template`
prints an optional launchd or systemd user-service definition. Review and install
it yourself if you want service-manager restarts; the application does not install
it or claim it can alert after its own process has died.

Notifications are opt-in in `config.toml`:

```toml
[notifications]
local = false
# webhook = "https://your-configured-endpoint.example/alerts"
```

Only configured destinations receive transition metadata. Incident creation,
worsening and observed recovery enqueue durable deliveries. Repeated observations
do not independently send alerts. Use `socketclaw notification-status` to inspect delivery failures and retries.
Their durable records live in `notifications.db`; they are separate from collection health. Webhook delivery is
at least once with a stable `Idempotency-Key`. A receiver must deduplicate that key
to handle the crash window between receiving a request and recording its receipt.
No external heartbeat service is configured automatically.

## Investigation, action and evidence boundaries

An incident reader provides a local summary and a family-specific verification
runbook without AI. Context preview shows the bounded, redacted evidence sent for
an explicit AI investigation. Related observation IDs, source clocks and recovery
facts accompany the selected event. Omission rules and missing collection evidence
remain visible. Factual AI output must quote an actual evidence field and ID;
possible explanations remain unverified. Paid model accessibility and quality
checks remain a separate opt-in test.

Proposal approval records review only. Operator action records distinguish
`user_performed`, `failed`, `rolled_back` and `verified`. Verification requires
linked observations occurring after a recorded action. The application never runs
model-generated shell commands or automatically changes a firewall.

Raw local evidence remains private and unchanged. AI requests and both shared
export formats redact structured credentials, common password/token strings,
cookies, URL credentials, private keys and recognized provider secrets. Account
names and addresses are explicitly included for incident correlation. Pattern
redaction cannot guarantee recognition of arbitrary embedded secrets; inspect the
preview before sharing. Session drafts survive navigation and failed saves in
settings, rules, maintenance and incident-reason editors. Independent new
observations do not invalidate a note or an operator action; a genuine intervening
operator state change asks for review while preserving the draft.

## History retention and rule replay

`socketclaw history-retention --days 30` previews a bounded cleanup. Add `--apply`
to create a verified private SQLite backup and delete eligible old normal facts.
Incident-linked evidence, investigations and suppression decisions are protected.
Rule versions, log checkpoints, batch receipts and source-key deduplication
records remain intact. `doctor` reports disk space and backup headroom. Cleanup reuses SQLite pages; it does not promise an
immediate reduction of the database file or delete archive backups. Backups contain
raw private evidence and require their own operator-managed retention. Stop all
writers before restoring a verified backup, move aside the current database and
its WAL/SHM sidecars, then restore the backup and run `db migrate` followed by
`doctor` using the matching application version.

Rules / Preview and `socketclaw replay` compare stored evidence against proposed
numeric rules without changing original scores or incident history. Reports show
added and missed alert candidates, severity changes and snapshot fingerprints.
Incident counts are estimates: replay does not reconstruct operator decisions or
logs that the original collector never retained.

See [operation and validation evidence](src/docs/operations-validation.md) for
measured storage, sustained-load and platform coverage. Full historical validation
is intentionally more expensive than indexed history queries. Windows runtime,
remote macOS architectures and live model quality are reported separately from
local tests.
