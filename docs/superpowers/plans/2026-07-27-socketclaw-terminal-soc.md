# SocketClaw Terminal SOC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Claude/Gradio prototype with a polished, local-first
Textual security cockpit that monitors hosts, persists incidents, and analyzes
them through exactly three curated OpenRouter model presets.

**Architecture:** Build a new `src/socketclaw` package beside the prototype,
prove each boundary with tests, then remove the unsupported prototype surface.
The Textual process owns an async monitoring engine, SQLite repository, and
OpenRouter client; configuration and secrets are local files below
`~/.socketclaw` or a test-only `SOCKETCLAW_HOME`.

**Tech Stack:** Python 3.11+, Textual, Rich, HTTPX, Pydantic 2, SQLAlchemy 2,
aiosqlite, Typer, pytest, pytest-asyncio, pytest-textual-snapshot, Ruff, Pyright,
uv.

## Global Constraints

- The executable is `socketclaw`; default use requires no browser or separate
  daemon.
- Only `openai/gpt-5.6-terra`, `moonshotai/kimi-k3`, and
  `qwen/qwen3.7-max` may be selected.
- Their reasoning efforts are respectively `high`, `max`, and `high`.
- Anthropic, Claude, LangChain, LangGraph, Gradio, and required WebSocket
  services must not remain in the supported runtime.
- The API key is stored only as `OPENROUTER_API_KEY` in
  `~/.socketclaw/.env`, mode `0600`.
- Non-secret settings are stored atomically in
  `~/.socketclaw/config.toml`.
- Monitoring remains useful offline; AI failure never stops probes or history.
- Response mode defaults to `approval`; unsafe address classes are never
  blockable.
- Python 3.11+, macOS and Linux first-class, terminal minimum 80×24.
- Every production behavior follows a witnessed RED→GREEN cycle.
- Do not stage or print the root `.env`; it contains the live test credential.
- Do not delegate: the repository `AGENTS.md` requires inline execution.

---

## File Map

```text
src/socketclaw/
├── __init__.py              package version
├── cli.py                   Typer entry point and non-TUI commands
├── config.py                home paths, presets, validated settings, secrets
├── domain.py                event, assessment, usage, and response models
├── detection.py             deterministic scoring and named signals
├── openrouter.py            authenticated HTTP client and response validation
├── storage.py               SQLite schema, repository, schema version
├── export.py                Markdown and JSON incident export
├── doctor.py                non-secret install/runtime diagnostics
├── monitor.py               probe orchestration and in-process event stream
├── probes/
│   ├── __init__.py
│   ├── ping.py              cross-platform ping collector
│   ├── ports.py             bounded async TCP scanner
│   └── logs.py              rotation-aware log watcher
└── ui/
    ├── __init__.py
    ├── app.py               application lifecycle, bindings, command palette
    ├── styles.tcss          complete responsive visual system
    ├── onboarding.py        first-run wizard
    ├── dashboard.py         overview metrics and activity
    ├── events.py            filters, table, details, investigation action
    ├── hosts.py             targets and manual diagnostics
    ├── investigations.py    AI result queue and cost metadata
    ├── settings.py          safe atomic configuration editor
    └── dialogs.py           help, confirmation, diagnostics, errors
tests/
├── unit/
├── integration/
├── tui/
├── snapshots/
└── live/
```

The old `src/agent`, `src/network`, `src/protocol`, `src/ui/dashboard.py`,
top-level scripts, and their tests are deleted only in Task 9 after replacement
coverage exists.

---

### Task 1: Package, Model Presets, and Secure Configuration

**Files:**
- Create: `.python-version`
- Modify: `pyproject.toml`
- Modify: `.gitignore`
- Create: `src/socketclaw/__init__.py`
- Create: `src/socketclaw/config.py`
- Create: `tests/unit/test_config.py`

**Interfaces:**
- Produces:
  - `ModelPreset(key: str, label: str, model_id: str, effort: str)`
  - `MODEL_PRESETS: Mapping[str, ModelPreset]`
  - `AppConfig(BaseModel)`
  - `ConfigStore(home: Path | None = None)`
  - `ConfigStore.load() -> AppConfig`
  - `ConfigStore.save(config: AppConfig) -> None`
  - `ConfigStore.load_api_key() -> str | None`
  - `ConfigStore.save_api_key(value: str) -> None`

- [x] **Step 1: Replace dependency declarations and declare the CLI**

Pin the development interpreter to `3.11` in `.python-version`, set the project
floor to `>=3.11`, declare runtime dependencies `aiosqlite`, `httpx`,
`pydantic`, `sqlalchemy`, `textual`, and `typer`, create a PEP 735 `dev`
dependency group with pytest, pytest-asyncio, pytest-cov,
pytest-textual-snapshot, Ruff, and Pyright, and add:

```toml
[project.scripts]
socketclaw = "socketclaw.cli:app"
```

Add `.env`, `.coverage`, `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/`,
`.pyright/`, and generated screenshot reports to `.gitignore`.

- [x] **Step 2: Write configuration tests**

```python
def test_model_presets_are_exact() -> None:
    assert [(p.model_id, p.effort) for p in MODEL_PRESETS.values()] == [
        ("openai/gpt-5.6-terra", "high"),
        ("moonshotai/kimi-k3", "max"),
        ("qwen/qwen3.7-max", "high"),
    ]

def test_secret_is_written_to_private_env_file(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.save_api_key("sk-or-v1-test")
    assert store.env_path.read_text() == (
        "OPENROUTER_API_KEY=sk-or-v1-test\n"
    )
    assert stat.S_IMODE(store.env_path.stat().st_mode) == 0o600

def test_config_round_trip_is_atomic_and_validated(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    expected = AppConfig(model="kimi", targets=["1.1.1.1", "example.com"])
    store.save(expected)
    assert store.load() == expected
    assert not list(tmp_path.glob("*.tmp"))
```

Also cover an env value containing `#`, quotes, and whitespace, invalid targets,
invalid ports, corrupt TOML, `SOCKETCLAW_HOME`, and permissions corrected on an
existing file.

- [x] **Step 3: Run tests and witness RED**

Run:

```bash
uv sync --dev
uv run pytest tests/unit/test_config.py -q
```

Expected: collection fails because `socketclaw.config` does not exist.

- [x] **Step 4: Implement secure configuration**

Use a frozen dataclass for presets and Pydantic for settings:

```python
@dataclass(frozen=True, slots=True)
class ModelPreset:
    key: str
    label: str
    model_id: str
    effort: str

class AppConfig(BaseModel):
    model: Literal["terra", "kimi", "qwen"] = "terra"
    targets: list[str] = Field(default_factory=lambda: ["1.1.1.1"])
    ping_interval: float = Field(default=5.0, ge=1.0, le=3600.0)
    scan_interval: float = Field(default=60.0, ge=5.0, le=86400.0)
    ports: list[int] = Field(
        default_factory=lambda: [22, 53, 80, 443, 3389, 5432, 6379, 8080]
    )
    log_paths: list[str] = Field(default_factory=list)
    investigation_threshold: Literal["medium", "high", "critical"] = "high"
    response_mode: Literal["simulation", "approval", "automatic"] = "approval"
    theme: str = "textual-dark"
```

Write TOML with a small deterministic serializer for this flat schema and parse
with `tomllib`. Save through a sibling temporary file, `fsync`, `os.replace`,
and `chmod`. Encode the secret with shell-safe single quotes and decode using
`shlex`; never call `source` or execute the file.

- [x] **Step 5: Run GREEN and full regression**

Run:

```bash
uv run pytest tests/unit/test_config.py -q
uv run pytest -q
```

Expected: all configuration tests and the legacy suite pass.

- [x] **Step 6: Commit**

```bash
git add .gitignore pyproject.toml uv.lock src/socketclaw tests/unit/test_config.py
git commit -m "feat: add secure SocketClaw configuration"
```

---

### Task 2: Typed Domain and Deterministic Detection

**Files:**
- Create: `src/socketclaw/domain.py`
- Create: `src/socketclaw/detection.py`
- Create: `tests/unit/test_domain.py`
- Create: `tests/unit/test_detection.py`

**Interfaces:**
- Produces:
  - `Severity(StrEnum)`
  - `EventSource(StrEnum)`
  - `SecurityEvent(BaseModel)`
  - `DetectionSignal(BaseModel)`
  - `Assessment(BaseModel)`
  - `ModelUsage(BaseModel)`
  - `ResponseProposal(BaseModel)`
  - `Detector.score(event: SecurityEvent, recent: Sequence[SecurityEvent])`
    returning `DetectionResult(score: int, severity: Severity,
    signals: tuple[DetectionSignal, ...])`

- [ ] **Step 1: Write domain and scoring tests**

```python
def test_total_ping_loss_is_high_with_explanation() -> None:
    event = SecurityEvent(
        source="ping",
        event_type="ping.result",
        title="Ping failed",
        summary="No replies",
        target="1.1.1.1",
        evidence={"packet_loss": 100.0},
    )
    result = Detector().score(event, [])
    assert result.severity is Severity.HIGH
    assert result.score >= 70
    assert [signal.code for signal in result.signals] == ["ping.total_loss"]

def test_repeated_auth_failures_escalate() -> None:
    events = [auth_failure("10.0.0.8", seconds_ago=i) for i in range(6)]
    result = Detector().score(events[-1], events[:-1])
    assert result.severity is Severity.CRITICAL
    assert "log.auth_burst" in {s.code for s in result.signals}

def test_private_address_is_not_malicious_by_itself() -> None:
    result = Detector().score(manual_event(target="192.168.1.2"), [])
    assert result.score == 0
```

Cover new sensitive ports, multiple opened ports, recovery, suspicious log
patterns, unrelated-window events, exact score clamping, UUID/timestamp
defaults, confidence bounds, and invalid proposal addresses.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/unit/test_domain.py tests/unit/test_detection.py -q
```

Expected: imports fail for missing modules.

- [ ] **Step 3: Implement models and rule engine**

Use UTC-aware datetimes and serializable Pydantic models. Each rule returns a
named signal:

```python
DetectionSignal(
    code="port.sensitive_opened",
    label="Sensitive port opened",
    points=35,
    detail=f"Newly opened: {', '.join(map(str, sensitive))}",
)
```

Map score to severity with exact thresholds:

```python
if score >= 90:
    severity = Severity.CRITICAL
elif score >= 70:
    severity = Severity.HIGH
elif score >= 40:
    severity = Severity.MEDIUM
elif score >= 15:
    severity = Severity.LOW
else:
    severity = Severity.INFO
```

- [ ] **Step 4: Run GREEN**

Run:

```bash
uv run pytest tests/unit/test_domain.py tests/unit/test_detection.py -q
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/domain.py src/socketclaw/detection.py tests/unit
git commit -m "feat: add explainable threat detection"
```

---

### Task 3: OpenRouter-Only Investigation Client

**Files:**
- Create: `src/socketclaw/openrouter.py`
- Create: `tests/unit/test_openrouter.py`
- Create: `tests/live/test_openrouter_models.py`

**Interfaces:**
- Consumes: `ModelPreset`, `SecurityEvent`, `Assessment`, `ModelUsage`
- Produces:
  - `OpenRouterClient(api_key: str, transport: httpx.AsyncBaseTransport | None)`
  - `OpenRouterClient.validate_key() -> KeyStatus`
  - `OpenRouterClient.investigate(event, preset) -> InvestigationResult`
  - `OpenRouterError(kind: ErrorKind, status_code: int | None, message: str)`
  - `redact_secrets(text: str, secrets: Sequence[str]) -> str`

- [ ] **Step 1: Write request-contract and error tests**

```python
@pytest.mark.asyncio
async def test_investigation_sends_exact_model_effort_and_schema() -> None:
    transport = httpx.MockTransport(success_response)
    client = OpenRouterClient("sk-or-v1-secret", transport=transport)
    result = await client.investigate(event_fixture(), MODEL_PRESETS["kimi"])
    request = captured_request()
    body = json.loads(request.content)
    assert body["model"] == "moonshotai/kimi-k3"
    assert body["reasoning"] == {"effort": "max", "exclude": True}
    assert body["response_format"]["type"] == "json_schema"
    assert result.assessment.classification == "suspicious"

@pytest.mark.asyncio
async def test_401_is_non_retryable_and_redacted() -> None:
    client = OpenRouterClient(
        "sk-or-v1-secret", transport=httpx.MockTransport(unauthorized_response)
    )
    with pytest.raises(OpenRouterError) as caught:
        await client.validate_key()
    assert caught.value.kind is ErrorKind.AUTHENTICATION
    assert "sk-or-v1-secret" not in str(caught.value)
```

Cover `/api/v1/key`, 402, 429 with `Retry-After`, 502/503 backoff, timeouts,
malformed JSON, fenced JSON, API error inside a 200 response, Qwen request
shape, usage/cost parsing, missing usage, and request ID capture.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/unit/test_openrouter.py -q
```

Expected: import fails for `socketclaw.openrouter`.

- [ ] **Step 3: Implement the HTTP boundary**

Send:

```python
payload = {
    "model": preset.model_id,
    "messages": [
        {"role": "system", "content": INCIDENT_SYSTEM_PROMPT},
        {"role": "user", "content": event.model_dump_json()},
    ],
    "reasoning": {"effort": preset.effort, "exclude": True},
    "response_format": {
        "type": "json_schema",
        "json_schema": {
            "name": "socketclaw_incident_assessment",
            "strict": True,
            "schema": Assessment.model_json_schema(),
        },
    },
    "max_tokens": 1200,
}
```

Use three total attempts for 429, 502, and 503; honor a bounded
`Retry-After <= 30`, otherwise use 0.25 and 0.5 seconds. Never retry 400, 401,
402, or 403. Categorize errors for TUI guidance.

- [ ] **Step 4: Run GREEN**

Run:

```bash
uv run pytest tests/unit/test_openrouter.py -q
```

Expected: all pass with no warnings.

- [ ] **Step 5: Add opt-in live test scaffold**

The live test must skip unless both `SOCKETCLAW_LIVE_OPENROUTER=1` and a key are
present, parametrize the exact three presets, request a tiny synthetic event,
and write redacted JSON evidence to
`artifacts/live-openrouter/<preset>.json`. It asserts the returned model,
non-empty assessment, latency, and non-negative usage/cost without printing the
key.

- [ ] **Step 6: Commit**

```bash
git add src/socketclaw/openrouter.py tests/unit/test_openrouter.py tests/live
git commit -m "feat: integrate curated OpenRouter investigations"
```

---

### Task 4: Persistent Incident History and Export

**Files:**
- Create: `src/socketclaw/storage.py`
- Create: `src/socketclaw/export.py`
- Create: `tests/integration/test_storage.py`
- Create: `tests/unit/test_export.py`

**Interfaces:**
- Consumes: all domain models
- Produces:
  - `Repository(database_path: Path)`
  - `Repository.initialize() -> None`
  - `Repository.save_event(event, detection) -> SecurityEvent`
  - `Repository.list_events(EventQuery) -> list[StoredEvent]`
  - `Repository.save_investigation(event_id, result) -> StoredInvestigation`
  - `Repository.list_investigations(limit=100) -> list[StoredInvestigation]`
  - `Repository.session_stats() -> SessionStats`
  - `export_json(...) -> str`
  - `export_markdown(...) -> str`

- [ ] **Step 1: Write repository and export tests**

```python
@pytest.mark.asyncio
async def test_event_and_investigation_round_trip(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "socketclaw.db")
    await repo.initialize()
    stored = await repo.save_event(event_fixture(), detection_fixture())
    await repo.save_investigation(stored.id, investigation_fixture())
    assert (await repo.list_events(EventQuery()))[0].id == stored.id
    assert (await repo.list_investigations())[0].event_id == stored.id

def test_markdown_export_contains_evidence_not_secret() -> None:
    rendered = export_markdown(incident_fixture(), api_key="sk-or-v1-secret")
    assert "# SocketClaw Incident" in rendered
    assert "ping.total_loss" in rendered
    assert "sk-or-v1-secret" not in rendered
```

Cover schema version creation, idempotent initialize, severity/source/text/date
filters, pagination, model usage totals, failed investigations, JSON round-trip,
and deterministic Markdown.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/integration/test_storage.py tests/unit/test_export.py -q
```

Expected: missing modules.

- [ ] **Step 3: Implement SQLite and exports**

Create SQLAlchemy tables `schema_meta`, `events`, `investigations`,
`response_proposals`, and `runs`. Store flexible evidence and signals as JSON,
while indexing timestamp, severity, source, target, and investigation status.
Use `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`. Keep sessions
method-scoped and return detached Pydantic records.

- [ ] **Step 4: Run GREEN**

Run:

```bash
uv run pytest tests/integration/test_storage.py tests/unit/test_export.py -q
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/storage.py src/socketclaw/export.py tests
git commit -m "feat: persist and export incident history"
```

---

### Task 5: Probes and Monitoring Orchestration

**Files:**
- Create: `src/socketclaw/probes/__init__.py`
- Create: `src/socketclaw/probes/ping.py`
- Create: `src/socketclaw/probes/ports.py`
- Create: `src/socketclaw/probes/logs.py`
- Create: `src/socketclaw/monitor.py`
- Create: `tests/unit/test_probes.py`
- Create: `tests/integration/test_monitor.py`

**Interfaces:**
- Produces:
  - `PingProbe.collect(target: str) -> SecurityEvent`
  - `PortProbe.collect(target: str, ports: Sequence[int]) -> SecurityEvent`
  - `LogProbe.poll() -> list[SecurityEvent]`
  - `MonitorService.start()`, `pause()`, `resume()`, `stop()`
  - `MonitorService.events() -> AsyncIterator[SecurityEvent]`
  - `MonitorService.run_diagnostic(kind, target) -> SecurityEvent`
  - `MonitorStatus`

- [ ] **Step 1: Write probe and lifecycle tests**

```python
@pytest.mark.asyncio
async def test_port_probe_reports_newly_opened_and_closed() -> None:
    probe = PortProbe(connector=fake_connector({22: True, 443: False}))
    first = await probe.collect("127.0.0.1", [22, 443])
    probe.connector = fake_connector({22: False, 443: True})
    second = await probe.collect("127.0.0.1", [22, 443])
    assert first.evidence["newly_opened"] == [22]
    assert second.evidence["newly_opened"] == [443]
    assert second.evidence["newly_closed"] == [22]

@pytest.mark.asyncio
async def test_probe_failure_becomes_system_event_and_others_continue() -> None:
    monitor = monitor_with(one_failing_probe(), one_successful_probe())
    await monitor.start()
    events = await take(monitor.events(), 2)
    assert {event.event_type for event in events} == {
        "system.probe_error", "ping.result"
    }
```

Cover platform ping parsing, timeout, bounded port concurrency, log append,
rotation/truncation, log regexes, pause/resume, idempotent stop, schedule
intervals, queue backpressure, persistence, and deterministic scoring.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/unit/test_probes.py tests/integration/test_monitor.py -q
```

Expected: missing modules.

- [ ] **Step 3: Implement probes and monitor**

Use `asyncio.create_subprocess_exec` with argument arrays for ping and
traceroute; never invoke a shell. TCP scans use `asyncio.open_connection` with
per-port timeouts and a semaphore of 100. Log watchers preserve inode and
offset. `MonitorService` owns tasks in a `TaskGroup`, converts exceptions to
system events, scores and persists every event, and fans out to bounded
subscriber queues.

- [ ] **Step 4: Run GREEN and real read-only probe smoke**

Run:

```bash
uv run pytest tests/unit/test_probes.py tests/integration/test_monitor.py -q
uv run python -c 'import asyncio; from socketclaw.probes.ping import PingProbe; print(asyncio.run(PingProbe().collect("127.0.0.1")).event_type)'
```

Expected: tests pass and smoke prints `ping.result`.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/probes src/socketclaw/monitor.py tests
git commit -m "feat: orchestrate resilient network monitoring"
```

---

### Task 6: Textual Shell, Onboarding, and Visual System

**Files:**
- Create: `src/socketclaw/ui/__init__.py`
- Create: `src/socketclaw/ui/app.py`
- Create: `src/socketclaw/ui/onboarding.py`
- Create: `src/socketclaw/ui/dashboard.py`
- Create: `src/socketclaw/ui/styles.tcss`
- Create: `tests/tui/conftest.py`
- Create: `tests/tui/test_onboarding.py`
- Create: `tests/tui/test_navigation.py`

**Interfaces:**
- Consumes: `ConfigStore`, `Repository`, `MonitorService`,
  `OpenRouterClient`
- Produces:
  - `SocketClawApp(App[None])`
  - `OnboardingScreen(Screen[bool])`
  - `DashboardScreen(Screen[None])`
  - dependency injection through `AppServices`

- [ ] **Step 1: Write Pilot tests before widgets**

```python
@pytest.mark.asyncio
async def test_first_run_opens_onboarding_and_masks_key(app_factory) -> None:
    app = app_factory(configured=False)
    async with app.run_test(size=(100, 30)) as pilot:
        assert isinstance(app.screen, OnboardingScreen)
        key = app.screen.query_one("#api-key", Input)
        assert key.password is True
        await pilot.click("#api-key")
        await pilot.press(*"sk-or-v1-test")
        assert "sk-or-v1-test" not in app.screen.render_str()

@pytest.mark.asyncio
async def test_direct_navigation_and_pause_binding(app_factory) -> None:
    app = app_factory(configured=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("2")
        assert app.query_one("#events-view").display
        await pilot.press("space")
        assert app.monitor.status.paused is True
```

Also cover key validation failure, successful onboarding save, model selection,
80×24 render, tab focus, `?`, `Ctrl+P`, `q`, and shutdown cleanup.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/tui/test_onboarding.py tests/tui/test_navigation.py -q
```

Expected: missing UI modules.

- [ ] **Step 3: Implement shell and responsive CSS**

Use a top status bar, left navigation rail on wide terminals, `ContentSwitcher`,
and footer key hints. At `max-width: 89`, hide the rail labels and secondary
panes. Use a restrained dark palette:

```css
$surface: #111827;
$panel: #182235;
$muted: #8fa0b7;
$accent: #66d9c5;
$warning: #f2c14e;
$danger: #ff6b6b;
```

Onboarding is a five-step `TabbedContent` wizard with validation preventing
forward movement. The key field is password-masked and its value is never
included in notifications.

- [ ] **Step 4: Run GREEN**

Run:

```bash
uv run pytest tests/tui/test_onboarding.py tests/tui/test_navigation.py -q
```

Expected: all pass at both terminal sizes.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/ui tests/tui
git commit -m "feat: add SocketClaw Textual shell and onboarding"
```

---

### Task 7: Rich Operational Screens and Investigation Flow

**Files:**
- Create: `src/socketclaw/ui/events.py`
- Create: `src/socketclaw/ui/hosts.py`
- Create: `src/socketclaw/ui/investigations.py`
- Create: `src/socketclaw/ui/settings.py`
- Create: `src/socketclaw/ui/dialogs.py`
- Modify: `src/socketclaw/ui/dashboard.py`
- Modify: `src/socketclaw/ui/app.py`
- Modify: `src/socketclaw/ui/styles.tcss`
- Create: `tests/tui/test_events.py`
- Create: `tests/tui/test_hosts.py`
- Create: `tests/tui/test_investigations.py`
- Create: `tests/tui/test_settings.py`

**Interfaces:**
- Consumes all core service interfaces
- Produces a complete keyboard-accessible operational UI

- [ ] **Step 1: Write event and investigation flow tests**

```python
@pytest.mark.asyncio
async def test_filter_select_investigate_and_show_usage(app_factory) -> None:
    app = app_factory(events=[critical_event()], investigation=successful_result())
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("2")
        await pilot.press("c")  # critical filter
        assert app.query_one("#events-table", DataTable).row_count == 1
        await pilot.press("i")
        await pilot.pause()
        await pilot.press("4")
        detail = app.query_one("#investigation-detail", Markdown)
        assert "GPT-5.6 Terra" in str(detail.content)
        assert "tokens" in str(detail.content)

@pytest.mark.asyncio
async def test_settings_select_qwen_and_atomically_save(app_factory) -> None:
    app = app_factory(configured=True)
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("5")
        select = app.query_one("#model", Select)
        select.value = "qwen"
        await pilot.click("#save-settings")
        assert app.config.model == "qwen"
        assert app.config_store.load().model == "qwen"
```

Cover empty/loading/error states, live event insertion, text/source/severity
filters, details, host CRUD validation, manual diagnostics, failed
investigation retry, exports, API key replacement, response confirmation,
trusted-address rejection, and session cost update.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/tui/test_events.py tests/tui/test_hosts.py \
  tests/tui/test_investigations.py tests/tui/test_settings.py -q
```

Expected: imports or widget queries fail.

- [ ] **Step 3: Implement operational screens**

Use `DataTable` for events, hosts, and investigation queue; `Markdown` for
details; `Sparkline` for recent activity; modals for destructive confirmations.
Every async action runs as an exclusive Textual worker and disables its trigger
until completion. Bind `i`, `e`, `r`, and filter shortcuts only on screens where
they apply.

- [ ] **Step 4: Run GREEN and entire TUI suite**

Run:

```bash
uv run pytest tests/tui -q
```

Expected: all Pilot flows pass without leaked tasks or warnings.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/ui tests/tui
git commit -m "feat: complete SocketClaw operational TUI"
```

---

### Task 8: CLI, Doctor, Packaging, and User Documentation

**Files:**
- Create: `src/socketclaw/cli.py`
- Create: `src/socketclaw/doctor.py`
- Create: `tests/unit/test_cli.py`
- Create: `tests/unit/test_doctor.py`
- Replace: `README.md`
- Create: `CHANGELOG.md`

**Interfaces:**
- Produces:
  - `socketclaw`
  - `socketclaw doctor`
  - `socketclaw config path`
  - `socketclaw export --format markdown|json`
  - `socketclaw version`

- [ ] **Step 1: Write CLI and doctor tests**

```python
def test_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"SocketClaw {__version__}"

def test_doctor_redacts_key(tmp_path: Path, monkeypatch) -> None:
    ConfigStore(tmp_path).save_api_key("sk-or-v1-secret")
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "OpenRouter key: configured" in result.stdout
    assert "sk-or-v1-secret" not in result.stdout
```

Cover config path, missing key, malformed config, unavailable ping/traceroute,
database writability, exports, TUI invocation, and `--help`.

- [ ] **Step 2: Run tests and witness RED**

Run:

```bash
uv run pytest tests/unit/test_cli.py tests/unit/test_doctor.py -q
```

Expected: missing modules.

- [ ] **Step 3: Implement commands and docs**

Use Typer with the no-argument callback launching `SocketClawApp`. `doctor`
returns exit 1 only for conditions that prevent launch. README includes
installation with `uv tool install .` and `pipx install .`, first run, the three
presets, home file layout, keyboard reference, safety modes, troubleshooting,
development, live-test opt-in, and screenshots.

- [ ] **Step 4: Run GREEN**

Run:

```bash
uv run pytest tests/unit/test_cli.py tests/unit/test_doctor.py -q
uv run socketclaw --help
uv run socketclaw version
```

Expected: tests pass and commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/socketclaw/cli.py src/socketclaw/doctor.py tests README.md CHANGELOG.md
git commit -m "feat: ship SocketClaw CLI and documentation"
```

---

### Task 9: Remove Prototype and Prove No Legacy Provider Remains

**Files:**
- Delete: `main.py`
- Delete: `scripts/`
- Delete: `src/agent/`
- Delete: `src/network/`
- Delete: `src/probes/`
- Delete: `src/protocol/`
- Delete: `src/storage/`
- Delete: `src/ui/`
- Delete: `tests/test_agent.py`
- Delete: `tests/test_integration.py`
- Delete: `tests/test_probes.py`
- Delete: `tests/test_protocol.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `tests/unit/test_no_legacy_provider.py`

**Interfaces:**
- Leaves only the supported `socketclaw` runtime and test surface

- [ ] **Step 1: Write the legacy-provider guard**

```python
def test_runtime_has_no_legacy_provider_references() -> None:
    forbidden = {
        "anthropic", "claude", "langchain", "langgraph", "gradio",
        "ANTHROPIC_API_KEY",
    }
    runtime = "\n".join(
        path.read_text(errors="ignore")
        for path in Path("src/socketclaw").rglob("*")
        if path.is_file()
    ).lower()
    assert not {term for term in forbidden if term.lower() in runtime}
```

Also inspect installed dependency names from `importlib.metadata.requires`.

- [ ] **Step 2: Run guard and witness RED**

Run:

```bash
uv run pytest tests/unit/test_no_legacy_provider.py -q
```

Expected: dependency assertion reports legacy packages.

- [ ] **Step 3: Delete the prototype and regenerate the lock**

Delete only the paths listed in this task, remove their dependencies, and run:

```bash
uv lock
uv sync --dev
```

Do not delete `.env`, `AGENTS.md`, docs, or the new package.

- [ ] **Step 4: Run GREEN and search**

Run:

```bash
uv run pytest tests/unit/test_no_legacy_provider.py -q
rg -ni "anthropic|claude|langchain|langgraph|gradio|ANTHROPIC_API_KEY" \
  src pyproject.toml README.md
```

Expected: test passes and search returns no matches.

- [ ] **Step 5: Commit**

```bash
git add -A main.py scripts src tests pyproject.toml uv.lock
git commit -m "refactor: remove the legacy Claude dashboard"
```

---

### Task 10: Visual, Live-Credit, Install, and Completion Verification

**Files:**
- Create: `tests/tui/test_snapshots.py`
- Create: `tests/snapshots/`
- Create: `scripts/capture_tui.py`
- Create: `artifacts/README.md`
- Create: `docs/verification/2026-07-27-completion-audit.md`
- Modify: `README.md`

**Interfaces:**
- Produces authoritative completion artifacts without secrets

- [ ] **Step 1: Add snapshot cases**

Parametrize onboarding, overview, events, investigation detail, and settings at
`(80, 24)` and `(120, 36)`:

```python
@pytest.mark.parametrize("case", VISUAL_CASES, ids=lambda case: case.name)
def test_visual_states(snap_compare, case: VisualCase) -> None:
    assert snap_compare(
        case.app_path,
        terminal_size=case.size,
        press=case.keys,
    )
```

- [ ] **Step 2: Witness initial snapshot RED and approve generated baselines**

Run:

```bash
uv run pytest tests/tui/test_snapshots.py -q
```

Expected: first run fails and emits an HTML/SVG diff report. Inspect every SVG
for clipping, overlap, unreadable contrast, secret leakage, and missing focus;
fix production CSS through a new failing assertion when behavior is wrong, then
approve the baselines.

- [ ] **Step 3: Capture actual TUI states**

`scripts/capture_tui.py` starts the real app with a deterministic seeded
database and calls Textual's screenshot API after scripted Pilot navigation.
Write SVG files under `artifacts/tui/` for the five named states and convert
representative SVGs to PNG for visual inspection when a converter is available.

Run:

```bash
uv run python scripts/capture_tui.py
```

Expected: five SVG captures at wide size and at least onboarding/overview at
80×24, with no key in any file.

- [ ] **Step 4: Run all three paid model tests**

Point the live fixture at the repository root key file. The fixture parses the
single assignment as data with `shlex`; it does not execute or print the file:

```bash
SOCKETCLAW_LIVE_OPENROUTER=1 \
SOCKETCLAW_LIVE_ENV_FILE=/Users/johnnybae/workspace/socketclaw/.env \
uv run pytest \
  tests/live/test_openrouter_models.py -v
```

Expected: all three exact model presets return validated assessments. Inspect
the redacted evidence JSON for model ID, requested effort, latency, usage, and
cost. If Qwen rejects `reasoning.effort=high`, preserve the user-visible preset
label but record and implement the provider-compatible normalized request only
after a failing contract test proves the necessary exception.

- [ ] **Step 5: Run quality gates**

Run fresh:

```bash
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -q
uv build
```

Expected: every command exits 0 with no warnings that indicate leaked tasks,
unawaited coroutines, or deprecated runtime APIs.

- [ ] **Step 6: Test the wheel in a fresh environment and PTY**

Create a temporary directory with `mktemp -d`, create a Python 3.11+ virtual
environment there, install `dist/socketclaw-*.whl`, then run:

```bash
socketclaw version
SOCKETCLAW_HOME="$temporary_home" socketclaw doctor
SOCKETCLAW_HOME="$temporary_home" socketclaw --help
```

Start `socketclaw` in a PTY with the deterministic test home, wait for the
onboarding heading, send `q`, and assert exit 0 with terminal state restored.

- [ ] **Step 7: Perform the requirement-by-requirement audit**

Create `docs/verification/2026-07-27-completion-audit.md` with one row per
requirement from the approved design and original request. Each row names the
exact command, source file, live artifact, screenshot, or test that proves it.
Any missing or indirect evidence returns to the responsible task.

- [ ] **Step 8: Final commit**

```bash
git add tests scripts artifacts docs README.md
git commit -m "test: verify SocketClaw end to end"
```

- [ ] **Step 9: Re-run the final gate after the commit**

Run:

```bash
git status --short --branch
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -q
uv build
```

Expected: only user-owned untracked files are present, all gates exit 0, live
evidence exists for all three models, and the completion audit has no open row.
