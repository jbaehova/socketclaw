"""SocketClaw Textual application lifecycle and global actions."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Collection, Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol
from uuid import UUID

from textual.app import App, SystemCommand
from textual.binding import Binding, BindingType
from textual.screen import Screen
from textual.theme import Theme

from ..collection import CheckpointChange
from ..config import AppConfig, ConfigStore
from ..domain import InvestigationResult, SecurityEvent
from ..export import export_incident_markdown, export_markdown, write_managed_export
from ..incident_store import IncidentStore
from ..monitor import MonitorStatus
from ..openai import ModelAccess, OpenAIClient, redact_secrets
from ..storage import (
    EventQuery,
    IncidentReport,
    RelatedPage,
    ResponseStatus,
    SessionStats,
    StoredEvent,
    StoredInvestigation,
    StoredResponseProposal,
    StoredResponseStatus,
)
from .dashboard import DashboardScreen
from .dialogs import HelpScreen
from .health import HealthScreen
from .hosts import HostsView
from .incidents import IncidentDesk
from .onboarding import OnboardingScreen
from .rules import RuleSettingsScreen


class Monitor(Protocol):
    @property
    def status(self) -> MonitorStatus: ...

    async def start(self) -> None: ...

    def pause(self) -> None: ...

    def resume(self) -> None: ...

    async def stop(self) -> None: ...

    def events(self) -> AsyncIterator[SecurityEvent]: ...

    async def run_diagnostic(self, kind: str, target: str) -> StoredEvent: ...


class DataRepository(Protocol):
    @property
    def incidents(self) -> IncidentStore | None: ...

    async def load_checkpoint(self, probe_id: str) -> CheckpointChange: ...

    async def list_events(self, query: EventQuery | None = None) -> list[StoredEvent]: ...

    async def get_event(self, event_id: UUID) -> StoredEvent | None: ...

    async def incident_report(self, identifier: UUID) -> IncidentReport | None: ...

    async def incident_observations(
        self,
        identifier: UUID,
        *,
        watermark: int | None = None,
        before: int | None = None,
        limit: int = 100,
    ) -> RelatedPage: ...

    async def list_investigations(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
    ) -> list[StoredInvestigation]: ...

    async def queue_investigation(
        self,
        event_id: UUID,
        *,
        model_id: str,
        requested_effort: str,
    ) -> StoredInvestigation: ...

    async def start_investigation(self, investigation_id: UUID) -> StoredInvestigation: ...

    async def complete_investigation(
        self,
        investigation_id: UUID,
        result: InvestigationResult,
    ) -> StoredInvestigation: ...

    async def fail_investigation(
        self,
        investigation_id: UUID,
        *,
        error: str,
    ) -> StoredInvestigation: ...

    async def recover_incomplete_investigations(self) -> int: ...

    async def list_response_proposals(
        self,
        *,
        event_id: UUID | None = None,
        limit: int = 100,
    ) -> list[StoredResponseProposal]: ...

    async def update_response_proposal_status(
        self,
        proposal_id: UUID,
        status: ResponseStatus,
        *,
        expected_status: StoredResponseStatus,
        protected_targets: Collection[str],
    ) -> StoredResponseProposal: ...

    async def session_stats(self) -> SessionStats: ...


KeyValidator = Callable[[str], Awaitable[ModelAccess]]
InvestigationRunner = Callable[[UUID], Awaitable[StoredInvestigation]]
ConfigReconfigurer = Callable[[AppConfig], Awaitable[None]]


async def _validate_key(key: str) -> ModelAccess:
    return await OpenAIClient(key).validate_key()


@dataclass(slots=True)
class AppServices:
    config_store: ConfigStore
    monitor: Monitor
    validate_key: KeyValidator = _validate_key
    repository: DataRepository | None = None
    investigate: InvestigationRunner | None = None
    reconfigure: ConfigReconfigurer | None = None


class SocketClawApp(App[None]):
    """One-process terminal security operations cockpit."""

    TITLE = "SocketClaw"
    SUB_TITLE = "Local network operations"
    CSS_PATH = "styles.tcss"
    ENABLE_COMMAND_PALETTE = True
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("1", "show_view('overview-view')", "Overview", show=False),
        Binding("2", "show_view('events-view')", "Events", show=False),
        Binding("3", "show_view('hosts-view')", "Hosts", show=False),
        Binding(
            "4",
            "show_view('investigations-view')",
            "Investigations",
            show=False,
        ),
        Binding("5", "show_view('settings-view')", "Settings", show=False),
        Binding("l", "log_status", "Log sources", show=False),
        Binding("h", "health", "Health", show=False),
        Binding("space", "toggle_monitor", "Pause / resume", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, services: AppServices) -> None:
        super().__init__()
        self.register_theme(
            Theme(
                name="socketclaw-dark",
                primary="#66d9c5",
                warning="#f2c14e",
                error="#ff6b6b",
                foreground="#e7eef7",
                background="#0a0f18",
                surface="#111827",
                panel="#182235",
                variables={
                    "border": "#2b3950",
                    "text": "#e7eef7",
                    "text-muted": "#8fa0b7",
                    "footer-key-foreground": "#66d9c5",
                    "button-color-foreground": "#0a0f18",
                },
            )
        )
        self.register_theme(
            Theme(
                name="socketclaw-light",
                primary="#087b6d",
                warning="#936b00",
                error="#b42318",
                foreground="#101827",
                background="#f4f7fb",
                surface="#ffffff",
                panel="#e7edf5",
                dark=False,
                variables={
                    "border": "#c5d0dc",
                    "text": "#101827",
                    "text-muted": "#526174",
                    "footer-key-foreground": "#087b6d",
                    "button-color-foreground": "#ffffff",
                },
            )
        )
        self.services = services
        self.config = AppConfig()
        self._monitor_stopped = False
        self._product_screen_mounted = False
        self._config_lock = asyncio.Lock()

    @property
    def config_store(self) -> ConfigStore:
        return self.services.config_store

    async def on_mount(self) -> None:
        onboarding_complete = self.services.config_store.config_path.exists()
        self.config = self.services.config_store.load()
        self._apply_theme(self.config.theme)
        recovery_error: str | None = None
        if self.services.repository is not None:
            try:
                await self.services.repository.recover_incomplete_investigations()
            except Exception as exc:
                recovery_error = (
                    f"Investigation recovery failed: {str(exc).strip() or type(exc).__name__}"
                )
        key = self.services.config_store.load_api_key()
        if not onboarding_complete:
            self._show_product_screen(
                OnboardingScreen(
                    self.services,
                    self.config,
                    existing_api_key=key,
                )
            )
            return
        await self._open_dashboard(startup_warning=recovery_error)

    async def complete_onboarding(self, config: AppConfig, api_key: str | None) -> None:
        previous = self.config
        previous_key = self.services.config_store.load_api_key()
        try:
            await self.save_config(config)
            if api_key is not None:
                self.services.config_store.save_api_key(api_key)
            await self._open_dashboard()
        except BaseException:
            if previous_key is None:
                self.services.config_store.clear_api_key()
            else:
                self.services.config_store.save_api_key(previous_key)
            with suppress(Exception):
                await self.save_config(previous)
            self.services.config_store.config_path.unlink(missing_ok=True)
            raise

    async def _open_dashboard(self, *, startup_warning: str | None = None) -> None:
        self._monitor_stopped = False
        startup_error: str | None = None
        try:
            await self.services.monitor.start()
        except Exception as exc:
            startup_error = str(exc).strip() or type(exc).__name__
        self._show_product_screen(
            DashboardScreen(
                self.config,
                self.services,
                startup_error=startup_error,
                startup_warning=startup_warning,
            )
        )

    async def save_config(self, config: AppConfig) -> None:
        async with self._config_lock:
            await self._save_config_locked(AppConfig.model_validate(config))

    async def update_config(
        self,
        transform: Callable[[AppConfig], AppConfig],
    ) -> AppConfig:
        """Apply a config mutation to the latest state under one runtime lock."""
        async with self._config_lock:
            candidate = AppConfig.model_validate(transform(self.config))
            await self._save_config_locked(candidate)
            return candidate

    async def _save_config_locked(self, config: AppConfig) -> None:
        previous = self.config
        config_existed = self.services.config_store.config_path.exists()
        self.services.config_store.save(config)
        if self.services.reconfigure is not None:
            try:
                await self.services.reconfigure(config)
            except BaseException:
                if config_existed:
                    self.services.config_store.save(previous)
                else:
                    self.services.config_store.config_path.unlink(missing_ok=True)
                with suppress(BaseException):
                    await self.services.reconfigure(previous)
                raise
        self.config = config
        self._apply_theme(config.theme)
        if isinstance(self.screen, DashboardScreen):
            self.screen.apply_config(config)

    async def investigate_event(self, event_id: UUID) -> StoredInvestigation:
        if self.services.investigate is not None:
            result = await self.services.investigate(event_id)
            self._refresh_investigations()
            return result
        repository = self.services.repository
        if repository is None:
            raise RuntimeError("Investigation storage is unavailable")
        event = await repository.get_event(event_id)
        if event is None:
            raise KeyError(str(event_id))
        key = self.services.config_store.load_api_key()
        if key is None:
            raise RuntimeError("OpenAI API key is not configured")
        preset = self.config.preset
        effort = preset.effort_for(event.severity)
        queue_task = asyncio.create_task(
            repository.queue_investigation(
                event_id,
                model_id=preset.model_id,
                requested_effort=effort,
            ),
            name=f"socketclaw-queue-investigation-{event_id}",
        )
        try:
            queued = await asyncio.shield(queue_task)
        except asyncio.CancelledError:
            with suppress(Exception):
                queued = await queue_task
                await repository.fail_investigation(
                    queued.id,
                    error="Investigation canceled during queue persistence",
                )
            self._refresh_investigations()
            raise
        self._refresh_investigations()
        try:
            await repository.start_investigation(queued.id)
            self._refresh_investigations()
            result = await OpenAIClient(key).investigate(event)
        except asyncio.CancelledError:
            with suppress(Exception):
                await repository.fail_investigation(
                    queued.id,
                    error="Investigation canceled before completion",
                )
            self._refresh_investigations()
            raise
        except Exception as exc:
            message = _safe_investigation_error(exc, key)
            try:
                await repository.fail_investigation(
                    queued.id,
                    error=message,
                )
            except Exception as persistence_error:
                raise RuntimeError(
                    "Investigation failed and its durable state could not be updated: "
                    f"{_safe_investigation_error(persistence_error, key)}"
                ) from exc
            self._refresh_investigations()
            raise RuntimeError(message) from exc
        completion = asyncio.create_task(
            repository.complete_investigation(queued.id, result),
            name=f"socketclaw-complete-investigation-{queued.id}",
        )
        try:
            stored = await asyncio.shield(completion)
        except asyncio.CancelledError:
            with suppress(Exception):
                await completion
            with suppress(Exception):
                await self._fail_unless_completed(
                    repository,
                    event_id,
                    queued.id,
                    error="Investigation canceled during result persistence",
                )
            self._refresh_investigations()
            raise
        except Exception as exc:
            message = _safe_investigation_error(exc, key)
            completed = await self._fail_unless_completed(
                repository,
                event_id,
                queued.id,
                error=message,
            )
            if completed is None:
                self._refresh_investigations()
                raise RuntimeError(message) from exc
            stored = completed
        self._refresh_investigations()
        return stored

    async def _fail_unless_completed(
        self,
        repository: DataRepository,
        event_id: UUID,
        investigation_id: UUID,
        *,
        error: str,
    ) -> StoredInvestigation | None:
        """Fail active work while preserving a completion that may have committed."""
        records = await repository.list_investigations(event_id=event_id, limit=500)
        current = next((item for item in records if item.id == investigation_id), None)
        if current is not None and current.status == "complete":
            return current
        if current is not None and current.status in {"queued", "running"}:
            await repository.fail_investigation(investigation_id, error=error)
        return None

    async def export_incident(self, identifier: UUID) -> Path:
        repository = self.services.repository
        if repository is None:
            raise RuntimeError("Incident storage is unavailable")
        report = await repository.incident_report(identifier)
        if report is None:
            raise KeyError(str(identifier))
        key = self.services.config_store.load_api_key()
        rendered = export_incident_markdown(report, secrets=[key] if key else ())
        return await asyncio.to_thread(
            write_managed_export,
            self.services.config_store.home,
            f"incident-{identifier}.md",
            rendered,
        )

    async def export_event(self, event_id: UUID) -> Path:
        repository = self.services.repository
        if repository is None:
            raise RuntimeError("Event storage is unavailable")
        event = await repository.get_event(event_id)
        if event is None:
            raise KeyError(str(event_id))
        investigations = await repository.list_investigations(
            event_id=event_id,
            limit=1,
        )
        investigation = investigations[0] if investigations else None
        response_proposal: StoredResponseProposal | None = None
        if investigation is not None:
            proposals = await repository.list_response_proposals(
                event_id=event_id,
                limit=500,
            )
            response_proposal = next(
                (
                    proposal
                    for proposal in proposals
                    if proposal.investigation_id == investigation.id
                ),
                None,
            )
        key = self.services.config_store.load_api_key()
        suppressions = (
            await repository.incidents.suppression_decisions(event_id)
            if repository.incidents is not None
            else []
        )
        rendered = export_markdown(
            event,
            investigation,
            response_proposal=response_proposal,
            suppressions=suppressions,
            secrets=[key] if key else (),
        )
        return write_managed_export(
            self.services.config_store.home,
            f"{event_id}.md",
            rendered,
        )

    def _refresh_investigations(self) -> None:
        if isinstance(self.screen, DashboardScreen):
            self.screen.refresh_investigations()

    def _show_product_screen(
        self,
        screen: OnboardingScreen | DashboardScreen,
    ) -> None:
        if self._product_screen_mounted:
            self.switch_screen(screen)  # pyright: ignore[reportUnknownMemberType]
        else:
            self.push_screen(screen)
            self._product_screen_mounted = True

    def action_show_view(self, view_id: str) -> None:
        if isinstance(self.screen, DashboardScreen):
            self.screen.show_view(view_id)

    async def action_toggle_monitor(self) -> None:
        if not isinstance(self.screen, DashboardScreen):
            return
        try:
            status = self.services.monitor.status
            if not status.running:
                await self.services.monitor.start()
            elif status.paused:
                self.services.monitor.resume()
            else:
                self.services.monitor.pause()
        except Exception as exc:
            self.screen.show_monitor_error(str(exc) or type(exc).__name__)
            return
        self.screen.clear_monitor_error()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def get_system_commands(self, screen: Screen[object]) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)  # pyright: ignore[reportUnknownMemberType]
        if isinstance(screen, DashboardScreen):
            yield SystemCommand(
                "Incident desk", "Review and resolve correlated incidents", self.action_incidents
            )
            yield SystemCommand(
                "Maintenance exceptions",
                "Limit incident creation during planned work",
                self.action_maintenance,
            )
            yield SystemCommand(
                "Detection rules", "Edit thresholds and score contributions", self.action_rules
            )
            yield SystemCommand(
                "Health", "Inspect collection health and scheduling", self.action_health
            )
            yield SystemCommand(
                "Log sources", "Inspect committed log progress", self.action_log_status
            )

    def action_maintenance(self) -> None:
        from .suppressions import MaintenanceScreen

        repository = self.services.repository
        if isinstance(self.screen, DashboardScreen) and repository and repository.incidents:
            self.push_screen(MaintenanceScreen(repository.incidents))

    def action_incidents(self) -> None:
        repository = self.services.repository
        if (
            isinstance(self.screen, DashboardScreen)
            and repository is not None
            and repository.incidents is not None
        ):
            self.push_screen(IncidentDesk(repository.incidents))

    def action_rules(self) -> None:
        if isinstance(self.screen, DashboardScreen):
            self.push_screen(RuleSettingsScreen(self.config.rules))

    def action_health(self) -> None:
        if isinstance(self.screen, DashboardScreen):
            self.push_screen(HealthScreen(self.services.monitor))

    async def action_log_status(self) -> None:
        if not isinstance(self.screen, DashboardScreen):
            return
        self.screen.show_view("hosts-view")
        self.screen.query_one(HostsView).open_logs()

    async def action_quit(self) -> None:
        with suppress(BaseException):
            await self._stop_monitor()
        self.exit()

    async def on_unmount(self) -> None:
        with suppress(BaseException):
            await self._stop_monitor()

    async def _stop_monitor(self) -> None:
        if self._monitor_stopped:
            return
        self._monitor_stopped = True
        await self.services.monitor.stop()

    def _apply_theme(self, theme_name: str) -> None:
        """Apply a configured theme without letting a stale name crash startup."""
        aliases = {
            "textual-dark": "socketclaw-dark",
            "textual-light": "socketclaw-light",
        }
        selected = aliases.get(theme_name, theme_name)
        self.theme = selected if selected in self.available_themes else "socketclaw-dark"


def _safe_investigation_error(exc: BaseException, key: str) -> str:
    """Return a stable error safe for durable storage and terminal display."""
    return redact_secrets(str(exc), [key]).strip() or type(exc).__name__
