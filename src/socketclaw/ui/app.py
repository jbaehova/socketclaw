"""SocketClaw Textual application lifecycle and global actions."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol
from uuid import UUID

from textual.app import App
from textual.binding import Binding, BindingType

from ..config import AppConfig, ConfigStore
from ..domain import InvestigationResult, SecurityEvent
from ..export import export_markdown
from ..monitor import MonitorStatus
from ..openai import ModelAccess, OpenAIClient
from ..storage import (
    EventQuery,
    ResponseStatus,
    SessionStats,
    StoredEvent,
    StoredInvestigation,
    StoredResponseProposal,
)
from .dashboard import DashboardScreen
from .dialogs import HelpScreen
from .onboarding import OnboardingScreen


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
    async def list_events(self, query: EventQuery | None = None) -> list[StoredEvent]: ...

    async def get_event(self, event_id: UUID) -> StoredEvent | None: ...

    async def list_investigations(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
    ) -> list[StoredInvestigation]: ...

    async def save_investigation(
        self,
        event_id: UUID,
        result: InvestigationResult,
    ) -> StoredInvestigation: ...

    async def save_investigation_failure(
        self,
        event_id: UUID,
        *,
        model_id: str,
        requested_effort: str,
        error: str,
    ) -> StoredInvestigation: ...

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
    ) -> StoredResponseProposal: ...

    async def session_stats(self) -> SessionStats: ...


KeyValidator = Callable[[str], Awaitable[ModelAccess]]
InvestigationRunner = Callable[[UUID], Awaitable[StoredInvestigation]]


async def _validate_key(key: str) -> ModelAccess:
    return await OpenAIClient(key).validate_key()


@dataclass(slots=True)
class AppServices:
    config_store: ConfigStore
    monitor: Monitor
    validate_key: KeyValidator = _validate_key
    repository: DataRepository | None = None
    investigate: InvestigationRunner | None = None


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
        Binding("space", "toggle_monitor", "Pause / resume", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True, priority=True),
    ]

    def __init__(self, services: AppServices) -> None:
        super().__init__()
        self.services = services
        self.config = AppConfig()
        self._monitor_stopped = False
        self._product_screen_mounted = False

    @property
    def config_store(self) -> ConfigStore:
        return self.services.config_store

    async def on_mount(self) -> None:
        self.config = self.services.config_store.load()
        key = self.services.config_store.load_api_key()
        if key is None:
            self._show_product_screen(OnboardingScreen(self.services, self.config))
            return
        await self._open_dashboard()

    async def complete_onboarding(self, config: AppConfig, api_key: str) -> None:
        self.services.config_store.save_api_key(api_key)
        self.services.config_store.save(config)
        self.config = config
        await self._open_dashboard()

    async def _open_dashboard(self) -> None:
        await self.services.monitor.start()
        self._monitor_stopped = False
        self._show_product_screen(DashboardScreen(self.config, self.services))

    def save_config(self, config: AppConfig) -> None:
        self.services.config_store.save(config)
        self.config = config
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
        try:
            result = await OpenAIClient(key).investigate(event)
        except Exception as exc:
            await repository.save_investigation_failure(
                event_id,
                model_id=preset.model_id,
                requested_effort=effort,
                error=str(exc),
            )
            self._refresh_investigations()
            raise
        stored = await repository.save_investigation(event_id, result)
        self._refresh_investigations()
        return stored

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
        key = self.services.config_store.load_api_key()
        rendered = export_markdown(
            event,
            investigations[0] if investigations else None,
            secrets=[key] if key else (),
        )
        directory = self.services.config_store.home / "exports"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = directory / f"{event_id}.md"
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                prefix=f".{event_id}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(rendered)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            temporary_path.chmod(0o600)
            os.replace(temporary_path, destination)
            destination.chmod(0o600)
        except OSError:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise
        return destination

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

    def action_toggle_monitor(self) -> None:
        if not isinstance(self.screen, DashboardScreen):
            return
        if self.services.monitor.status.paused:
            self.services.monitor.resume()
        else:
            self.services.monitor.pause()
        self.screen.refresh_run_state()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    async def action_quit(self) -> None:
        await self._stop_monitor()
        self.exit()

    async def on_unmount(self) -> None:
        await self._stop_monitor()

    async def _stop_monitor(self) -> None:
        if self._monitor_stopped:
            return
        await self.services.monitor.stop()
        self._monitor_stopped = True
