"""SocketClaw Textual application lifecycle and global actions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import ClassVar, Protocol

from textual.app import App
from textual.binding import Binding

from ..config import AppConfig, ConfigStore
from ..openrouter import KeyStatus, OpenRouterClient
from .dashboard import DashboardScreen
from .dialogs import HelpScreen
from .onboarding import OnboardingScreen


class Monitor(Protocol):
    @property
    def status(self) -> object: ...

    async def start(self) -> None: ...

    def pause(self) -> None: ...

    def resume(self) -> None: ...

    async def stop(self) -> None: ...


KeyValidator = Callable[[str], Awaitable[KeyStatus]]


async def _validate_key(key: str) -> KeyStatus:
    return await OpenRouterClient(key).validate_key()


@dataclass(slots=True)
class AppServices:
    config_store: ConfigStore
    monitor: Monitor
    validate_key: KeyValidator = _validate_key


class SocketClawApp(App[None]):
    """One-process terminal security operations cockpit."""

    TITLE = "SocketClaw"
    SUB_TITLE = "Local network operations"
    CSS_PATH = "styles.tcss"
    ENABLE_COMMAND_PALETTE = True
    BINDINGS: ClassVar[list[Binding]] = [
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

    async def on_mount(self) -> None:
        key = self.services.config_store.load_api_key()
        if key is None:
            self._show_product_screen(OnboardingScreen(self.services))
            return
        self.config = self.services.config_store.load()
        await self._open_dashboard()

    async def complete_onboarding(self, config: AppConfig, api_key: str) -> None:
        self.services.config_store.save_api_key(api_key)
        self.services.config_store.save(config)
        self.config = config
        await self._open_dashboard()

    async def _open_dashboard(self) -> None:
        await self.services.monitor.start()
        self._monitor_stopped = False
        self._show_product_screen(DashboardScreen(self.config, self.services.monitor))

    def _show_product_screen(
        self,
        screen: OnboardingScreen | DashboardScreen,
    ) -> None:
        if self._product_screen_mounted:
            self.switch_screen(screen)
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
