"""Primary SocketClaw workspace shell."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Button, ContentSwitcher, Footer, Static

from ..config import AppConfig

_VIEWS = {
    "nav-overview": "overview-view",
    "nav-events": "events-view",
    "nav-hosts": "hosts-view",
    "nav-investigations": "investigations-view",
    "nav-settings": "settings-view",
}


class DashboardScreen(Screen[None]):
    """Calm, dense shell into which the operational screens are mounted."""

    def __init__(self, config: AppConfig, monitor: object) -> None:
        super().__init__()
        self.config = config
        self.monitor = monitor

    def compose(self) -> ComposeResult:
        preset = self.config.preset
        with Horizontal(id="topbar"):
            yield Static("SOCKETCLAW", id="brand")
            yield Static(
                f"{preset.label} / {preset.effort.upper()}",
                id="active-model",
            )
            yield Static("", id="run-state")
        with Horizontal(id="primary-nav"):
            yield Button("1  Overview", id="nav-overview", classes="nav-button active")
            yield Button("2  Events", id="nav-events", classes="nav-button")
            yield Button("3  Hosts", id="nav-hosts", classes="nav-button")
            yield Button(
                "4  Investigations",
                id="nav-investigations",
                classes="nav-button",
            )
            yield Button("5  Settings", id="nav-settings", classes="nav-button")
        with ContentSwitcher(initial="overview-view", id="workspace"):
            with Vertical(id="overview-view", classes="workspace-view"):
                yield Static("LIVE POSTURE", classes="view-kicker")
                yield Static("Network changes, prioritized.", classes="view-title")
                yield Static(
                    "Monitoring is active. New evidence will appear here as probes "
                    "complete their first cycle.",
                    classes="view-copy",
                )
                with Horizontal(id="overview-metrics"):
                    yield Static(
                        f"[b]{len(self.config.targets):02d}[/b]\nTARGETS",
                        classes="metric",
                    )
                    yield Static("[b]00[/b]\nOPEN INCIDENTS", classes="metric")
                    yield Static("[b]—[/b]\nSESSION COST", classes="metric")
                yield Static(
                    "No events yet\nThe activity stream will update without refreshing.",
                    id="activity-empty",
                )
            with Vertical(id="events-view", classes="workspace-view"):
                yield Static("EVENTS", classes="view-kicker")
                yield Static("Incident timeline", classes="view-title")
                yield Static("No captured events.", classes="empty-state")
            with Vertical(id="hosts-view", classes="workspace-view"):
                yield Static("HOSTS", classes="view-kicker")
                yield Static("Watch targets", classes="view-title")
                yield Static(
                    "\n".join(f"• {target}" for target in self.config.targets),
                    classes="target-list",
                )
            with Vertical(id="investigations-view", classes="workspace-view"):
                yield Static("INVESTIGATIONS", classes="view-kicker")
                yield Static("OpenRouter analysis queue", classes="view-title")
                yield Static("No investigations yet.", classes="empty-state")
            with Vertical(id="settings-view", classes="workspace-view"):
                yield Static("SETTINGS", classes="view-kicker")
                yield Static("Runtime configuration", classes="view-title")
                yield Static(
                    f"Model         {preset.label}\n"
                    f"Reasoning     {preset.effort.upper()}\n"
                    f"Ping interval {self.config.ping_interval:g}s\n"
                    f"Scan interval {self.config.scan_interval:g}s",
                    classes="settings-summary",
                )
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_run_state()

    def on_resize(self, event: Resize) -> None:
        self.set_class(event.size.width < 90, "narrow")

    @on(Button.Pressed, ".nav-button")
    def select_navigation(self, event: Button.Pressed) -> None:
        if event.button.id in _VIEWS:
            self.show_view(_VIEWS[event.button.id])

    def show_view(self, view_id: str) -> None:
        if view_id not in _VIEWS.values():
            return
        self.query_one("#workspace", ContentSwitcher).current = view_id
        for button in self.query(".nav-button").results(Button):
            button.set_class(_VIEWS.get(button.id) == view_id, "active")

    def refresh_run_state(self) -> None:
        paused = bool(self.monitor.status.paused)
        marker = "PAUSED" if paused else "● LIVE"
        self.query_one("#run-state", Static).update(marker)
        self.query_one("#run-state", Static).set_class(paused, "paused")
