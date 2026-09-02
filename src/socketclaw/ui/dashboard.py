"""Primary SocketClaw operational workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Footer,
    Sparkline,
    Static,
)

from ..config import AppConfig
from .context import socketclaw_app
from .events import EventsView
from .hosts import HostsView
from .investigations import InvestigationsView
from .settings import SettingsView

if TYPE_CHECKING:
    from .app import AppServices

_VIEWS = {
    "nav-overview": "overview-view",
    "nav-events": "events-view",
    "nav-hosts": "hosts-view",
    "nav-investigations": "investigations-view",
    "nav-settings": "settings-view",
}
_FOCUS_TARGETS = {
    "overview-view": "#overview-events",
    "events-view": "#events-table",
    "hosts-view": "#hosts-table",
    "investigations-view": "#investigations-table",
    "settings-view": "#threshold",
}


class OverviewView(Vertical):
    """At-a-glance posture backed by current persisted session data."""

    def __init__(self, config: AppConfig) -> None:
        super().__init__(id="overview-view", classes="workspace-view")
        self.config = config

    def compose(self) -> ComposeResult:
        yield Static("OVERVIEW / LIVE POSTURE", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Network changes, prioritized.", classes="view-title")
            yield Static("Local evidence / explicit model spend", classes="view-hint")
        with Horizontal(id="overview-metrics"):
            yield Static("00\nEVENTS", id="metric-events", classes="metric")
            yield Static("00\nHIGH + CRITICAL", id="metric-incidents", classes="metric")
            yield Static("00\nINVESTIGATIONS", id="metric-investigations", classes="metric")
            yield Static("$0.000000\nEST. COST", id="metric-cost", classes="metric")
        with Horizontal(id="overview-body"):
            with Vertical(id="activity-panel"):
                yield Static("RECENT SEVERITY PULSE", classes="section-label")
                yield Sparkline([0], id="activity-sparkline")
                yield Static("", id="overview-state", classes="inline-state")
            with Vertical(id="recent-panel"):
                yield Static("RECENT HIGH-SIGNAL EVENTS", classes="section-label")
                yield DataTable(
                    id="overview-events",
                    cursor_type="row",
                    zebra_stripes=True,
                )

    def on_mount(self) -> None:
        self.query_one("#overview-events", DataTable).add_columns("TIME", "SEV", "TARGET", "EVENT")
        self.refresh_data()

    @work(exclusive=True, group="overview-load")
    async def refresh_data(self) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            self.query_one("#overview-state", Static).update("Event storage is unavailable.")
            return
        try:
            stats = await repository.session_stats()
            events = await repository.list_events()
        except Exception as exc:
            state = self.query_one("#overview-state", Static)
            state.update(f"Could not load posture: {exc}")
            state.add_class("error")
            return
        high_signal = [event for event in events if event.severity.value in {"high", "critical"}]
        self.query_one("#metric-events", Static).update(f"{stats.total_events:02d}\nEVENTS")
        self.query_one("#metric-incidents", Static).update(
            f"{len(high_signal):02d}\nHIGH + CRITICAL"
        )
        self.query_one("#metric-investigations", Static).update(
            f"{stats.completed_investigations:02d}\nINVESTIGATIONS"
        )
        self.query_one("#metric-cost", Static).update(f"${stats.cost_usd:.6f}\nEST. COST")
        weights = {
            "info": 1,
            "low": 2,
            "medium": 4,
            "high": 7,
            "critical": 10,
        }
        self.query_one("#activity-sparkline", Sparkline).data = [
            weights[event.severity.value] for event in reversed(events[:30])
        ] or [0]
        table = cast(
            DataTable[str],
            self.query_one("#overview-events", DataTable),
        )
        table.clear()
        for event in high_signal[:8]:
            table.add_row(
                event.observed_at.astimezone().strftime("%H:%M:%S"),
                event.severity.value.upper(),
                event.target or "-",
                event.title,
                key=str(event.id),
            )
        self.query_one("#overview-state", Static).update(
            "Monitoring is active. New evidence appears without refreshing."
            if events
            else "Waiting for the first probe cycle."
        )


class DashboardScreen(Screen[None]):
    """Calm, dense shell containing all operational screens."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("c", "critical_events", "Critical", show=False),
        Binding("a", "all_events", "All events", show=False),
        Binding("i", "investigate", "Investigate", show=False),
        Binding("e", "export", "Export", show=False),
        Binding("r", "context_retry", "Run / retry", show=False),
    ]

    def __init__(self, config: AppConfig, services: AppServices) -> None:
        super().__init__()
        self.config = config
        self.services = services
        self.monitor = services.monitor

    def compose(self) -> ComposeResult:
        preset = self.config.preset
        with Horizontal(id="topbar"):
            yield Static("SOCKETCLAW", id="brand")
            yield Static(
                f"{preset.label} / {preset.reasoning_label}",
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
            yield OverviewView(self.config)
            yield EventsView()
            yield HostsView()
            yield InvestigationsView()
            yield SettingsView()
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_run_state()
        self._consume_events()

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
            button.set_class(
                button.id is not None and _VIEWS.get(button.id) == view_id,
                "active",
            )
        self.query_one(_FOCUS_TARGETS[view_id]).focus()
        if view_id == "overview-view":
            self.query_one(OverviewView).refresh_data()
        elif view_id == "events-view":
            self.query_one(EventsView).refresh_data()
        elif view_id == "investigations-view":
            self.query_one(InvestigationsView).refresh_data()

    def apply_config(self, config: AppConfig) -> None:
        self.config = config
        preset = config.preset
        self.query_one("#active-model", Static).update(f"{preset.label} / {preset.reasoning_label}")
        overview = self.query_one(OverviewView)
        overview.config = config
        self.query_one(HostsView).refresh_targets()

    def refresh_run_state(self) -> None:
        paused = bool(self.monitor.status.paused)
        marker = "PAUSED" if paused else "● LIVE"
        self.query_one("#run-state", Static).update(marker)
        self.query_one("#run-state", Static).set_class(paused, "paused")

    def refresh_investigations(self) -> None:
        self.query_one(InvestigationsView).refresh_data()
        self.query_one(OverviewView).refresh_data()

    def action_critical_events(self) -> None:
        if self._current_view == "events-view":
            self.query_one(EventsView).set_critical_filter()

    def action_all_events(self) -> None:
        if self._current_view == "events-view":
            self.query_one(EventsView).clear_filters()

    def action_investigate(self) -> None:
        if self._current_view == "events-view":
            self.query_one(EventsView).investigate_selected()

    def action_export(self) -> None:
        if self._current_view == "events-view":
            self.query_one(EventsView).export_selected()

    def action_context_retry(self) -> None:
        if self._current_view == "hosts-view":
            self.query_one(HostsView).run_diagnostic("ping")
        elif self._current_view == "investigations-view":
            self.query_one("#retry-investigation", Button).press()

    @property
    def _current_view(self) -> str:
        current = self.query_one("#workspace", ContentSwitcher).current
        return str(current or "")

    @work(exclusive=True, group="live-events")
    async def _consume_events(self) -> None:
        async for event in self.monitor.events():
            self.query_one(EventsView).add_live_event(event)
            self.query_one(OverviewView).refresh_data()
