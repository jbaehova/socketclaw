"""Primary SocketClaw operational workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast
from uuid import UUID

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
from ..domain import Severity
from ..monitor import MonitorStatus
from ..storage import EventQuery
from .context import safe_text, socketclaw_app
from .detail import DetailScreen, event_detail_markdown
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
    "settings-view": "#settings-targets",
}


class OverviewView(Vertical):
    """At-a-glance posture backed by current persisted session data."""

    def __init__(self, config: AppConfig, *, startup_warning: str | None = None) -> None:
        super().__init__(id="overview-view", classes="workspace-view")
        self.config = config
        self.startup_warning = startup_warning

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
                yield Static("", id="overview-state", classes="inline-state", markup=False)
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

    @on(DataTable.RowSelected, "#overview-events")
    def open_selected(self, event: DataTable.RowSelected) -> None:
        self._open_event(UUID(str(event.row_key.value)))

    @work(exclusive=True, group="overview-detail")
    async def _open_event(self, event_id: UUID) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            return
        try:
            event = await repository.get_event(event_id)
        except Exception as exc:
            self.query_one("#overview-state", Static).update(safe_text(f"Cannot open event: {exc}"))
            return
        if event is None:
            self.query_one("#overview-state", Static).update(
                "This observation is no longer available."
            )
            return
        decisions = (
            await repository.incidents.suppression_decisions(event.id)
            if repository.incidents
            else []
        )
        app.push_screen(DetailScreen(event_detail_markdown(event, decisions)))

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
            high_signal = await repository.list_events(
                EventQuery(severities=(Severity.HIGH, Severity.CRITICAL), limit=8)
            )
        except Exception as exc:
            state = self.query_one("#overview-state", Static)
            state.update(f"Could not load posture: {exc}")
            state.add_class("error")
            return
        self.query_one("#metric-events", Static).update(f"{stats.total_events:02d}\nEVENTS")
        self.query_one("#metric-incidents", Static).update(
            f"{stats.by_severity.get('high', 0) + stats.by_severity.get('critical', 0):02d}"
            "\nHIGH + CRITICAL"
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
                safe_text(event.target or "-"),
                safe_text(event.title),
                key=str(event.id),
            )
        state = self.query_one("#overview-state", Static)
        if self.startup_warning is not None:
            state.update(safe_text(self.startup_warning))
            state.set_class(True, "error")
        else:
            state.update(_overview_status(app.services.monitor.status, has_events=bool(events)))
            state.remove_class("error")


class DashboardScreen(Screen[None]):
    """Calm, dense shell containing all operational screens."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("c", "critical_events", "Critical", show=False),
        Binding("a", "all_events", "All events", show=False),
        Binding("i", "investigate", "Investigate", show=False),
        Binding("e", "export", "Export", show=False),
        Binding("r", "context_retry", "Run / retry", show=False),
    ]

    def __init__(
        self,
        config: AppConfig,
        services: AppServices,
        *,
        startup_error: str | None = None,
        startup_warning: str | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.services = services
        self.monitor = services.monitor
        self._monitor_error = startup_error
        self._startup_warning = startup_warning
        self._overview_dirty = False

    def compose(self) -> ComposeResult:
        preset = self.config.preset
        with Horizontal(id="topbar"):
            yield Static("SOCKETCLAW", id="brand")
            yield Static(
                f"{preset.label} / {preset.reasoning_label}",
                id="active-model",
            )
            yield Static("", id="run-state", markup=False)
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
            yield OverviewView(self.config, startup_warning=self._startup_warning)
            yield EventsView()
            yield HostsView()
            yield InvestigationsView()
            yield SettingsView()
        yield Footer()

    def on_mount(self) -> None:
        self.set_class(self.size.width < 90, "narrow")
        self.refresh_run_state()
        if self._monitor_error is not None:
            self.show_monitor_error(self._monitor_error)
        self.set_interval(1.0, self.refresh_run_state)
        self.set_interval(0.25, self._refresh_dirty_views)
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
        if view_id == "hosts-view":
            self.query_one(HostsView).focus_workspace()
        else:
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
        self.query_one(InvestigationsView).refresh_actions()
        self.query_one(SettingsView).apply_config(config)

    def refresh_run_state(self) -> None:
        status = self.monitor.status
        if self._monitor_error is not None:
            marker = "! OFFLINE"
            state_class = "offline"
        elif not status.running:
            marker = "○ STOPPED"
            state_class = "offline"
        elif status.paused:
            marker = "Ⅱ PAUSED"
            state_class = "paused"
        elif status.last_error or self._startup_warning:
            marker = "● LIVE / WARN"
            state_class = "degraded"
        else:
            marker = "● LIVE"
            state_class = ""
        widget = self.query_one("#run-state", Static)
        widget.update(marker)
        widget.set_classes(state_class)

    def show_monitor_error(self, error: str) -> None:
        self._monitor_error = error
        self.refresh_run_state()
        overview_state = self.query_one("#overview-state", Static)
        overview_state.update(f"Monitor is offline: {safe_text(error)}. Press Space to retry.")
        overview_state.set_class(True, "error")

    def clear_monitor_error(self) -> None:
        self._monitor_error = None
        self.refresh_run_state()

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
            self.query_one(HostsView).run_context_action()
        elif self._current_view == "investigations-view":
            self.query_one("#retry-investigation", Button).press()

    @property
    def _current_view(self) -> str:
        current = self.query_one("#workspace", ContentSwitcher).current
        return str(current or "")

    def _refresh_dirty_views(self) -> None:
        if socketclaw_app(self).screen is not self:
            return
        if self._current_view == "events-view":
            self.query_one(EventsView).refresh_live()
        elif self._current_view == "overview-view" and self._overview_dirty:
            self._overview_dirty = False
            self.query_one(OverviewView).refresh_data()

    @work(exclusive=True, group="live-events")
    async def _consume_events(self) -> None:
        try:
            async for event in self.monitor.events():
                self._monitor_error = None
                self.query_one(EventsView).add_live_event(event)
                self._overview_dirty = True
        except Exception as exc:
            self.show_monitor_error(str(exc) or type(exc).__name__)


def _overview_status(status: MonitorStatus, *, has_events: bool) -> str:
    if not status.running:
        return "Monitoring is stopped. Press Space to retry."
    if status.paused:
        return "Monitoring is paused. Press Space to resume."
    if status.last_error:
        return f"Monitoring continues; the last probe failed: {safe_text(status.last_error)}"
    if has_events:
        return "Monitoring is active. New evidence appears automatically."
    return "Monitoring is active. Waiting for the first probe cycle."
