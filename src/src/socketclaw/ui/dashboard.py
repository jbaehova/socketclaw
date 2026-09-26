"""Primary SocketClaw operational workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.widgets import (
    Button,
    ContentSwitcher,
    Input,
    OptionList,
    Static,
)
from textual.widgets.option_list import Option

from .. import __version__
from ..config import AppConfig
from ..health import coverage_summary
from ..monitor import MonitorStatus
from .commands import CommandBar
from .context import safe_text, socketclaw_app
from .detail import DetailScreen, event_detail_markdown
from .events import EventsView
from .hosts import HostsView
from .investigations import InvestigationsView
from .layout import ResponsiveScreen
from .settings import SettingsView

if TYPE_CHECKING:
    from .app import AppServices

_VIEWS = {"overview-view", "events-view", "hosts-view", "investigations-view", "settings-view"}
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
        yield Static("Your watch", classes="view-title")
        yield Static("", id="watch-targets", markup=False)
        yield Static("", id="watch-summary", markup=False)
        yield Static("", id="watch-coverage", markup=False)
        yield Static("", id="overview-state", classes="inline-state", markup=False)
        yield Static("Recent activity", id="activity-label", classes="section-label")
        yield OptionList(id="overview-events")
        yield Static(
            "No observations yet. Your first probe results will appear here.\n"
            "Use /hosts to add a target, or /logs to watch a log file.",
            id="activity-empty",
            markup=False,
        )

    def on_mount(self) -> None:
        self.query_one("#overview-state").can_focus = True
        self._activity_signature: tuple[tuple[str, str], ...] = ()
        self.refresh_data()

    @on(OptionList.OptionSelected, "#overview-events")
    def open_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id is not None:
            self._open_event(UUID(event.option.id))

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
        except Exception as exc:
            state = self.query_one("#overview-state", Static)
            state.update(f"Could not load posture: {exc}")
            state.add_class("error")
            return
        self.query_one("#watch-targets", Static).update(
            "Watching "
            + (", ".join(self.config.targets) or "configured local sources")
            + f" / {len(self.config.log_paths)} log file(s)"
        )
        attention = stats.attention_incidents
        self.query_one("#watch-summary", Static).update(
            f"{stats.total_events} observations   {attention} need attention   "
            f"{stats.completed_investigations} investigations   ${stats.cost_usd:.4f}"
        )
        selected_events = events[:30]
        self.query_one("#activity-label", Static).update("Recent activity / original observations")
        activity = self.query_one("#overview-events", OptionList)
        self.query_one("#activity-empty").display = not selected_events
        activity.display = bool(selected_events)
        signature = tuple((str(item.id), item.model_dump_json()) for item in selected_events)
        if signature != self._activity_signature:
            previous = None
            if activity.highlighted is not None and activity.option_count:
                previous = activity.get_option_at_index(activity.highlighted).id
            activity.clear_options()
            for item in selected_events:
                stamp = item.observed_at.astimezone().strftime("%H:%M:%S")
                prompt = Text(f"{stamp}  {item.severity.value.upper()}  ")
                prompt.append(safe_text(item.target or "local"))
                prompt.append("\n" + safe_text(item.title), style="bold")
                prompt.append("\n" + safe_text(item.summary))
                activity.add_option(Option(prompt, id=str(item.id)))
            if previous in {str(item.id) for item in selected_events}:
                activity.highlighted = activity.get_option_index(previous)
            elif selected_events:
                activity.highlighted = 0
            self._activity_signature = signature
        self.query_one("#watch-coverage", Static).update(
            coverage_summary(self.config, app.services.monitor.status.probe_health)
        )
        state = self.query_one("#overview-state", Static)
        if self.startup_warning is not None:
            state.update(safe_text(self.startup_warning))
            state.set_class(True, "error")
        else:
            state.update(_overview_status(app.services.monitor.status, has_events=bool(events)))
            state.remove_class("error")


class DashboardScreen(ResponsiveScreen[None]):
    """Inline terminal workspace with a shared command prompt."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("slash", "command_prompt", "Commands", show=False),
        Binding("ctrl+k", "command_prompt", "Commands", show=False, priority=True),
        Binding("escape", "overview", "Your watch", show=False),
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
        with Horizontal(id="topbar"):
            yield Static(f"socketclaw [dim]{__version__}[/]", id="brand")
            yield Static("", id="run-state", markup=False)
        with ContentSwitcher(initial="overview-view", id="workspace"):
            yield OverviewView(self.config, startup_warning=self._startup_warning)
            yield EventsView()
            yield HostsView()
            yield InvestigationsView()
            yield SettingsView()
        yield CommandBar()

    def on_mount(self) -> None:
        self.set_class(self.size.width < 90, "narrow")
        self.refresh_run_state()
        if self._monitor_error is not None:
            self.show_monitor_error(self._monitor_error)
        self.set_interval(1.0, self.refresh_run_state)
        self.set_interval(0.25, self._refresh_dirty_views)
        self.set_interval(5, self._resync_evidence)
        self._consume_events()
        self.call_after_refresh(self._focus_view, "overview-view")

    def on_resize(self, event: Resize) -> None:
        self.set_class(event.size.width < 90, "narrow")

    def show_view(self, view_id: str) -> None:
        if view_id not in _VIEWS:
            return
        self.query_one("#workspace", ContentSwitcher).current = view_id
        self.call_after_refresh(self._focus_view, view_id)
        if view_id == "overview-view":
            self.query_one(OverviewView).refresh_data()
        elif view_id == "events-view":
            self.query_one(EventsView).refresh_data()
        elif view_id == "investigations-view":
            self.query_one(InvestigationsView).refresh_data()

    def _focus_view(self, view_id: str) -> None:
        if view_id == "hosts-view":
            self.query_one(HostsView).focus_workspace()
        else:
            target = self.query_one(_FOCUS_TARGETS[view_id])
            if view_id == "overview-view" and not target.display:
                target = self.query_one("#overview-state")
            target.focus()
            target.scroll_visible(animate=False)
            if view_id == "settings-view":
                scroll = self.query_one("#settings-scroll", VerticalScroll)
                self.call_after_refresh(scroll.scroll_home, animate=False)

    def action_command_prompt(self) -> None:
        self.query_one(CommandBar).activate()

    def action_overview(self) -> None:
        self.show_view("overview-view")

    @on(CommandBar.Cancelled)
    def cancel_command(self) -> None:
        self._focus_view(self._current_view)

    @on(CommandBar.Submitted)
    async def run_command(self, event: CommandBar.Submitted) -> None:
        app = socketclaw_app(self)
        value = event.value.lower()
        destinations = {
            "/overview": "overview-view",
            "/events": "events-view",
            "/hosts": "hosts-view",
            "/investigations": "investigations-view",
            "/settings": "settings-view",
        }
        if value in destinations:
            self.show_view(destinations[value])
        elif value == "/logs":
            await app.action_log_status()
        elif value == "/pause":
            await app.action_toggle_monitor()
        elif value == "/quit":
            await app.action_quit()
        elif value.startswith("/theme "):
            selected = value.removeprefix("/theme ")
            if selected in {"light", "dark", "terminal"}:
                await app.set_appearance(selected)
        elif value in {"/help", "/health", "/rules", "/incidents", "/maintenance"}:
            {
                "/help": app.action_help,
                "/health": app.action_health,
                "/rules": app.action_rules,
                "/incidents": app.action_incidents,
                "/maintenance": app.action_maintenance,
            }[value]()
        else:
            self.query_one("#command-hint", Static).update("Unknown command. Type / to browse.")
        if app.screen is self and self.query_one("#command-input", Input).has_focus:
            self.cancel_command()

    def apply_config(self, config: AppConfig) -> None:
        self.config = config
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

    def _resync_evidence(self) -> None:
        # Queue delivery is only a hint. Periodic DB reads recover dropped notifications.
        if not self.is_mounted or socketclaw_app(self).screen is not self:
            return
        if self._current_view == "overview-view":
            self.query_one(OverviewView).refresh_data()
        elif self._current_view == "events-view":
            self.query_one(EventsView).resync_live()

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
