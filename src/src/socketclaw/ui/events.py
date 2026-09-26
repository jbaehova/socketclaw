"""Filterable observation timeline and event detail workspace."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import cast
from uuid import UUID

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Markdown, Select, Static

from ..domain import EventSource, SecurityEvent, Severity
from ..storage import EventQuery, StoredEvent
from .context import safe_text, socketclaw_app
from .detail import DetailScreen, event_detail_markdown
from .event_filters import HistoryFilters


class EventsView(Vertical):
    """Repository-backed events table with explainable evidence detail."""

    def __init__(self) -> None:
        super().__init__(id="events-view", classes="workspace-view")
        self.events: list[StoredEvent] = []
        self._selected_id: UUID | None = None
        self._investigating = False
        self._exporting = False
        self.live = True
        self.pending_count = 0
        self._dirty = False
        self._rendering_rows = False
        self._page_cursors: list[int | None] = [None]
        self._watermark: int | None = None
        self._has_more = False
        self._advanced: dict[str, str] = {}

    def _controls_available(self) -> bool:
        return self.is_mounted and all(
            self.query(f"#{identifier}")
            for identifier in (
                "event-search",
                "event-severity",
                "event-source",
                "events-state",
                "events-table",
                "event-detail",
                "investigate-event",
                "export-event",
                "events-prev",
                "events-next",
            )
        )

    def compose(self) -> ComposeResult:
        yield Static("EVENTS / LOCAL EVIDENCE", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Observation timeline", classes="view-title")
            yield Static("C critical  A all  I investigate  E export", classes="view-hint")
        with Horizontal(classes="filter-row"):
            yield Input(placeholder="Search title, target, or summary", id="event-search")
            yield Select(
                [("All severities", "all")]
                + [(item.value.title(), item.value) for item in Severity],
                value="all",
                allow_blank=False,
                id="event-severity",
            )
            yield Select(
                [("All sources", "all")]
                + [(item.value.replace("_", " ").title(), item.value) for item in EventSource],
                value="all",
                allow_blank=False,
                id="event-source",
            )
        yield Static(
            "Loading local event history…",
            id="events-state",
            classes="inline-state",
            markup=False,
        )
        with Horizontal(classes="split-workspace"):
            yield DataTable(
                id="events-table",
                cursor_type="row",
                zebra_stripes=True,
            )
            yield Markdown(
                "Select an event to inspect its evidence.",
                id="event-detail",
                open_links=False,
            )
        with Horizontal(classes="action-row"):
            yield Button(
                "Investigate",
                id="investigate-event",
                variant="primary",
                disabled=True,
            )
            yield Button("AI preview", id="preview-investigation")
            yield Button("Export .md", id="export-event", disabled=True)
            yield Button("Live", id="events-live")
            yield Button("Incidents", id="open-incidents")
        with Horizontal(classes="pagination-row"):
            yield Button("Filters", id="events-filters")
            yield Button("Previous", id="events-prev", disabled=True)
            yield Button("Older", id="events-next", disabled=True)

    @on(Button.Pressed, "#open-incidents")
    def open_incidents(self) -> None:
        socketclaw_app(self).action_incidents()

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one("#events-table", DataTable))
        table.add_columns("TIME", "SEV", "SOURCE", "TARGET", "EVENT")
        self.refresh_data()

    @work(exclusive=True, group="events-load")
    async def refresh_data(self) -> None:
        if not self._controls_available():
            return
        if not self.live and self.events:
            return
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            self._show_state("Event storage is unavailable.", error=True)
            return
        severity_value = _select_value(
            cast(Select[object], self.query_one("#event-severity", Select))
        )
        source_value = _select_value(cast(Select[object], self.query_one("#event-source", Select)))
        search = self.query_one("#event-search", Input).value.strip()
        try:
            self.events = await repository.list_events(
                EventQuery(
                    severity=(Severity(str(severity_value)) if severity_value != "all" else None),
                    source=(EventSource(str(source_value)) if source_value != "all" else None),
                    text=search or None,
                    target=self._advanced.get("target") or None,
                    event_type=self._advanced.get("event_type") or None,
                    after=datetime.fromisoformat(self._advanced["after"])
                    if self._advanced.get("after")
                    else None,
                    before=datetime.fromisoformat(self._advanced["before"])
                    if self._advanced.get("before")
                    else None,
                    limit=101,
                    watermark=self._watermark,
                    before_seq=self._page_cursors[-1],
                )
            )
        except Exception as exc:
            self._show_state(f"Could not load events: {exc}", error=True)
            return
        self._has_more = len(self.events) > 100
        self.events = self.events[:100]
        if self._watermark is None and self.events:
            self._watermark = max((item.ingest_seq or 0) for item in self.events) or None
        if self._controls_available():
            self.query_one("#events-prev", Button).disabled = len(self._page_cursors) == 1
            self.query_one("#events-next", Button).disabled = not self._has_more
            self._render_rows()

    @on(Button.Pressed, "#events-filters")
    def advanced_filters(self) -> None:
        def apply(values: dict[str, str] | None) -> None:
            if values is not None:
                self._advanced = values
                self.filters_changed()

        socketclaw_app(self).push_screen(HistoryFilters(self._advanced), apply)

    def set_critical_filter(self) -> None:
        self.query_one("#event-severity", Select).value = Severity.CRITICAL.value

    def clear_filters(self) -> None:
        self._advanced = {}
        self.query_one("#event-search", Input).value = ""
        self.query_one("#event-severity", Select).value = "all"
        self.query_one("#event-source", Select).value = "all"

    def add_live_event(self, _event: SecurityEvent) -> None:
        self.pending_count += 1
        self._dirty = True

    def resync_live(self) -> None:
        if self.live and len(self._page_cursors) == 1:
            self._watermark = None
            self.refresh_data()

    def refresh_live(self) -> None:
        if not self._dirty:
            return
        if not self.live or len(self._page_cursors) > 1:
            self._show_state(
                f"Reading held / {self.pending_count} new observation(s). Choose Live to catch up."
            )
            return
        self._dirty = False
        self.pending_count = 0
        self._watermark = None
        self.refresh_data()

    @on(Button.Pressed, "#events-live")
    def return_to_live(self) -> None:
        self.live = True
        self._page_cursors = [None]
        self._watermark = None
        self.pending_count = 0
        self._dirty = False
        self.refresh_data()

    @on(Button.Pressed, "#events-next")
    def older_page(self) -> None:
        if self.events and self._has_more and self.events[-1].ingest_seq is not None:
            self._page_cursors.append(self.events[-1].ingest_seq)
            self.live = True
            self.refresh_data()

    def _hold_page(self) -> None:
        self.live = False

    @on(Button.Pressed, "#events-prev")
    def newer_page(self) -> None:
        if len(self._page_cursors) > 1:
            self._page_cursors.pop()
            self.live = True
            self.refresh_data()

    def selected_event(self) -> StoredEvent | None:
        if self._selected_id is not None:
            selected = next(
                (event for event in self.events if event.id == self._selected_id),
                None,
            )
            if selected is not None:
                return selected
        return self.events[0] if self.events else None

    def investigate_selected(self) -> None:
        if self._investigating:
            return
        event = self.selected_event()
        if event is None:
            self._show_state("Select an event before starting an investigation.")
            return
        self._investigating = True
        self._investigate(event.id)

    @work(exclusive=True, group="event-investigation")
    async def _investigate(self, event_id: UUID) -> None:
        if not self._controls_available():
            self._investigating = False
            return
        button = self.query_one("#investigate-event", Button)
        self._investigating = True
        button.disabled = True
        self._show_state("Investigating with GPT-5.6 Luna on OpenAI…")
        try:
            app = socketclaw_app(self)
            await app.investigate_event(event_id)
        except Exception as exc:
            self._show_state(f"Investigation failed: {exc}", error=True)
        else:
            self._show_state("Investigation complete. Open workspace 4 for the report.")
        finally:
            self._investigating = False
            self._refresh_actions()

    @on(Button.Pressed, "#preview-investigation")
    @work(exclusive=True, group="investigation-preview")
    async def preview_investigation(self) -> None:
        event = self.selected_event()
        if event is None:
            self._show_state("Select an observation to preview shared evidence.")
            return
        try:
            app = socketclaw_app(self)
            context = await app.investigation_context(event.id)
            key = app.config_store.load_api_key()
            content = context.preview(secrets=(key,) if key else ())
            if self._controls_available():
                app.push_screen(
                    DetailScreen(
                        "## AI transmission preview\n\nLocal evidence stays unchanged. "
                        "Credentials are redacted; addresses and accounts remain for correlation. "
                        "Review the exact bounded context before pressing Investigate.\n\n"
                        + "\n".join("    " + line for line in content.splitlines())
                    )
                )
        except Exception as exc:
            self._show_state(f"Cannot preview evidence: {exc}", error=True)

    def export_selected(self) -> None:
        if self._exporting:
            return
        event = self.selected_event()
        if event is None:
            self._show_state("Select an event before exporting.")
            return
        self._exporting = True
        self._export(event.id)

    @work(exclusive=True, group="event-export")
    async def _export(self, event_id: UUID) -> None:
        if not self._controls_available():
            self._exporting = False
            return
        button = self.query_one("#export-event", Button)
        self._exporting = True
        button.disabled = True
        try:
            app = socketclaw_app(self)
            destination = await app.export_event(event_id)
        except Exception as exc:
            self._show_state(f"Export failed: {exc}", error=True)
        else:
            self._show_state(f"Exported safely to {destination}")
        finally:
            self._exporting = False
            self._refresh_actions()

    @on(Input.Changed, "#event-search")
    @on(Select.Changed, "#event-severity")
    @on(Select.Changed, "#event-source")
    def filters_changed(self) -> None:
        self._page_cursors = [None]
        self._watermark = None
        self.live = True
        self.pending_count = 0
        self._reload_filters()

    @work(exclusive=True, group="event-filter-debounce")
    async def _reload_filters(self) -> None:
        await asyncio.sleep(0.2)
        if self._controls_available():
            self.refresh_data()

    @on(DataTable.RowSelected, "#events-table")
    def open_detail(self) -> None:
        event = self.selected_event()
        if event is not None:
            self.live = False
            self._open_detail(event)

    @work(exclusive=True, group="event-detail-open")
    async def _open_detail(self, event: StoredEvent) -> None:
        app = socketclaw_app(self)
        screen = app.screen
        try:
            repository = app.services.repository
            decisions = (
                await repository.incidents.suppression_decisions(event.id)
                if repository and repository.incidents
                else []
            )
        except Exception as exc:
            self._show_state(f"Cannot open evidence: {exc}", error=True)
            return
        if app.screen is screen:
            app.push_screen(DetailScreen(event_detail_markdown(event, decisions)))

    @on(DataTable.RowHighlighted, "#events-table")
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_rows:
            return
        try:
            self._selected_id = UUID(str(event.row_key.value))
            if self.events and self._selected_id != self.events[0].id:
                self.live = False
        except (TypeError, ValueError):
            self._selected_id = None
        self._render_detail()

    @on(Button.Pressed, "#investigate-event")
    def investigate_button(self) -> None:
        self.investigate_selected()

    @on(Button.Pressed, "#export-event")
    def export_button(self) -> None:
        self.export_selected()

    def _render_rows(self) -> None:
        table = cast(DataTable[str], self.query_one("#events-table", DataTable))
        previous_selection = self._selected_id
        self._rendering_rows = True
        self.call_after_refresh(self._finish_rendering)
        table.clear()
        for event in self.events:
            table.add_row(
                event.observed_at.astimezone().strftime("%H:%M:%S"),
                event.severity.value.upper(),
                event.source.value,
                safe_text(event.target or "-"),
                safe_text(event.title),
                key=str(event.id),
            )
        if not self.events:
            self._selected_id = None
            self.query_one("#event-detail", Markdown).update(
                "No event is selected. Adjust the filters or wait for a new probe result."
            )
            self._show_state("No events match the current filters.")
            self._refresh_actions()
            return
        event_ids = {event.id for event in self.events}
        self._selected_id = (
            previous_selection if previous_selection in event_ids else self.events[0].id
        )
        table.move_cursor(row=table.get_row_index(str(self._selected_id)))
        severity = _select_value(cast(Select[object], self.query_one("#event-severity", Select)))
        source = _select_value(cast(Select[object], self.query_one("#event-source", Select)))
        needle = self.query_one("#event-search", Input).value
        self._show_state(
            f"{len(self.events)} event(s) / Page {len(self._page_cursors)} / "
            f"Severity: {severity} / Source: {source} / Search: {needle or 'all'}"
            + (
                "\n"
                + " / ".join(f"{key}: {value}" for key, value in self._advanced.items() if value)
                if any(self._advanced.values())
                else ""
            )
        )
        self._render_detail()
        self._refresh_actions()

    def _finish_rendering(self) -> None:
        self._rendering_rows = False

    def _render_detail(self) -> None:
        event = self.selected_event()
        if event is None:
            self.query_one("#event-detail", Markdown).update("No event is selected.")
            return
        content = event_detail_markdown(event)
        detail = self.query_one("#event-detail", Markdown)
        if detail.source != content:
            detail.update(content)
        self._render_exceptions(event)

    @work(exclusive=True, group="event-preview-exceptions")
    async def _render_exceptions(self, event: StoredEvent) -> None:
        repository = socketclaw_app(self).services.repository
        if not repository or not repository.incidents:
            return
        try:
            decisions = await repository.incidents.suppression_decisions(event.id)
        except Exception:
            return  # Full reader reports failures; the raw preview remains usable.
        if self._controls_available() and decisions and self._selected_id == event.id:
            self.query_one("#event-detail", Markdown).update(
                event_detail_markdown(event, decisions)
            )

    def _refresh_actions(self) -> None:
        if not self._controls_available():
            return
        has_selection = self.selected_event() is not None
        self.query_one("#investigate-event", Button).disabled = (
            not has_selection or self._investigating
        )
        self.query_one("#export-event", Button).disabled = not has_selection or self._exporting

    def _show_state(self, message: str, *, error: bool = False) -> None:
        if not self._controls_available():
            return
        state = self.query_one("#events-state", Static)
        state.update(safe_text(message))
        state.set_class(error, "error")


def _select_value(widget: Select[object]) -> str:
    value = widget.value
    if not isinstance(value, str):
        raise ValueError("a filter selection is required")
    return value
