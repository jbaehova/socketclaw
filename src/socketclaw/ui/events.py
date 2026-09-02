"""Filterable incident timeline and event detail workspace."""

from __future__ import annotations

from typing import cast
from uuid import UUID

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Markdown, Select, Static

from ..domain import EventSource, SecurityEvent, Severity
from ..storage import EventQuery, StoredEvent
from .context import socketclaw_app


class EventsView(Vertical):
    """Repository-backed events table with explainable evidence detail."""

    def __init__(self) -> None:
        super().__init__(id="events-view", classes="workspace-view")
        self.events: list[StoredEvent] = []
        self._selected_id: UUID | None = None

    def compose(self) -> ComposeResult:
        yield Static("EVENTS / LOCAL EVIDENCE", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Incident timeline", classes="view-title")
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
        yield Static("Loading local event history…", id="events-state", classes="inline-state")
        with Horizontal(classes="split-workspace"):
            yield DataTable(
                id="events-table",
                cursor_type="row",
                zebra_stripes=True,
            )
            yield Markdown("Select an event to inspect its evidence.", id="event-detail")
        with Horizontal(classes="action-row"):
            yield Button("Investigate", id="investigate-event", variant="primary")
            yield Button("Export .md", id="export-event")

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one("#events-table", DataTable))
        table.add_columns("TIME", "SEV", "SOURCE", "TARGET", "EVENT")
        self.refresh_data()

    @work(exclusive=True, group="events-load")
    async def refresh_data(self) -> None:
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
                    limit=500,
                )
            )
        except Exception as exc:
            self._show_state(f"Could not load events: {exc}", error=True)
            return
        self._render_rows()

    def set_critical_filter(self) -> None:
        self.query_one("#event-severity", Select).value = Severity.CRITICAL.value

    def clear_filters(self) -> None:
        self.query_one("#event-search", Input).value = ""
        self.query_one("#event-severity", Select).value = "all"
        self.query_one("#event-source", Select).value = "all"

    def add_live_event(self, _event: SecurityEvent) -> None:
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
        event = self.selected_event()
        if event is None:
            self._show_state("Select an event before starting an investigation.")
            return
        self._investigate(event.id)

    @work(exclusive=True, group="event-investigation")
    async def _investigate(self, event_id: UUID) -> None:
        button = self.query_one("#investigate-event", Button)
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
            button.disabled = False

    def export_selected(self) -> None:
        event = self.selected_event()
        if event is None:
            self._show_state("Select an event before exporting.")
            return
        self._export(event.id)

    @work(exclusive=True, group="event-export")
    async def _export(self, event_id: UUID) -> None:
        button = self.query_one("#export-event", Button)
        button.disabled = True
        try:
            app = socketclaw_app(self)
            destination = await app.export_event(event_id)
        except Exception as exc:
            self._show_state(f"Export failed: {exc}", error=True)
        else:
            self._show_state(f"Exported safely to {destination}")
        finally:
            button.disabled = False

    @on(Input.Changed, "#event-search")
    @on(Select.Changed, "#event-severity")
    @on(Select.Changed, "#event-source")
    def filters_changed(self) -> None:
        self.refresh_data()

    @on(DataTable.RowHighlighted, "#events-table")
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            self._selected_id = UUID(str(event.row_key.value))
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
        table.clear()
        for event in self.events:
            table.add_row(
                event.observed_at.astimezone().strftime("%H:%M:%S"),
                event.severity.value.upper(),
                event.source.value,
                event.target or "-",
                event.title,
                key=str(event.id),
            )
        if not self.events:
            self._selected_id = None
            self.query_one("#event-detail", Markdown).update(
                "No event is selected. Adjust the filters or wait for a new probe result."
            )
            self._show_state("No events match the current filters.")
            return
        self._selected_id = self.events[0].id
        table.move_cursor(row=0)
        self._show_state(f"{len(self.events)} event(s) in the current view.")
        self._render_detail()

    def _render_detail(self) -> None:
        event = self.selected_event()
        if event is None:
            return
        signals = (
            "\n".join(
                f"- **{signal.label}** `+{signal.points}` - {signal.detail}"
                for signal in event.signals
            )
            or "- No deterministic signals were recorded."
        )
        self.query_one("#event-detail", Markdown).update(
            f"## {event.title}\n\n"
            f"**{event.severity.value.upper()} / {event.score}/100**  \n"
            f"`{event.event_type}` / `{event.target or 'no target'}`  \n"
            f"{event.observed_at.astimezone().isoformat(timespec='seconds')}\n\n"
            f"{event.summary}\n\n### Detection signals\n\n{signals}\n\n"
            f"### Evidence\n\n```json\n{event.model_dump_json(indent=2)}\n```"
        )

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#events-state", Static)
        state.update(message)
        state.set_class(error, "error")


def _select_value(widget: Select[object]) -> str:
    value = widget.value
    if not isinstance(value, str):
        raise ValueError("a filter selection is required")
    return value
