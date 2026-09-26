"""Independent read-only viewer for a home owned by a headless monitor."""

from __future__ import annotations

from typing import ClassVar, cast

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.widgets import DataTable, Footer, Static, TabbedContent, TabPane

from ..domain import utc_now
from ..storage import EventQuery, Repository


class AttachedApp(App[None]):
    """Poll durable watermarks. Closing this app never stops or mutates the collector."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Close viewer"),
        Binding("r", "refresh", "Refresh"),
    ]
    CSS = """
    Screen { layout: vertical; }
    #attached-state { height: auto; padding: 0 1; }
    TabbedContent { height: 1fr; }
    DataTable { height: 1fr; }
    """

    def __init__(self, repository: Repository, probe_ids: list[str]) -> None:
        super().__init__()
        self.repository = repository
        self.probe_ids = probe_ids

    def compose(self) -> ComposeResult:
        yield Static("READ ONLY / Connecting to committed monitor data", id="attached-state")
        with TabbedContent():
            with TabPane("Events"):
                yield DataTable(id="attached-events", cursor_type="row")
            with TabPane("Incidents"):
                yield DataTable(id="attached-incidents", cursor_type="row")
            with TabPane("Health"):
                yield DataTable(id="attached-health", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#attached-events", DataTable).add_columns("TIME", "SEVERITY", "OBSERVATION")
        self.query_one("#attached-incidents", DataTable).add_columns(
            "STATUS", "SEVERITY", "INCIDENT"
        )
        self.query_one("#attached-health", DataTable).add_columns(
            "PROBE", "STATE", "LAST SUCCESS", "DETAIL"
        )
        self.set_interval(2, self.action_refresh)
        self.action_refresh()

    @work(exclusive=True, group="attached-refresh")
    async def action_refresh(self) -> None:
        try:
            events = await self.repository.list_events(EventQuery(limit=100))
            incidents = await self.repository.incidents.list(limit=100)
            health = await self.repository.list_probe_health(self.probe_ids)
        except Exception as exc:
            if self.is_running:
                self.query_one("#attached-state", Static).update(
                    f"READ ONLY / Cannot refresh: {exc}"
                )
            return
        if not self.is_running:
            return
        self._rows(
            "attached-events",
            [
                (
                    str(item.id),
                    [item.observed_at.strftime("%H:%M:%S"), item.severity.value, item.title],
                )
                for item in events
            ],
        )
        self._rows(
            "attached-incidents",
            [
                (str(item.id), [item.status, item.highest_severity.value, item.title])
                for item in incidents
            ],
        )
        self._rows(
            "attached-health",
            [
                (
                    item.probe_id,
                    [
                        item.probe_id,
                        "stale" if item.is_stale(utc_now()) else item.state,
                        item.last_success_at.strftime("%H:%M:%S")
                        if item.last_success_at
                        else "never",
                        item.error or "",
                    ],
                )
                for item in health
            ],
        )
        watermark = max((item.ingest_seq or 0 for item in events), default=0)
        self.query_one("#attached-state", Static).update(
            f"READ ONLY / Refreshed {utc_now().strftime('%H:%M:%S')} UTC / "
            f"DB watermark {watermark} / Latest 100 rows per list"
        )

    def _rows(self, identifier: str, rows: list[tuple[str, list[str]]]) -> None:
        table = cast(DataTable[str], self.query_one(f"#{identifier}", DataTable))
        selected = (
            table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            if table.row_count
            else None
        )
        scroll = table.scroll_y
        table.clear()
        for key, cells in rows:
            table.add_row(*cells, key=key)
        keys = [key for key, _ in rows]
        if selected in keys:
            table.move_cursor(row=keys.index(selected), scroll=False)
        table.scroll_to(y=scroll, animate=False)
