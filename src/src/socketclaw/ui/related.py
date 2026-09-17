"""Read an incident's exact linked observations without losing the incident."""

from __future__ import annotations

from typing import ClassVar, cast
from uuid import UUID

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static

from ..storage import RelatedObservation
from .context import safe_text, socketclaw_app
from .detail import DetailScreen, event_detail_markdown


class RelatedObservations(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back to incident")]
    DEFAULT_CSS = """
    RelatedObservations { background: $background; padding: 1 2; }
    #related-title { height: 2; text-style: bold; }
    #related-state { height: 2; color: $text-muted; }
    #related-table { height: 1fr; }
    #related-actions { height: 3; margin-top: 1; align-horizontal: right; }
    #related-actions Button { min-width: 11; width: auto; margin-left: 1; }
    """

    def __init__(self, identifier: UUID) -> None:
        super().__init__()
        self.identifier = identifier
        self.watermark: int | None = None
        self.boundaries: list[int | None] = [None]
        self.next_before: int | None = None
        self.items: dict[str, RelatedObservation] = {}

    def compose(self) -> ComposeResult:
        yield Static("RELATED OBSERVATIONS / Enter Open / Esc Back", id="related-title")
        yield Static("Loading observations…", id="related-state", markup=False)
        yield DataTable(id="related-table", cursor_type="row")
        with Horizontal(id="related-actions"):
            yield Button("Previous", id="related-prev", disabled=True)
            yield Button("Next", id="related-next", disabled=True)
            yield Button("Refresh", id="related-refresh")
            yield Button("Open", id="related-open", variant="primary", disabled=True)
            yield Button("Back", id="related-back")

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one(DataTable))
        for label, width in (("TIME", 17), ("SEVERITY", 8), ("RELATION", 9), ("OBSERVATION", 32)):
            table.add_column(label, width=width)
        table.focus()
        self.load_page()

    def action_close(self) -> None:
        self.dismiss(None)

    @work(exclusive=True, group="related-page")
    async def load_page(self) -> None:
        repository = socketclaw_app(self).services.repository
        if repository is None:
            return
        try:
            page = await repository.incident_observations(
                self.identifier, watermark=self.watermark, before=self.boundaries[-1]
            )
        except Exception as exc:
            self.query_one("#related-state", Static).update(
                safe_text(f"Cannot load observations: {exc}")
            )
            return
        self.watermark = page.watermark
        self.next_before = page.next_before
        self.items = {str(item.event.id): item for item in page.items}
        table = cast(DataTable[str], self.query_one(DataTable))
        table.clear()
        for item in page.items:
            event = item.event
            table.add_row(
                event.observed_at.astimezone().strftime("%d %b %H:%M:%S"),
                event.severity.value.upper(),
                "Recovery" if item.link.kind == "observed_recovery" else "Anomaly",
                safe_text(event.title),
                key=str(event.id),
            )
        self.query_one("#related-state", Static).update(
            f"Page {len(self.boundaries)} / {len(page.items)} observations / "
            + ("More available" if page.has_more else "End of history")
            + ". Refresh includes new observations."
        )
        self.query_one("#related-prev", Button).disabled = len(self.boundaries) == 1
        self.query_one("#related-next", Button).disabled = not page.has_more
        self.query_one("#related-open", Button).disabled = not page.items

    @on(Button.Pressed)
    def button(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "related-prev":
                if len(self.boundaries) > 1:
                    self.boundaries.pop()
                    self.load_page()
            case "related-next":
                if self.next_before is not None:
                    self.boundaries.append(self.next_before)
                    self.load_page()
            case "related-refresh":
                self.watermark = None
                self.boundaries = [None]
                self.load_page()
            case "related-open":
                self.open_selected()
            case "related-back":
                self.action_close()
            case _:
                pass

    @on(DataTable.RowSelected)
    def open_selected(self) -> None:
        table = cast(DataTable[str], self.query_one(DataTable))
        if table.row_count:
            key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
            self.open_observation(UUID(key))

    @work(exclusive=True, group="related-detail")
    async def open_observation(self, identifier: UUID) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            return
        try:
            event = await repository.get_event(identifier)
            decisions = (
                await repository.incidents.suppression_decisions(identifier)
                if repository.incidents
                else []
            )
            if event is None:
                raise ValueError("Observation is no longer available")
        except Exception as exc:
            self.query_one("#related-state", Static).update(safe_text(str(exc)))
            return
        app.push_screen(DetailScreen(event_detail_markdown(event, decisions)))
