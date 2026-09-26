"""Compact advanced history filters, usable independently of terminal width."""

from __future__ import annotations

from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Input, Static

from .layout import ResponsiveModalScreen


class HistoryFilters(ResponsiveModalScreen[dict[str, str] | None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back")]
    DEFAULT_CSS = """
    HistoryFilters { background: $background; layout: vertical; padding: 0 2; }
    HistoryFilters VerticalScroll { height: 1fr; }
    HistoryFilters Static { height: auto; margin-top: 1; }
    HistoryFilters Input { margin-bottom: 1; }
    """

    def __init__(self, values: dict[str, str]) -> None:
        super().__init__()
        self.values = values

    def compose(self) -> ComposeResult:
        yield Static("SEARCH ALL RETAINED HISTORY / clear a field to remove its condition")
        with VerticalScroll():
            for key, label in (
                ("target", "Asset / exact target"),
                ("event_type", "Event kind / exact value, e.g. service.result"),
                ("after", "Start time / ISO date-time with timezone"),
                ("before", "End time / ISO date-time with timezone"),
            ):
                yield Static(label)
                yield Input(value=self.values.get(key, ""), id=f"history-{key}")
        with Horizontal(classes="action-row"):
            yield Button("Apply filters", id="history-apply", variant="primary")
            yield Button("Clear advanced", id="history-clear")
            yield Button("Back", id="history-close")

    @on(Button.Pressed, "#history-apply")
    def apply(self) -> None:
        self.dismiss(
            {
                key: self.query_one(f"#history-{key}", Input).value.strip()
                for key in ("target", "event_type", "after", "before")
            }
        )

    @on(Button.Pressed, "#history-clear")
    def clear(self) -> None:
        self.dismiss({})

    @on(Button.Pressed, "#history-close")
    def action_close(self) -> None:
        self.dismiss(None)
