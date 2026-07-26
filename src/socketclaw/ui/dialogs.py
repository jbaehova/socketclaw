"""Small modal dialogs shared across the SocketClaw TUI."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class HelpScreen(ModalScreen[None]):
    """Keyboard-first product help."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("question_mark", "dismiss", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static("SOCKETCLAW / KEYBOARD", id="help-title")
            yield Static(
                "[b]1-5[/b]  Switch workspace\n"
                "[b]Space[/b] Pause or resume monitoring\n"
                "[b]Ctrl+P[/b] Open command palette\n"
                "[b]R[/b] Run diagnostic  [b]I[/b] Investigate event\n"
                "[b]E[/b] Export incident  [b]?[/b] Help  [b]Q[/b] Quit",
                id="help-copy",
            )
            yield Button("Close", id="help-close", variant="primary")

    def action_dismiss(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss(None)
