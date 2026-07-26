"""Small modal dialogs shared across the SocketClaw TUI."""

from __future__ import annotations

from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ..storage import ResponseStatus, StoredResponseProposal


class HelpScreen(ModalScreen[None]):
    """Keyboard-first product help."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close_help", "Close", show=False),
        Binding("question_mark", "close_help", "Close", show=False),
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

    def action_close_help(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss(None)


class ConfirmResponseScreen(ModalScreen[bool]):
    """Require a deliberate confirmation before approval or execution."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(
        self,
        proposal: StoredResponseProposal,
        transition: ResponseStatus,
    ) -> None:
        super().__init__()
        self.proposal = proposal
        self.transition = transition

    def compose(self) -> ComposeResult:
        target = self.proposal.proposal.target_ip or "No network target"
        with Vertical(id="response-dialog"):
            yield Static("RESPONSE CONTROL", classes="dialog-kicker")
            yield Static(
                f"{self.transition.title()} {self.proposal.proposal.action} response?",
                id="response-title",
            )
            yield Static(
                f"Target  {target}\n"
                f"State   {self.proposal.status.upper()} → {self.transition.upper()}\n\n"
                f"{self.proposal.proposal.reason}\n\n"
                "SocketClaw records this transition locally. Execution remains "
                "separate from approval.",
                id="response-copy",
            )
            with Vertical(id="response-dialog-actions"):
                yield Button("Cancel", id="cancel-response")
                yield Button(
                    f"Confirm {self.transition}",
                    id="confirm-response",
                    variant="warning",
                )

    def action_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#cancel-response")
    def cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#confirm-response")
    def confirm(self) -> None:
        self.dismiss(True)
