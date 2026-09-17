"""Small modal dialogs shared across the SocketClaw TUI."""

from __future__ import annotations

from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ..storage import ResponseStatus, StoredResponseProposal
from .context import safe_text


class ResponseReview(VerticalScroll, can_focus=True):
    """Scrollable review area that reports deliberate traversal to its end."""

    class ReachedEnd(Message):
        """Posted when the operator reaches the end of the review."""

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        if new_value >= self.max_scroll_y:
            self.post_message(self.ReachedEnd())


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
                "[b]Enter[/b] Open detail  [b]Esc[/b] Return to your list\n"
                "[b]L[/b] Log source progress and read errors\n"
                "[b]H[/b] Collection health and scheduling\n"
                "[b]R[/b] Run diagnostic  [b]I[/b] Investigate event\n"
                "[b]E[/b] Export incident  [b]?[/b] Help  [b]Q[/b] Quit",
                id="help-copy",
            )
            yield Button("Close", id="help-close", variant="primary")

    def action_close_help(self) -> None:
        self.dismiss(None)

    def on_mount(self) -> None:
        self.query_one("#help-close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss(None)


class ConfirmResponseScreen(ModalScreen[bool]):
    """Require a deliberate confirmation before approval or execution."""

    response_transition: ResponseStatus

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("end", "review_end", "Review end", show=False),
    ]

    def __init__(
        self,
        proposal: StoredResponseProposal,
        transition: ResponseStatus,
    ) -> None:
        super().__init__()
        self.proposal = proposal
        self.response_transition = transition

    def compose(self) -> ComposeResult:
        proposal = self.proposal.proposal
        target = safe_text(proposal.target_ip or "No network target")
        platform = _single_line(proposal.platform or "Not specified")
        command = safe_text(proposal.command or "No command proposed")
        reason = safe_text(proposal.reason)
        action = safe_text(proposal.action)
        verb = _transition_verb(self.response_transition)
        with Vertical(id="response-dialog"):
            yield Static("RESPONSE CONTROL", classes="dialog-kicker")
            yield Static(
                f"{verb} {action} response?",
                id="response-title",
                markup=False,
            )
            with ResponseReview(id="response-review"):
                yield Static(
                    f"Target              {target}\n"
                    f"State               {self.proposal.status.upper()} → "
                    f"{self.response_transition.upper()}\n"
                    f"Platform            {platform}\n"
                    f"Reversible          {'yes' if proposal.reversible else 'no'}\n"
                    f"Requires approval   {'yes' if proposal.requires_approval else 'no'}",
                    id="response-copy",
                    markup=False,
                )
                yield Static("REASON", classes="response-section-label")
                yield Static(
                    _review_body(reason),
                    id="response-reason",
                    classes="response-model-content",
                    markup=False,
                )
                yield Static("PROPOSED COMMAND", classes="response-section-label")
                yield Static(
                    _review_body(command),
                    id="response-command",
                    classes="response-model-content",
                    markup=False,
                )
                yield Static(
                    "SocketClaw records this transition locally. Execution remains "
                    "separate from approval.",
                    id="response-disclaimer",
                    markup=False,
                )
            with Horizontal(id="response-dialog-actions"):
                yield Button("Cancel", id="cancel-response")
                yield Button(
                    f"Confirm {verb.lower()}",
                    id="confirm-response",
                    variant="warning",
                    disabled=True,
                )

    def on_mount(self) -> None:
        self.query_one("#cancel-response", Button).focus()
        self.call_after_refresh(self._sync_review_gate)

    @on(ResponseReview.ReachedEnd)
    def reviewed_to_end(self) -> None:
        self._sync_review_gate()

    def action_review_end(self) -> None:
        self.query_one("#response-review", ResponseReview).scroll_end(animate=False)
        self.call_after_refresh(self._sync_review_gate)

    def _sync_review_gate(self) -> None:
        review = self.query_one("#response-review", ResponseReview)
        button = self.query_one("#confirm-response", Button)
        reviewed = review.max_scroll_y == 0 or review.is_vertical_scroll_end
        button.disabled = not reviewed
        button.label = (
            f"Confirm {_transition_verb(self.response_transition).lower()}"
            if reviewed
            else "Review to end"
        )

    def action_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#cancel-response")
    def cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#confirm-response")
    def confirm(self) -> None:
        self.dismiss(True)


def _transition_verb(transition: ResponseStatus) -> str:
    return {
        "approved": "Approve",
        "rejected": "Reject",
        "pending": "Reset",
    }[transition]


def _single_line(value: str) -> str:
    return " ".join(safe_text(value).splitlines())


def _review_body(value: str) -> str:
    return "\n".join(f"  {line}" for line in safe_text(value).splitlines()) or "  None"


class ConfirmTargetRemovalScreen(ModalScreen[bool]):
    """Confirm a monitoring gap before removing a watch target."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = safe_text(target)

    def compose(self) -> ComposeResult:
        with Vertical(id="target-removal-dialog"):
            yield Static("MONITORING CHANGE", classes="dialog-kicker")
            yield Static("Remove watch target?", id="target-removal-title")
            yield Static(
                f"{self.target}\n\nNew events from this target will no longer be collected.",
                id="target-removal-copy",
                markup=False,
            )
            with Horizontal(id="target-removal-actions"):
                yield Button("Keep target", id="cancel-target-removal")
                yield Button(
                    "Remove target",
                    id="confirm-target-removal",
                    variant="error",
                )

    def on_mount(self) -> None:
        self.query_one("#cancel-target-removal", Button).focus()

    def action_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#cancel-target-removal")
    def cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#confirm-target-removal")
    def confirm(self) -> None:
        self.dismiss(True)


class SettingsConflictScreen(ModalScreen[str]):
    """Resolve an overlapping edit using the loaded, saved, and draft values."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    SettingsConflictScreen { background: $surface; layout: vertical; padding: 1; }
    SettingsConflictScreen > VerticalScroll { height: 1fr; }
    SettingsConflictScreen > Horizontal { height: auto; }
    SettingsConflictScreen Button { min-width: 16; margin-right: 1; }
    """

    def __init__(self, comparison: str) -> None:
        super().__init__()
        self.comparison = comparison

    def compose(self) -> ComposeResult:
        with VerticalScroll(can_focus=True):
            yield Static("These settings changed while you were editing.", markup=False)
            yield Static(safe_text(self.comparison), markup=False)
        with Horizontal():
            yield Button("Cancel", id="conflict-cancel")
            yield Button("Use saved", id="conflict-saved")
            yield Button("Keep my changes", id="conflict-draft", variant="primary")

    def action_cancel(self) -> None:
        self.dismiss("cancel")

    @on(Button.Pressed)
    def resolve(self, event: Button.Pressed) -> None:
        self.dismiss((event.button.id or "conflict-cancel").removeprefix("conflict-"))
