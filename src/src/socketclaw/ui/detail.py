"""A full-screen reader for the same content shown in the detail pane."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Markdown, Static

from ..incidents import SuppressionDecision
from ..storage import StoredEvent
from .context import escape_markdown, indented_code


class DetailScreen(ModalScreen[None]):
    """Keep the underlying selection and scroll intact while reading evidence."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back to list")]
    DEFAULT_CSS = """
    DetailScreen { background: $surface; layout: vertical; }
    DetailScreen > Static { height: 1; padding: 0 1; color: $text-muted; }
    DetailScreen > VerticalScroll { height: 1fr; padding: 0 1; }
    DetailScreen Markdown { height: auto; }
    DetailScreen > Button { height: 3; margin: 0 1; }
    """

    def __init__(self, content: str) -> None:
        super().__init__()
        self.content = content

    def compose(self) -> ComposeResult:
        yield Static("DETAIL / Esc returns to your place in the list")
        with VerticalScroll(id="full-detail-scroll", can_focus=True):
            yield Markdown(self.content, id="full-detail-body", open_links=False)
        yield Button("Back to list", id="close-detail", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#full-detail-scroll").focus()

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#close-detail")
    def close_button(self) -> None:
        self.action_close()


def event_detail_markdown(
    event: StoredEvent, suppressions: Sequence[SuppressionDecision] = ()
) -> str:
    signals = (
        "\n".join(
            f"- **{escape_markdown(signal.label)}** `+{signal.points}` - "
            f"{escape_markdown(signal.detail)}"
            for signal in event.signals
        )
        or "- No deterministic signals were recorded."
    )
    evidence = indented_code(event.model_dump_json(indent=2))
    return (
        f"## {escape_markdown(event.title)}\n\n"
        f"**{event.severity.value.upper()} / {event.score}/100**  \n"
        f"{escape_markdown(event.event_type)} / "
        f"{escape_markdown(event.target or 'no target')}  \n"
        f"{event.observed_at.astimezone().isoformat(timespec='seconds')}\n\n"
        f"{escape_markdown(event.summary)}\n\n### Detection signals\n\n{signals}\n\n"
        f"### Evidence\n\n{evidence}" + suppression_markdown(suppressions)
    )


def suppression_markdown(decisions: Sequence[SuppressionDecision]) -> str:
    if not decisions:
        return ""
    return (
        "\n\n### Maintenance exceptions\n\n"
        "Original score preserved. Incident creation was limited.\n\n"
        + "\n\n".join(
            f"**{escape_markdown(item.reason)}**  \n"
            f"Expires {item.expires_at.astimezone().isoformat(timespec='minutes')}  \n"
            f"Rules: {escape_markdown(', '.join(item.rule_codes))}"
            for item in decisions
        )
    )
