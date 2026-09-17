"""A terminal prompt with a command menu that participates in layout."""

from dataclasses import dataclass

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Key
from textual.message import Message
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

COMMANDS = (
    ("/overview", "Return to your watch"),
    ("/events", "Browse observations"),
    ("/hosts", "Manage watched hosts"),
    ("/logs", "Manage log sources"),
    ("/incidents", "Review incidents"),
    ("/investigations", "Read AI investigations"),
    ("/settings", "Edit configuration"),
    ("/health", "Check collection health"),
    ("/rules", "Edit detection rules"),
    ("/theme terminal", "Use your terminal colors"),
    ("/theme light", "Light appearance"),
    ("/theme dark", "Dark appearance"),
    ("/pause", "Pause or resume monitoring"),
    ("/help", "Keyboard reference"),
    ("/quit", "End this session"),
)


class CommandBar(Vertical):
    @dataclass
    class Submitted(Message):
        value: str

    class Cancelled(Message):
        pass

    def __init__(self) -> None:
        super().__init__(id="command-bar")
        self.matches: list[str] = []

    def compose(self) -> ComposeResult:
        yield OptionList(id="command-menu")
        with Horizontal(id="command-line"):
            yield Static(">", id="command-marker")
            yield Input(placeholder="/ for commands", id="command-input", select_on_focus=False)
        yield Static("/ commands   1-5 views   ctrl+t theme   ctrl+c quit", id="command-hint")

    def on_mount(self) -> None:
        self.query_one("#command-menu").display = False

    def activate(self) -> None:
        field = self.query_one(Input)
        field.value = "/"
        field.focus()
        field.cursor_position = 1

    @on(Input.Changed)
    def changed(self, event: Input.Changed) -> None:
        value = event.value.strip().lower()
        menu = self.query_one(OptionList)
        matching = [(name, description) for name, description in COMMANDS if name.startswith(value)]
        self.matches = [name for name, _ in matching] if value.startswith("/") else []
        menu.clear_options()
        if self.matches:
            for name, description in matching:
                prompt = Text(name, style="bold")
                prompt.append(f"  {description}")
                menu.add_option(Option(prompt, id=name))
            menu.highlighted = 0
        menu.display = bool(self.matches) and self.query_one(Input).has_focus

    def on_key(self, event: Key) -> None:
        field = self.query_one(Input)
        if not field.has_focus:
            return
        menu = self.query_one(OptionList)
        if event.key == "escape":
            field.value = ""
            menu.display = False
            self.post_message(self.Cancelled())
        elif menu.display and event.key in {"up", "down", "tab"}:
            if event.key == "tab":
                field.value = self.matches[menu.highlighted or 0]
                field.cursor_position = len(field.value)
            else:
                direction = -1 if event.key == "up" else 1
                menu.highlighted = ((menu.highlighted or 0) + direction) % len(self.matches)
                menu.scroll_to_highlight()
        else:
            return
        event.stop()
        event.prevent_default()

    @on(Input.Submitted)
    def submit(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        menu = self.query_one(OptionList)
        if self.matches and value not in self.matches:
            value = self.matches[menu.highlighted or 0]
        self._submit(value)
        event.stop()

    @on(OptionList.OptionSelected)
    def selected(self, event: OptionList.OptionSelected) -> None:
        self._submit(event.option.id or "")
        event.stop()

    def _submit(self, value: str) -> None:
        self.query_one(Input).value = ""
        self.query_one(OptionList).display = False
        if value:
            self.post_message(self.Submitted(value))
