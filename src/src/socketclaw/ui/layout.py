"""Shared terminal-size rules for workspaces and readers."""

from typing import TypeVar

from textual.events import DescendantFocus, Resize
from textual.screen import ModalScreen, Screen

Result = TypeVar("Result")


def reflow(screen: Screen[Result], width: int, height: int) -> None:
    screen.set_class(width < 90, "narrow")
    screen.set_class(width < 64, "tiny")
    screen.set_class(height < 25, "short")
    focused = screen.focused
    if focused is not None:
        screen.call_after_refresh(focused.scroll_visible, animate=False)


class ResponsiveScreen(Screen[Result]):
    def on_descendant_focus(self, event: DescendantFocus) -> None:
        self.call_after_refresh(event.widget.scroll_visible, animate=False)

    def on_resize(self, event: Resize) -> None:
        reflow(self, event.size.width, event.size.height)


class ResponsiveModalScreen(ModalScreen[Result]):
    def on_descendant_focus(self, event: DescendantFocus) -> None:
        self.call_after_refresh(event.widget.scroll_visible, animate=False)

    def on_resize(self, event: Resize) -> None:
        reflow(self, event.size.width, event.size.height)
