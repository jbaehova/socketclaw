"""Typed access to the concrete SocketClaw app from nested Textual widgets."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from textual.widget import Widget

if TYPE_CHECKING:
    from .app import SocketClawApp


def socketclaw_app(widget: Widget) -> SocketClawApp:
    """Narrow Textual's generic app property to this product's app type."""
    return cast("SocketClawApp", widget.app)  # pyright: ignore[reportUnknownMemberType]
