"""Typed access to the concrete SocketClaw app from nested Textual widgets."""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, cast

from textual.widget import Widget

if TYPE_CHECKING:
    from .app import SocketClawApp


def socketclaw_app(widget: Widget) -> SocketClawApp:
    """Narrow Textual's generic app property to this product's app type."""
    return cast("SocketClawApp", widget.app)  # pyright: ignore[reportUnknownMemberType]


_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+.!|>~-])")
_UNSAFE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def safe_text(value: str) -> str:
    """Strip terminal and Unicode format controls while preserving whitespace."""
    normalized = (
        value.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\u2028", "\n")
        .replace("\u2029", "\n")
        .replace("\t", "    ")
    )
    without_controls = _UNSAFE_CONTROL.sub("", normalized)
    return "".join(
        character for character in without_controls if unicodedata.category(character) != "Cf"
    )


def escape_markdown(value: str) -> str:
    """Render untrusted evidence as text inside a Markdown document."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", safe_text(value))


def indented_code(value: str) -> str:
    """Render arbitrary text as a Markdown code block without fence injection."""
    return "\n".join(f"    {line}" for line in safe_text(value).splitlines())
