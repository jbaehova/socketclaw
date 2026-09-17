from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from .conftest import event_fixture, investigation_fixture


@dataclass(frozen=True, slots=True)
class VisualCase:
    name: str
    size: tuple[int, int]
    configured: bool
    keys: tuple[str, ...] = ()


VISUAL_CASES = tuple(
    VisualCase(
        name=f"{state}-{width}x{height}",
        size=(width, height),
        configured=state != "onboarding",
        keys=(
            ()
            if state in {"onboarding", "overview"}
            else ((key,) if state == "settings" else (key, "_"))
        ),
    )
    for width, height in ((80, 24), (120, 36))
    for state, key in (
        ("onboarding", ""),
        ("overview", ""),
        ("events", "2"),
        ("hosts", "3"),
        ("investigations", "4"),
        ("settings", "5"),
    )
)


@pytest.mark.parametrize("case", VISUAL_CASES, ids=lambda case: case.name)
def test_visual_states(
    snap_compare: Callable[..., bool],
    app_factory: Callable[..., Any],
    case: VisualCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLORTERM", "truecolor")
    event = event_fixture()
    fixture = app_factory(
        configured=case.configured,
        events=[event],
        investigations=[investigation_fixture(event.id)],
    )

    assert snap_compare(
        fixture.app,
        terminal_size=case.size,
        press=case.keys,
    )
