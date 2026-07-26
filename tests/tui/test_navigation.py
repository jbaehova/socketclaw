from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.command import CommandPalette
from textual.widgets import ContentSwitcher

from socketclaw.ui.dashboard import DashboardScreen
from socketclaw.ui.dialogs import HelpScreen


@pytest.mark.asyncio
async def test_direct_navigation_and_pause_binding(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)

    async with fixture.app.run_test(size=(110, 32)) as pilot:
        await pilot.pause()
        assert isinstance(fixture.app.screen, DashboardScreen)
        switcher = fixture.app.screen.query_one("#workspace", ContentSwitcher)
        assert switcher.current == "overview-view"

        await pilot.press("2")
        assert switcher.current == "events-view"
        await pilot.press("5")
        assert switcher.current == "settings-view"
        await pilot.press("1")
        assert switcher.current == "overview-view"

        await pilot.press("space")
        assert fixture.monitor.paused is True
        assert "PAUSED" in str(fixture.app.screen.query_one("#run-state").render())
        await pilot.press("space")
        assert fixture.monitor.paused is False


@pytest.mark.asyncio
async def test_help_and_command_palette_are_keyboard_accessible(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        assert isinstance(fixture.app.screen, HelpScreen)
        await pilot.press("escape")
        assert isinstance(fixture.app.screen, DashboardScreen)

        await pilot.press("ctrl+p")
        assert isinstance(fixture.app.screen, CommandPalette)
        await pilot.press("escape")
        assert isinstance(fixture.app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_quit_stops_monitor_and_exits_cleanly(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert fixture.monitor.running is True
        await pilot.press("q")

    assert fixture.monitor.stopped == 1
    assert fixture.monitor.running is False
