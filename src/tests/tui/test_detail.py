from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Markdown, OptionList

from socketclaw.ui.detail import DetailScreen

from .conftest import event_fixture, investigation_fixture


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 36), (160, 48)])
@pytest.mark.parametrize("workspace", ["2", "4"])
async def test_enter_opens_full_detail_and_escape_restores_selection(
    app_factory: Callable[..., Any], size: tuple[int, int], workspace: str
) -> None:
    events = [event_fixture(title=f"Evidence {i}") for i in range(30)]
    fixture = app_factory(
        configured=True,
        events=events,
        investigations=[investigation_fixture(event.id) for event in events],
    )
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.pause()
        await pilot.press(workspace)
        await pilot.pause()
        dashboard = fixture.app.screen
        table = dashboard.query_one(
            "#events-table" if workspace == "2" else "#investigations-table", DataTable
        )
        table.move_cursor(row=20)
        await pilot.pause()
        scroll_y = table.scroll_y
        await pilot.press("enter")
        assert isinstance(fixture.app.screen, DetailScreen)
        assert fixture.app.screen.query_one("#full-detail-body", Markdown).source
        reader = fixture.app.screen.query_one("#full-detail-scroll", VerticalScroll)
        assert reader.region.height > 0
        await pilot.resize_terminal(80, 24)
        await pilot.press("end")
        await pilot.press("escape")
        assert fixture.app.screen is dashboard
        assert table.cursor_row == 20
        assert table.scroll_y == scroll_y
        assert fixture.app.focused is table


async def test_overview_keeps_recent_activity_visible_despite_old_high_scores(
    app_factory: Callable[..., Any],
) -> None:
    critical = event_fixture(title="Older critical event", severity="critical")
    fixture = app_factory(
        configured=True,
        events=[event_fixture(severity="info") for _ in range(101)] + [critical],
    )
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        table = fixture.app.screen.query_one("#overview-events", OptionList)
        assert table.option_count == 30
        assert "Older critical event" not in str(table.get_option_at_index(0).prompt)
        table.focus()
        await pilot.press("enter")
        assert isinstance(fixture.app.screen, DetailScreen)
        assert (
            "Repeated SSH authentication failures"
            in fixture.app.screen.query_one("#full-detail-body", Markdown).source
        )
        await pilot.press("escape")
        assert fixture.app.focused is table
