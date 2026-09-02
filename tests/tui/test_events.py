from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import DataTable, Input, Markdown, Static

from .conftest import event_fixture


@pytest.mark.asyncio
async def test_filter_select_investigate_export_and_live_insert(
    app_factory: Callable[..., Any],
) -> None:
    critical = event_fixture()
    informational = event_fixture(
        title="Routine reachability check",
        severity="info",
        source="ping",
        event_type="ping.result",
    )
    fixture = app_factory(
        configured=True,
        events=[critical, informational],
    )

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        await pilot.pause(0.2)
        table = fixture.app.screen.query_one("#events-table", DataTable)
        assert table.row_count == 2

        await pilot.press("c")
        await pilot.pause(0.2)
        assert table.row_count == 1
        assert "Repeated SSH" in fixture.app.screen.query_one("#event-detail", Markdown).source

        await pilot.press("i")
        await pilot.pause(0.3)
        assert fixture.repository.investigations_data[0].event_id == critical.id

        await pilot.press("e")
        await pilot.pause(0.2)
        exports = list((fixture.store.home / "exports").glob("*.md"))
        assert len(exports) == 1
        assert "sk-proj-configured" not in exports[0].read_text()

        live = event_fixture(title="Live DNS anomaly", severity="high")
        await fixture.monitor.publish(live)
        await pilot.pause(0.3)
        await pilot.press("a")
        await pilot.pause(0.2)
        assert table.row_count == 3


@pytest.mark.asyncio
async def test_event_text_filter_and_empty_state(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True, events=[event_fixture()])

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        search = fixture.app.screen.query_one("#event-search", Input)
        search.value = "does-not-exist"
        await pilot.pause(0.3)

        assert fixture.app.screen.query_one("#events-table", DataTable).row_count == 0
        assert "No events match" in str(
            fixture.app.screen.query_one("#events-state", Static).render()
        )
