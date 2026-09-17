from datetime import UTC, datetime

import pytest
from textual.widgets import DataTable, Markdown

from socketclaw.health import ProbeHealth
from socketclaw.ui.detail import DetailScreen
from socketclaw.ui.health import HealthScreen


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 36), (160, 48)])
async def test_health_reader_retains_selection_and_exposes_scheduling(app_factory, size) -> None:
    fixture = app_factory(configured=True)
    fixture.monitor.health_records = (
        ProbeHealth(
            probe_id="logs",
            interval_seconds=1,
            state="degraded",
            error_kind="read_error",
            error="Permission denied",
            consecutive_errors=4,
        ),
        ProbeHealth(
            probe_id="ports:gateway.local",
            interval_seconds=60,
            state="healthy",
            last_success_at=datetime(2026, 7, 27, tzinfo=UTC),
            lag_ms=125,
            duration_ms=1500,
            skipped_ticks=2,
        ),
    )
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.press("h")
        await pilot.pause()
        assert isinstance(fixture.app.screen, HealthScreen)
        table = fixture.app.screen.query_one("#health-table", DataTable)
        assert table.row_count == 2
        assert table.size.height >= 3
        await pilot.press("down", "enter")
        await pilot.pause()
        assert isinstance(fixture.app.screen, DetailScreen)
        body = fixture.app.screen.query_one("#full-detail-body", Markdown)
        assert r"ports:gateway\.local" in body.source
        assert "125.0 ms" in body.source
        assert "Skipped ticks: 2" in body.source
        await pilot.press("escape")
        assert isinstance(fixture.app.screen, HealthScreen)
        assert table.cursor_row == 1
        fixture.app.screen.refresh_health()
        assert table.cursor_row == 1
        await pilot.press("escape")
        assert not isinstance(fixture.app.screen, HealthScreen)


async def test_health_is_available_from_command_palette(app_factory) -> None:
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("ctrl+p")
        await pilot.press(*"Health")
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(fixture.app.screen, HealthScreen)
