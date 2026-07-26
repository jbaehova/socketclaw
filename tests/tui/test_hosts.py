from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import DataTable, Input, Static

from socketclaw.config import AppConfig


@pytest.mark.asyncio
async def test_host_add_remove_validation_and_manual_diagnostic(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(
        configured=True,
        config=AppConfig(targets=["1.1.1.1", "gateway.local"]),
    )

    async with fixture.app.run_test(size=(110, 32)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("3")
        table = fixture.app.screen.query_one("#hosts-table", DataTable)
        assert table.row_count == 2

        target = fixture.app.screen.query_one("#host-target", Input)
        target.value = "bad host!"
        await pilot.click("#add-host")
        await pilot.pause(0.1)
        assert (
            "invalid" in str(fixture.app.screen.query_one("#hosts-state", Static).render()).lower()
        )

        target.value = "8.8.8.8"
        await pilot.pause(0.2)
        await pilot.click("#add-host")
        await pilot.pause(0.2)
        assert fixture.store.load().targets == [
            "1.1.1.1",
            "gateway.local",
            "8.8.8.8",
        ]
        assert table.row_count == 3

        table.move_cursor(row=2)
        await pilot.click("#ping-host")
        await pilot.pause(0.2)
        assert fixture.monitor.diagnostics[-1] == ("ping", "8.8.8.8")

        await pilot.click("#remove-host")
        await pilot.pause(0.2)
        assert "8.8.8.8" not in fixture.store.load().targets
        assert table.row_count == 2
