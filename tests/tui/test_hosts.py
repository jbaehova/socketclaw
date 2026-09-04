from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Button, DataTable, Input, Static

from socketclaw.config import AppConfig
from socketclaw.ui.dialogs import ConfirmTargetRemovalScreen


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
        assert isinstance(fixture.app.screen, ConfirmTargetRemovalScreen)
        await pilot.click("#confirm-target-removal")
        await pilot.pause(0.2)
    assert "8.8.8.8" not in fixture.store.load().targets
    assert table.row_count == 2


@pytest.mark.asyncio
async def test_unavailable_ping_is_disabled_and_context_retry_is_explained(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)
    fixture.monitor.available_diagnostics = frozenset({"ports"})

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("3")
        await pilot.pause(0.1)

        ping = fixture.app.screen.query_one("#ping-host", Button)
        assert ping.disabled is True
        assert str(ping.label) == "Ping unavailable"

        await pilot.press("r")
        await pilot.pause(0.1)
        state = fixture.app.screen.query_one("#hosts-state", Static)
        assert "unavailable" in str(state.render()).lower()
        assert fixture.monitor.diagnostics == []
