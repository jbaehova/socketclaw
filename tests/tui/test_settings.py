from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Input, Select, Static


@pytest.mark.asyncio
async def test_settings_select_qwen_and_atomically_save(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("5")
        fixture.app.screen.query_one("#model", Select).value = "qwen"
        fixture.app.screen.query_one("#settings-targets", Input).value = "1.1.1.1, 8.8.8.8"
        fixture.app.screen.query_one("#settings-ping", Input).value = "10"
        fixture.app.screen.query_one("#settings-scan", Input).value = "120"
        fixture.app.screen.query_one("#threshold", Select).value = "critical"
        fixture.app.screen.query_one("#response-mode", Select).value = "simulation"
        await pilot.click("#save-settings")
        await pilot.pause(0.2)

        assert fixture.app.config.model == "qwen"
        saved = fixture.store.load()
        assert saved.model == "qwen"
        assert saved.targets == ["1.1.1.1", "8.8.8.8"]
        assert saved.investigation_threshold == "critical"
        assert saved.response_mode == "simulation"
        assert "Saved" in str(fixture.app.screen.query_one("#settings-state", Static).render())


@pytest.mark.asyncio
async def test_api_key_replacement_is_masked_validated_and_never_rendered(
    app_factory: Callable[..., Any],
) -> None:
    seen: list[str] = []

    async def validate(key: str):
        seen.append(key)
        from .conftest import valid_key

        return await valid_key(key)

    fixture = app_factory(configured=True, validator=validate)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("5")
        key = fixture.app.screen.query_one("#settings-api-key", Input)
        assert key.password is True
        key.value = "sk-or-v1-replacement"
        await pilot.click("#save-settings")
        await pilot.pause(0.3)

        assert seen == ["sk-or-v1-replacement"]
        assert fixture.store.load_api_key() == "sk-or-v1-replacement"
        assert "sk-or-v1-replacement" not in str(
            fixture.app.screen.query_one("#settings-state", Static).render()
        )
