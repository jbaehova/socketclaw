from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Input, Select, Static

from socketclaw.openrouter import ErrorKind, OpenRouterError
from socketclaw.ui.dashboard import DashboardScreen
from socketclaw.ui.onboarding import OnboardingScreen


@pytest.mark.asyncio
async def test_first_run_opens_onboarding_and_masks_key(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(fixture.app.screen, OnboardingScreen)
        await pilot.click("#onboarding-next")
        key = fixture.app.screen.query_one("#api-key", Input)
        assert key.password is True
        await pilot.click("#api-key")
        await pilot.press(*"sk-or-v1-test")
        assert key.value == "sk-or-v1-test"
        assert "sk-or-v1-test" not in str(
            fixture.app.screen.query_one("#onboarding-error", Static).render()
        )


@pytest.mark.asyncio
async def test_invalid_key_stays_on_key_step_with_safe_message(
    app_factory: Callable[..., Any],
) -> None:
    async def invalid(_key: str):
        raise OpenRouterError(
            ErrorKind.AUTHENTICATION,
            "Invalid API key [REDACTED]",
            status_code=401,
        )

    fixture = app_factory(configured=False, validator=invalid)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        fixture.app.screen.query_one("#api-key", Input).value = "sk-or-v1-bad"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)

        assert isinstance(fixture.app.screen, OnboardingScreen)
        assert fixture.app.screen.current_step == 1
        error = fixture.app.screen.query_one("#onboarding-error", Static)
        assert "Invalid API key" in str(error.render())
        assert "sk-or-v1-bad" not in str(error.render())
        assert not fixture.store.env_path.exists()


@pytest.mark.asyncio
async def test_onboarding_saves_qwen_targets_and_enters_dashboard(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        fixture.app.screen.query_one("#api-key", Input).value = "sk-or-v1-new"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)
        fixture.app.screen.query_one("#onboarding-model", Select).value = "qwen"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        fixture.app.screen.query_one("#onboarding-targets", Input).value = "1.1.1.1, example.com"
        fixture.app.screen.query_one("#onboarding-ping-interval", Input).value = "10"
        fixture.app.screen.query_one("#onboarding-scan-interval", Input).value = "120"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)

        assert isinstance(fixture.app.screen, DashboardScreen)
        assert fixture.store.load_api_key() == "sk-or-v1-new"
        saved = fixture.store.load()
        assert saved.model == "qwen"
        assert saved.preset.effort == "high"
        assert saved.targets == ["1.1.1.1", "example.com"]
        assert saved.ping_interval == 10
        assert saved.scan_interval == 120
        assert fixture.monitor.running is True
