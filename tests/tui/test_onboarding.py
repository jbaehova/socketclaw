from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Input, Static

from socketclaw.config import AppConfig
from socketclaw.openai import ErrorKind, OpenAIError
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
        await pilot.press(*"sk-proj-test")
        assert key.value == "sk-proj-test"
        assert "sk-proj-test" not in str(
            fixture.app.screen.query_one("#onboarding-error", Static).render()
        )


@pytest.mark.asyncio
async def test_invalid_key_stays_on_key_step_with_safe_message(
    app_factory: Callable[..., Any],
) -> None:
    async def invalid(_key: str):
        raise OpenAIError(
            ErrorKind.AUTHENTICATION,
            "Invalid API key [REDACTED]",
            status_code=401,
        )

    fixture = app_factory(configured=False, validator=invalid)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        fixture.app.screen.query_one("#api-key", Input).value = "sk-proj-bad"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)

        assert isinstance(fixture.app.screen, OnboardingScreen)
        assert fixture.app.screen.current_step == 1
        error = fixture.app.screen.query_one("#onboarding-error", Static)
        assert "Invalid API key" in str(error.render())
        assert "sk-proj-bad" not in str(error.render())
        assert not fixture.store.env_path.exists()


@pytest.mark.asyncio
async def test_onboarding_saves_luna_targets_and_enters_dashboard(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        fixture.app.screen.query_one("#api-key", Input).value = "sk-proj-new"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)
        assert fixture.app.screen.current_step == 2
        fixture.app.screen.query_one("#onboarding-targets", Input).value = "1.1.1.1, example.com"
        fixture.app.screen.query_one("#onboarding-ping-interval", Input).value = "10"
        fixture.app.screen.query_one("#onboarding-scan-interval", Input).value = "120"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        assert fixture.app.screen.current_step == 3
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)

        assert isinstance(fixture.app.screen, DashboardScreen)
        assert fixture.store.load_api_key() == "sk-proj-new"
        saved = fixture.store.load()
        assert saved.model == "luna"
        assert saved.preset.reasoning_label == "MEDIUM-HIGH"
        assert saved.targets == ["1.1.1.1", "example.com"]
        assert saved.ping_interval == 10
        assert saved.scan_interval == 120
        assert fixture.monitor.running is True


@pytest.mark.asyncio
async def test_missing_api_key_onboarding_preserves_existing_configuration(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)
    existing = AppConfig(
        targets=["gateway.local", "10.0.0.5"],
        ping_interval=15,
        scan_interval=180,
        ports=[22, 8443],
        log_paths=["/var/log/auth.log"],
        investigation_threshold="medium",
        response_mode="simulation",
        theme="textual-light",
    )
    fixture.store.save(existing)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(fixture.app.screen, OnboardingScreen)
        assert fixture.app.config == existing

        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        assert fixture.app.screen.current_step == 1
        fixture.app.screen.query_one("#api-key", Input).value = "sk-proj-new"
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)
        assert fixture.app.screen.current_step == 2

        assert (
            fixture.app.screen.query_one("#onboarding-targets", Input).value
            == "gateway.local, 10.0.0.5"
        )
        assert fixture.app.screen.query_one("#onboarding-ping-interval", Input).value == "15"
        assert fixture.app.screen.query_one("#onboarding-scan-interval", Input).value == "180"

        await pilot.click("#onboarding-next")
        await pilot.pause(0.2)
        assert fixture.app.screen.current_step == 3
        await pilot.click("#onboarding-next")
        await pilot.pause(0.3)

        assert isinstance(fixture.app.screen, DashboardScreen)
        assert fixture.store.load_api_key() == "sk-proj-new"
        assert fixture.store.load() == existing
