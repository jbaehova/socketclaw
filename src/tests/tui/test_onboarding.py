from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Button, Input, Static

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
        assert await pilot.click("#onboarding-next", offset=(2, 1))
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
    reconfigured: list[AppConfig] = []

    async def reconfigure(config: AppConfig) -> None:
        reconfigured.append(config)

    fixture = app_factory(configured=False, reconfigure=reconfigure)

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
        assert reconfigured == [saved]


@pytest.mark.asyncio
async def test_saved_configuration_opens_dashboard_without_an_api_key(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)
    existing = AppConfig(
        targets=["gateway.local", "10.0.0.5"],
        ping_interval=15,
        scan_interval=180,
        ports=[22, 8443],
        log_paths=["/var/log/auth.log"],
        theme="textual-light",
    )
    fixture.store.save(existing)

    async with fixture.app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(fixture.app.screen, DashboardScreen)
        assert fixture.app.config == existing
        assert fixture.app.theme == "socketclaw-light"
        assert fixture.monitor.running is True
        assert fixture.store.load_api_key() is None


@pytest.mark.asyncio
async def test_onboarding_can_skip_openai_and_stays_complete_after_restart(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=False)

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.click("#onboarding-next")
        await pilot.pause(0.1)
        assert fixture.app.screen.current_step == 1
        await pilot.click("#onboarding-skip")
        await pilot.pause(0.1)
        assert fixture.app.screen.current_step == 2
        await pilot.click("#onboarding-next")
        await pilot.pause(0.1)
        assert fixture.app.screen.current_step == 3
        assert "Local monitoring only" in str(
            fixture.app.screen.query_one("#onboarding-summary", Static).render()
        )
        assert fixture.app.screen.query_one("#onboarding-next", Button).disabled is False
        assert await pilot.click("#onboarding-next", offset=(2, 1))
        for _ in range(30):
            if isinstance(fixture.app.screen, DashboardScreen):
                break
            await asyncio.sleep(0.1)

        assert isinstance(fixture.app.screen, DashboardScreen), (
            str(fixture.app.screen.query_one("#onboarding-error", Static).render()),
            fixture.store.config_path.exists(),
            fixture.monitor.started,
        )
        assert fixture.store.config_path.exists()
        assert fixture.store.load_api_key() is None
        assert fixture.monitor.running is True
