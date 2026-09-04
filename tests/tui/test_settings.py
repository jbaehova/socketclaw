from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Input, Select, Static

from socketclaw.config import AppConfig


@pytest.mark.asyncio
async def test_settings_preserves_luna_and_atomically_saves(
    app_factory: Callable[..., Any],
) -> None:
    reconfigured: list[AppConfig] = []

    async def reconfigure(config: AppConfig) -> None:
        reconfigured.append(config)

    fixture = app_factory(configured=True, reconfigure=reconfigure)

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("5")
        fixture.app.screen.query_one("#settings-targets", Input).value = "1.1.1.1, 8.8.8.8"
        fixture.app.screen.query_one("#settings-ping", Input).value = "10"
        fixture.app.screen.query_one("#settings-scan", Input).value = "120"
        fixture.app.screen.query_one("#settings-ports", Input).value = "22, 443, 8443"
        fixture.app.screen.query_one(
            "#settings-log-paths", Input
        ).value = "/var/log/auth.log, /var/log/system.log"
        fixture.app.screen.query_one("#settings-theme", Select).value = "textual-light"
        await pilot.click("#save-settings")
        await pilot.pause(0.2)

        assert fixture.app.config.model == "luna"
        saved = fixture.store.load()
        assert saved.model == "luna"
        assert saved.targets == ["1.1.1.1", "8.8.8.8"]
        assert saved.ports == [22, 443, 8443]
        assert saved.log_paths == ["/var/log/auth.log", "/var/log/system.log"]
        assert saved.theme == "textual-light"
        assert fixture.app.theme == "socketclaw-light"
        assert reconfigured == [saved]
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
        key.value = "sk-proj-replacement"
        await pilot.click("#save-settings")
        await pilot.pause(0.3)

        assert seen == ["sk-proj-replacement"]
        assert fixture.store.load_api_key() == "sk-proj-replacement"
        assert "sk-proj-replacement" not in str(
            fixture.app.screen.query_one("#settings-state", Static).render()
        )


@pytest.mark.asyncio
async def test_first_key_and_config_are_rolled_back_when_reconfigure_fails(
    app_factory: Callable[..., Any],
) -> None:
    async def reject_reconfigure(_config: AppConfig) -> None:
        raise RuntimeError("monitor rejected configuration")

    fixture = app_factory(configured=True, reconfigure=reject_reconfigure)
    fixture.store.clear_api_key()
    original = fixture.store.load()

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("5")
        fixture.app.screen.query_one("#settings-targets", Input).value = "8.8.8.8"
        fixture.app.screen.query_one("#settings-api-key", Input).value = "sk-proj-first"
        await pilot.click("#save-settings")
        await pilot.pause(0.3)

        assert fixture.store.load() == original
        assert fixture.store.load_api_key() is None
        assert fixture.app.config == original
        state = fixture.app.screen.query_one("#settings-state", Static)
        assert "not saved" in str(state.render()).lower()


@pytest.mark.asyncio
async def test_every_settings_field_scrolls_fully_above_the_footer_at_80x24(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True)

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("5")
        scroll = fixture.app.screen.query_one("#settings-scroll", VerticalScroll)
        footer = fixture.app.screen.query_one("#settings-footer", Vertical)

        for selector in (
            "#settings-targets",
            "#settings-ping",
            "#settings-scan",
            "#settings-ports",
            "#settings-log-paths",
            "#settings-api-key",
            "#settings-theme",
        ):
            field = fixture.app.screen.query_one(selector)
            field.focus()
            await pilot.pause(0.1)
            assert field.region.y >= scroll.content_region.y
            assert field.region.bottom <= scroll.content_region.bottom
            assert field.region.bottom <= footer.region.y


@pytest.mark.asyncio
async def test_cancelled_reconfigure_rolls_back_file_app_and_runtime_plan(
    app_factory: Callable[..., Any],
) -> None:
    started = asyncio.Event()
    restored: list[AppConfig] = []

    async def reconfigure(config: AppConfig) -> None:
        if config.targets == ["8.8.8.8"]:
            started.set()
            await asyncio.Future()
        restored.append(config)

    fixture = app_factory(configured=True, reconfigure=reconfigure)
    original = fixture.store.load()
    updated = original.model_copy(update={"targets": ["8.8.8.8"]})

    async with fixture.app.run_test(size=(80, 24)):
        task = asyncio.create_task(fixture.app.save_config(updated))
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert fixture.store.load() == original
        assert fixture.app.config == original
        assert restored == [original]


@pytest.mark.asyncio
async def test_concurrent_disjoint_config_mutations_preserve_both_updates(
    app_factory: Callable[..., Any],
) -> None:
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    runtime_configs: list[AppConfig] = []

    async def reconfigure(config: AppConfig) -> None:
        runtime_configs.append(config)
        if config.ping_interval == 10 and config.targets == ["1.1.1.1"]:
            first_started.set()
            await release_first.wait()

    fixture = app_factory(configured=True, reconfigure=reconfigure)

    async with fixture.app.run_test(size=(80, 24)):
        settings_task = asyncio.create_task(
            fixture.app.update_config(
                lambda current: current.model_copy(update={"ping_interval": 10})
            )
        )
        await asyncio.wait_for(first_started.wait(), timeout=1.0)
        hosts_task = asyncio.create_task(
            fixture.app.update_config(
                lambda current: current.model_copy(
                    update={"targets": [*current.targets, "8.8.8.8"]}
                )
            )
        )
        release_first.set()
        await asyncio.gather(settings_task, hosts_task)

        assert fixture.app.config.ping_interval == 10
        assert fixture.app.config.targets == ["1.1.1.1", "8.8.8.8"]
        assert fixture.store.load() == fixture.app.config
        assert runtime_configs[-1] == fixture.app.config


@pytest.mark.asyncio
async def test_socketclaw_theme_aliases_apply_real_registered_palette(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True, config=AppConfig(theme="textual-dark"))

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)

        assert fixture.app.theme == "socketclaw-dark"
        assert fixture.app.current_theme.background == "#0a0f18"


@pytest.mark.asyncio
async def test_supported_nonstandard_theme_is_preserved_in_settings(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True, config=AppConfig(theme="nord"))

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        assert fixture.app.theme == "nord"
        await pilot.press("5")
        theme = fixture.app.screen.query_one("#settings-theme", Select)
        assert theme.value == "nord"


@pytest.mark.asyncio
async def test_unknown_theme_falls_back_visibly_without_crashing(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True, config=AppConfig(theme="missing-theme"))

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        assert fixture.app.theme == "socketclaw-dark"
        await pilot.press("5")
        state = fixture.app.screen.query_one("#settings-state", Static)
        assert "unavailable" in str(state.render()).lower()
