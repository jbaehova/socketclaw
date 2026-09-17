"""Verify editing and command navigation across actual terminal sizes."""

import pytest
from textual.containers import VerticalScroll
from textual.widgets import ContentSwitcher, Input, OptionList, Select

from socketclaw.config import AppConfig


def assert_exposed(screen, widget):
    region = widget.region
    assert region.width > 0 and region.height > 0
    x, y = region.x + min(2, region.width - 1), region.y
    hit, _ = screen.get_widget_at(x, y)
    assert hit is widget or widget in hit.ancestors, (widget.id, region, hit)


@pytest.mark.parametrize("size", [(40, 16), (60, 20), (80, 24), (120, 36)])
async def test_settings_fields_and_prompt_remain_reachable(app_factory, size):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.press("5")
        await pilot.pause()
        screen = fixture.app.screen
        scroll = screen.query_one("#settings-scroll", VerticalScroll)
        for selector in (
            "#settings-targets",
            "#settings-ping",
            "#settings-scan",
            "#settings-ports",
            "#settings-log-paths",
            "#settings-api-key",
            "#settings-theme",
        ):
            field = screen.query_one(selector)
            field.focus()
            await pilot.pause()
            assert field.region.y >= scroll.content_region.y
            assert field.region.bottom <= scroll.content_region.bottom
            assert_exposed(screen, field)
        assert_exposed(screen, screen.query_one("#save-settings"))
        assert_exposed(screen, screen.query_one("#command-input"))


async def test_resize_preserves_focused_input_and_draft(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.press("5")
        field = fixture.app.screen.query_one("#settings-log-paths", Input)
        field.focus()
        field.value = "/tmp/unsaved-draft.log"
        for size in ((40, 16), (60, 20), (120, 36)):
            await pilot.resize_terminal(*size)
            await pilot.pause()
            assert fixture.app.focused is field
            assert field.value == "/tmp/unsaved-draft.log"
            assert_exposed(fixture.app.screen, field)


async def test_command_menu_navigates_and_never_covers_prompt(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(60, 20)) as pilot:
        await pilot.press("slash")
        await pilot.pause()
        screen = fixture.app.screen
        field = screen.query_one("#command-input", Input)
        menu = screen.query_one("#command-menu", OptionList)
        assert fixture.app.focused is field
        assert menu.display
        assert menu.region.bottom <= field.region.y
        assert_exposed(screen, field)
        await pilot.press("e", "v", "e", "n", "t", "s", "enter")
        await pilot.pause()
        assert screen.query_one("#workspace", ContentSwitcher).current == "events-view"
        assert not menu.display
        await pilot.press("slash", "escape")
        assert not menu.display
        assert fixture.app.focused.id == "events-table"


async def test_theme_command_and_toggle_persist_without_losing_drafts(app_factory):
    fixture = app_factory(configured=True, config=AppConfig(theme="terminal"))
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("slash")
        field = fixture.app.screen.query_one("#command-input", Input)
        field.value = "/theme light"
        await pilot.press("enter")
        await pilot.pause()
        assert fixture.app.theme == "socketclaw-light"
        assert fixture.store.load().theme == "socketclaw-light"
        await pilot.press("5")
        targets = fixture.app.screen.query_one("#settings-targets", Input)
        targets.value = "draft.example"
        await pilot.press("ctrl+t")
        await pilot.pause()
        assert fixture.app.theme == "socketclaw-dark"
        assert targets.value == "draft.example"


@pytest.mark.parametrize("size", [(40, 16), (60, 20), (80, 24)])
async def test_onboarding_inputs_and_actions_do_not_overlap(app_factory, size):
    fixture = app_factory(configured=False)
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.press("enter")
        await pilot.pause()
        screen = fixture.app.screen
        assert_exposed(screen, screen.query_one("#api-key"))
        await pilot.click("#onboarding-skip")
        await pilot.pause()
        for selector in (
            "#onboarding-targets",
            "#onboarding-ping-interval",
            "#onboarding-scan-interval",
        ):
            field = screen.query_one(selector, Input)
            field.focus()
            await pilot.pause()
            assert_exposed(screen, field)
        assert_exposed(screen, screen.query_one("#onboarding-next"))
        await pilot.press("ctrl+t")
        assert not fixture.store.config_path.exists()


async def test_light_select_menu_is_usable_near_bottom_of_scroll(app_factory):
    fixture = app_factory(configured=True, config=AppConfig(theme="socketclaw-light"))
    async with fixture.app.run_test(size=(40, 16)) as pilot:
        await pilot.press("5")
        field = fixture.app.screen.query_one("#settings-theme", Select)
        field.focus()
        await pilot.pause()
        await pilot.press("enter", "home", "enter")
        await pilot.pause()
        assert not field.expanded
        assert_exposed(fixture.app.screen, field)


async def test_command_menu_keyboard_completion_from_a_form(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(60, 20)) as pilot:
        await pilot.press("5", "ctrl+k")
        field = fixture.app.screen.query_one("#command-input", Input)
        assert fixture.app.focused is field
        await pilot.press("down", "tab")
        assert field.value == "/events"
        assert fixture.app.focused is field
        await pilot.press("enter")
        await pilot.pause()
        assert fixture.app.screen.query_one("#workspace", ContentSwitcher).current == "events-view"
