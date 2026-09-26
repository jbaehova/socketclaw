from __future__ import annotations

import pytest
from textual.widgets import Input, Static

from socketclaw.config import AppConfig
from socketclaw.rules import RuleConfig
from socketclaw.ui.rules import RuleSettingsScreen


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 36), (160, 48)])
async def test_rules_editor_applies_policy_and_restores_settings_focus(app_factory, size):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.press("5")
        await pilot.click("#edit-rules")
        assert isinstance(fixture.app.screen, RuleSettingsScreen)
        fixture.app.screen.query_one("#rule-auth_failure_count", Input).value = "3"
        await pilot.click("#apply-rules")
        await pilot.pause()
        assert fixture.store.load().rules.auth_failure_count == 3
        await pilot.press("escape")
        assert fixture.app.focused.id == "edit-rules"
        # An unrelated Settings draft must not reset the separate rule policy.
        await pilot.click("#save-settings")
        await pilot.pause()
        assert fixture.store.load().rules.auth_failure_count == 3


async def test_invalid_rules_keep_saved_config_and_draft(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        fixture.app.action_rules()
        await pilot.pause()
        fixture.app.screen.query_one("#rule-window_seconds", Input).value = "0"
        await pilot.click("#apply-rules")
        await pilot.pause()
        assert fixture.store.load().rules.window_seconds == 300
        assert fixture.app.screen.query_one("#rule-window_seconds", Input).value == "0"
        assert "not saved" in str(fixture.app.screen.query_one("#rule-feedback", Static).render())


async def test_concurrent_rule_edit_conflict_preserves_draft_until_explicit_reload(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        fixture.app.action_rules()
        await pilot.pause()
        fixture.app.screen.query_one("#rule-auth_failure_count", Input).value = "3"
        await fixture.app.save_config(AppConfig(rules=RuleConfig(auth_failure_count=4)))
        await pilot.click("#apply-rules")
        await pilot.pause()
        assert fixture.store.load().rules.auth_failure_count == 4
        assert fixture.app.screen.query_one("#rule-auth_failure_count", Input).value == "3"
        assert "changed elsewhere" in str(
            fixture.app.screen.query_one("#rule-feedback", Static).render()
        )
        await pilot.click("#reload-rules")
        assert fixture.app.screen.query_one("#rule-auth_failure_count", Input).value == "4"


async def test_failed_rule_activation_keeps_saved_policy_and_draft(app_factory):
    async def reject(_config):
        raise OSError("synthetic activation failure")

    fixture = app_factory(configured=True, reconfigure=reject)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        fixture.app.action_rules()
        await pilot.pause()
        fixture.app.screen.query_one("#rule-auth_failure_count", Input).value = "3"
        await pilot.click("#apply-rules")
        await pilot.pause()
        assert fixture.store.load().rules.auth_failure_count == 6
        assert fixture.app.screen.query_one("#rule-auth_failure_count", Input).value == "3"
        assert "not saved" in str(fixture.app.screen.query_one("#rule-feedback", Static).render())


async def test_compact_editor_keyboard_reaches_last_score_and_apply(app_factory):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        fixture.app.action_rules()
        await pilot.pause()
        # Additional policy fields and replay scope remain keyboard reachable.
        for _ in range(80):
            if fixture.app.focused.id == "points-log_firewall_denial_burst":
                break
            await pilot.press("tab")
        assert fixture.app.focused.id == "points-log_firewall_denial_burst"
        await pilot.press("ctrl+shift+a", "4", "2")
        for _ in range(20):
            await pilot.press("tab")
            if fixture.app.focused.id == "apply-rules":
                break
        assert fixture.app.focused.id == "apply-rules"
        await pilot.press("enter")
        await pilot.pause()
        assert fixture.store.load().rules.points.log_firewall_denial_burst == 42
