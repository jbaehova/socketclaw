"""Regressions for the audited operator workflows, with real incident storage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest
from textual.widgets import Button, Input, Select, TextArea

from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig, ConfigStore
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.incidents import SuppressionRule
from socketclaw.monitor import MonitorService
from socketclaw.storage import Repository
from socketclaw.ui.app import AppServices, SocketClawApp
from socketclaw.ui.events import EventsView
from socketclaw.ui.incidents import IncidentComment, IncidentReader
from socketclaw.ui.rules import RuleSettingsScreen
from socketclaw.ui.suppressions import MaintenanceEditor, MaintenanceScreen

from .conftest import event_fixture, investigation_fixture


async def test_twenty_shortcuts_and_navigation_share_one_request(app_factory):
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])
    started = 0
    released = asyncio.Event()

    async def investigate(identifier):
        nonlocal started
        started += 1
        await released.wait()
        return investigation_fixture(identifier)

    fixture.app.services.investigate = investigate
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("2")
        await pilot.pause()
        await pilot.press(*(["i"] * 20))
        await pilot.press("1", "2", "i")
        await pilot.pause()
        assert started == 1
        assert fixture.app.screen.query_one(EventsView)._investigating
        released.set()
        await pilot.pause()
        await pilot.pause()
        assert not fixture.app.screen.query_one(EventsView)._investigating


async def test_log_path_json_roundtrip_and_narrow_filters(app_factory):
    paths = ["logs/auth, archived.log", "logs/한글 '인증'.log"]
    fixture = app_factory(configured=True, config=AppConfig(log_paths=paths))
    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.press("5")
        await pilot.pause()
        assert json.loads(fixture.app.screen.query_one("#settings-log-paths", Input).value) == paths
        await pilot.click("#save-settings")
        await pilot.pause()
        assert fixture.store.load().log_paths == paths
        await pilot.press("2")
        await pilot.pause()
        source = fixture.app.screen.query_one("#event-source", Select)
        source.value = "log"
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        assert source.display and source.region.width > 0 and source.region.height > 0
        assert source.value == "log"
        source.value = "ping"
        await pilot.pause()
        assert source.value == "ping"


async def test_rule_and_maintenance_drafts_survive_back_and_resize(app_factory, tmp_path):
    fixture = app_factory(configured=True)
    repository = Repository(tmp_path / "drafts.sqlite3")
    await repository.initialize()
    try:
        async with fixture.app.run_test(size=(80, 24)) as pilot:
            fixture.app.action_rules()
            await pilot.pause()
            fixture.app.screen.query_one("#rule-window_seconds", Input).value = "777"
            await pilot.press("escape")
            fixture.app.action_rules()
            await pilot.pause()
            assert isinstance(fixture.app.screen, RuleSettingsScreen)
            assert fixture.app.screen.query_one("#rule-window_seconds", Input).value == "777"
            await pilot.click("#reload-rules")
            assert fixture.app.screen.query_one("#rule-window_seconds", Input).value == "300"
            await pilot.press("escape")
            fixture.app.push_screen(MaintenanceEditor(repository.incidents, None))
            await pilot.pause()
            fixture.app.screen.query_one("#exception-target", Input).value = "host.example"
            fixture.app.screen.query_one(TextArea).load_text("Planned router upgrade")
            await pilot.resize_terminal(120, 36)
            await pilot.press("escape")
            fixture.app.push_screen(MaintenanceEditor(repository.incidents, None))
            await pilot.pause()
            assert fixture.app.screen.query_one("#exception-target", Input).value == "host.example"
            assert fixture.app.screen.query_one(TextArea).text == "Planned router upgrade"
    finally:
        await repository.close()


async def test_note_survives_ten_new_observations_and_reason_cancel(tmp_path):
    config = ConfigStore(tmp_path)
    config.save(AppConfig(targets=["gateway.local"]))
    repository = Repository(config.database_path)
    await repository.initialize()
    now = datetime.now(UTC)

    async def ingest(index):
        stamp = now + timedelta(seconds=index)
        await repository.ingest_batch(
            ProbeBatch(
                collected_at=stamp,
                observations=(
                    SecurityEvent(
                        observed_at=stamp,
                        source="ping",
                        event_type="ping.result",
                        target="gateway.local",
                        title="Gateway unreachable",
                        summary="100% loss",
                        evidence={"packet_loss": 100, "outcome": "ok"},
                    ),
                ),
            ),
            Detector(),
        )

    try:
        await ingest(0)
        incident = (await repository.incidents.list())[0]
        app = SocketClawApp(
            AppServices(
                config_store=config,
                repository=repository,
                monitor=MonitorService(repository, Detector()),
            )
        )
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen(IncidentReader(repository.incidents, incident))
            await pilot.pause()
            await pilot.click("#case-note")
            await pilot.pause()
            app.screen.query_one(TextArea).load_text("Checked router power")
            for index in range(1, 11):
                await ingest(index)
            await pilot.click("#case-comment-save")
            await pilot.pause()
            await pilot.pause(0.2)
            assert [note.body for note in await repository.incidents.notes(incident.id)] == [
                "Checked router power"
            ]
            await pilot.click("#case-resolve")
            await pilot.pause()
            app.screen.query_one(TextArea).load_text("Pending final verification")
            await pilot.press("escape")
            await pilot.click("#case-resolve")
            await pilot.pause()
            assert isinstance(app.screen, IncidentComment)
            assert app.screen.query_one(TextArea).text == "Pending final verification"
    finally:
        await repository.close()


async def test_maintenance_expiry_repaints_without_selection_loss(
    app_factory, tmp_path, monkeypatch
):
    fixture = app_factory(configured=True)
    repository = Repository(tmp_path / "expiry.sqlite3")
    await repository.initialize()
    now = datetime.now(UTC)
    rule = SuppressionRule(
        target="host.example",
        reason="Scheduled work",
        starts_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    await repository.incidents.create_suppression(rule)
    try:
        async with fixture.app.run_test(size=(80, 24)) as pilot:
            fixture.app.push_screen(MaintenanceScreen(repository.incidents))
            await pilot.pause()
            screen = fixture.app.screen
            assert not screen.query_one("#maintenance-end", Button).disabled
            monkeypatch.setattr(
                "socketclaw.ui.suppressions.utc_now", lambda: now + timedelta(minutes=2)
            )
            screen.refresh_expiry()
            assert screen.selected().id == rule.id
            assert screen.query_one("#maintenance-end", Button).disabled
    finally:
        await repository.close()


@pytest.mark.parametrize("iteration", range(5))
async def test_fast_mount_navigation_exit_has_no_worker_error(app_factory, iteration):
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("2", "4", "5", "1", "ctrl+c")


async def test_ui_searches_and_pages_beyond_500_observations(tmp_path):
    config = ConfigStore(tmp_path)
    config.save(AppConfig(targets=[]))
    repository = Repository(config.database_path)
    await repository.initialize()
    now = datetime.now(UTC)
    observations = tuple(
        SecurityEvent(
            observed_at=now + timedelta(seconds=index),
            source="manual",
            event_type="manual.check",
            target="archive.local",
            title=f"Retained observation {index:03d}",
            summary="Local fixture",
        )
        for index in range(510)
    )
    await repository.ingest_batch(
        ProbeBatch(collected_at=now, observations=observations), Detector()
    )
    app = SocketClawApp(
        AppServices(
            config_store=config,
            repository=repository,
            monitor=MonitorService(repository, Detector()),
        )
    )
    try:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.press("2")
            await pilot.pause()
            view = app.screen.query_one(EventsView)
            for _ in range(5):
                await pilot.click("#events-next")
                await pilot.pause(0.3)
            assert len(view.events) == 10
            assert observations[0].id in {event.id for event in view.events}
            view.query_one("#event-search", Input).value = "Retained observation 000"
            await pilot.pause(0.3)
            await pilot.pause()
            assert [event.id for event in view.events] == [observations[0].id]
    finally:
        await repository.close()


async def test_real_operator_conflict_preserves_reason_and_reloads_state(tmp_path):
    config = ConfigStore(tmp_path)
    config.save(AppConfig(targets=[]))
    repository = Repository(config.database_path)
    await repository.initialize()
    event = SecurityEvent(
        source="ping",
        event_type="ping.result",
        target="router.local",
        title="Router unavailable",
        summary="100% loss",
        evidence={"packet_loss": 100, "outcome": "ok"},
    )
    await repository.ingest_batch(ProbeBatch(observations=(event,)), Detector())
    incident = (await repository.incidents.list())[0]
    app = SocketClawApp(
        AppServices(
            config_store=config,
            repository=repository,
            monitor=MonitorService(repository, Detector()),
        )
    )
    try:
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen(IncidentReader(repository.incidents, incident))
            await pilot.pause()
            await pilot.click("#case-resolve")
            await pilot.pause()
            app.screen.query_one(TextArea).load_text("My verification draft")
            await repository.incidents.change_status(
                incident.id,
                "acknowledged",
                reason="Another operator is investigating",
                expected_revision=incident.revision,
            )
            await pilot.click("#case-comment-save")
            await pilot.pause(0.2)
            await pilot.pause()
            assert app.screen.incident.status == "acknowledged"
            await pilot.click("#case-resolve")
            await pilot.pause()
            assert app.screen.query_one(TextArea).text == "My verification draft"
    finally:
        await repository.close()


async def test_different_observations_in_one_incident_share_running_analysis(tmp_path):
    config = ConfigStore(tmp_path)
    repository = Repository(config.database_path)
    await repository.initialize()
    observations = tuple(
        SecurityEvent(
            source="ping",
            event_type="ping.result",
            target="router.local",
            title="Router unavailable",
            summary="100% loss",
            evidence={"packet_loss": 100, "outcome": "ok"},
        )
        for _ in range(2)
    )
    await repository.ingest_batch(ProbeBatch(observations=observations), Detector())
    release = asyncio.Event()
    started = 0

    async def investigate(identifier):
        nonlocal started
        started += 1
        await release.wait()
        return investigation_fixture(identifier)

    app = SocketClawApp(
        AppServices(
            config_store=config,
            repository=repository,
            monitor=MonitorService(repository, Detector()),
            investigate=investigate,
        )
    )
    try:
        tasks = [asyncio.create_task(app.investigate_event(event.id)) for event in observations]
        await asyncio.sleep(0.1)
        assert started == 1
        release.set()
        first, second = await asyncio.gather(*tasks)
        assert first.id == second.id
    finally:
        release.set()
        await repository.close()


async def test_manual_action_is_saved_separately_from_approval(tmp_path):
    from socketclaw.ui.incidents import ActionEditor

    config = ConfigStore(tmp_path)
    config.save(AppConfig(targets=[]))
    repository = Repository(config.database_path)
    await repository.initialize()
    event = SecurityEvent(
        source="ping",
        event_type="ping.result",
        target="router.local",
        title="Router unavailable",
        summary="100% loss",
        evidence={"packet_loss": 100, "outcome": "ok"},
    )
    await repository.ingest_batch(ProbeBatch(observations=(event,)), Detector())
    incident = (await repository.incidents.list())[0]
    app = SocketClawApp(
        AppServices(
            config_store=config,
            repository=repository,
            monitor=MonitorService(repository, Detector()),
        )
    )
    try:
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen(IncidentReader(repository.incidents, incident))
            await pilot.pause()
            await pilot.click("#case-action")
            await pilot.pause()
            assert isinstance(app.screen, ActionEditor)
            app.screen.query_one(TextArea).load_text("Restarted the local service manually")
            await pilot.click("#action-save")
            await pilot.pause(0.2)
            report = await repository.incident_report(incident.id)
            assert len(report.action_records) == 1
            assert report.action_records[0].status == "user_performed"
            assert report.history.incident.status == "open"
    finally:
        await repository.close()
