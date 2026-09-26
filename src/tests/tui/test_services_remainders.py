from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static, TabbedContent

from socketclaw.config import AppConfig, ServiceConfig
from socketclaw.storage import StoredEvent
from socketclaw.ui.hosts import HostsView
from socketclaw.ui.services import ServiceEditor, ServicesView


async def open_services(app, pilot) -> ServicesView:
    await pilot.press("3")
    app.screen.query_one("#hosts-tabs", TabbedContent).active = "host-services"
    await pilot.pause()
    return app.screen.query_one(ServicesView)


async def test_small_terminal_service_tcp_http_config_roundtrip(app_factory) -> None:
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        view = await open_services(fixture.app, pilot)
        await pilot.click("#service-add")
        assert isinstance(fixture.app.screen, ServiceEditor)
        screen = fixture.app.screen
        for key, value in {
            "id": "api",
            "name": "Local API",
            "host": "127.0.0.1",
            "port": "8081",
            "failure_threshold": "4",
            "recovery_threshold": "3",
            "interval": "20",
        }.items():
            screen.query_one(f"#service-{key}", Input).value = value
        # Every form field can become visible by keyboard focus in the scroll area.
        for field in screen.query("Input, Select, Checkbox"):
            if field.disabled:
                continue
            field.focus()
            await pilot.pause()
            assert field.region.overlaps(screen.query_one("#service-fields").region)
        screen.query_one("#service-save", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert len(fixture.store.load().services) == 1, str(
            screen.query_one("#service-editor-feedback", Static).render()
        )
        saved = fixture.store.load().services[0]
        assert saved.protocol == "tcp" and saved.port == 8081
        assert saved.failure_threshold == 4 and saved.recovery_threshold == 3
        assert saved.allowed_exposure == "loopback"
        await pilot.click("#service-edit")
        screen = fixture.app.screen
        assert screen.query_one("#service-id", Input).disabled
        screen.query_one("#service-protocol", Select).value = "http"
        screen.query_one("#service-path", Input).value = "/health"
        screen.query_one("#service-expected_status", Input).value = "204"
        screen.query_one("#service-body_contains", Input).value = "healthy"
        screen.query_one("#service-allowed_exposure", Select).value = "private"
        screen.query_one("#service-required", Checkbox).value = False
        screen.query_one("#service-save", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        saved = fixture.store.load().services[0]
        assert saved.protocol == "http" and saved.path == "/health"
        assert saved.expected_status == 204 and saved.body_contains == "healthy"
        assert saved.allowed_exposure == "private" and saved.required is False
        assert view.query_one("#services-table", DataTable).row_count == 1
        await pilot.click("#service-remove")
        await pilot.pause()
        assert fixture.store.load().services == []


async def test_service_validation_preserves_editor_values(app_factory) -> None:
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await open_services(fixture.app, pilot)
        await pilot.click("#service-add")
        screen = fixture.app.screen
        screen.query_one("#service-id", Input).value = "api"
        screen.query_one("#service-name", Input).value = "Retained draft"
        screen.query_one("#service-port", Input).value = "999999"
        screen.query_one("#service-save", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert fixture.app.screen is screen
        assert "Not saved" in str(screen.query_one("#service-editor-feedback", Static).render())
        assert screen.query_one("#service-name", Input).value == "Retained draft"
        assert fixture.store.load().services == []


async def test_service_measured_state_and_repeated_check_guard(app_factory) -> None:
    service = ServiceConfig(id="api", name="Local API", host="127.0.0.1", port=8081)
    event = StoredEvent(
        source="system",
        event_type="service.failed",
        title="API closed",
        summary="TCP connect refused",
        target="127.0.0.1",
        observed_at=datetime.now(UTC),
        evidence={
            "service_id": "api",
            "status": "closed",
            "confirmed": True,
        },
    )
    fixture = app_factory(configured=True, config=AppConfig(services=[service]), events=[event])
    fixture.monitor.available_diagnostics = frozenset({"service", "ping", "ports"})
    calls = []
    started, release = asyncio.Event(), asyncio.Event()

    async def blocked(kind, target):
        calls.append((kind, target))
        started.set()
        await release.wait()
        return event

    fixture.monitor.run_diagnostic = blocked
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        view = await open_services(fixture.app, pilot)
        row = view.query_one("#services-table", DataTable).get_row_at(0)
        assert "closed confirmed" in row
        view.check_service()
        await started.wait()
        view.check_service()
        view.check_service()
        assert calls == [("service", "api")]
        release.set()
        await pilot.pause()
        assert not view.query_one("#service-check", Button).disabled


async def test_last_target_removal_allows_log_only_inventory(app_factory) -> None:
    fixture = app_factory(configured=True, config=AppConfig(targets=["127.0.0.1"]))
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("3")
        fixture.app.screen.query_one(HostsView)._remove_target("127.0.0.1")
        await pilot.pause()
        assert fixture.store.load().targets == []
