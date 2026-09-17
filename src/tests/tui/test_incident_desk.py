from datetime import UTC, datetime

import pytest
from textual.widgets import Button, DataTable, Tabs, TextArea

from socketclaw.collection import ProbeBatch
from socketclaw.config import AppConfig, ConfigStore
from socketclaw.detection import Detector
from socketclaw.domain import SecurityEvent
from socketclaw.monitor import MonitorService
from socketclaw.storage import Repository
from socketclaw.ui.app import AppServices, SocketClawApp
from socketclaw.ui.incidents import IncidentComment, IncidentDesk, IncidentReader


@pytest.mark.parametrize("size", [(80, 24), (120, 36)])
async def test_review_note_and_resolve_from_events(tmp_path, size):
    store = ConfigStore(tmp_path)
    store.save(AppConfig(targets=["gateway.local"]))
    store.save_api_key("test-local-only")
    repository = Repository(store.database_path)
    await repository.initialize()
    try:
        await repository.ingest_batch(
            ProbeBatch(
                collected_at=datetime(2026, 7, 27, tzinfo=UTC),
                observations=(
                    SecurityEvent(
                        source="ping",
                        event_type="ping.result",
                        target="gateway.local",
                        title="Gateway unreachable",
                        summary="100% packet loss",
                        evidence={"packet_loss": 100, "outcome": "ok"},
                    ),
                ),
            ),
            Detector(),
        )
        incident = (await repository.incidents.list())[0]
        app = SocketClawApp(
            AppServices(
                config_store=store,
                monitor=MonitorService(repository, Detector()),
                repository=repository,
            )
        )
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("2")
            await pilot.pause()
            await pilot.click("#open-incidents")
            await pilot.pause()
            assert isinstance(app.screen, IncidentDesk)
            assert app.screen.query_one(DataTable).row_count == 1
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, IncidentReader)
            for button, reason in [
                ("#case-ack", "Checking the upstream route"),
                ("#case-note", "Router power is healthy"),
                ("#case-resolve", "Route restored and verified"),
            ]:
                await pilot.click(button)
                await pilot.pause()
                assert isinstance(app.screen, IncidentComment)
                app.screen.query_one(TextArea).load_text(reason)
                await pilot.pause()
                await pilot.click("#case-comment-save")
                await pilot.pause()
                await pilot.pause(0.2)
            current = await repository.incidents.get(incident.id)
            assert current.status == "resolved"
            assert [note.body for note in await repository.incidents.notes(incident.id)] == [
                "Router power is healthy"
            ]
            assert app.screen.query_one("#case-resolve", Button).label.plain == "Reopen"
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, IncidentDesk)
            assert app.screen.query_one(DataTable).row_count == 0
            app.screen.query_one(Tabs).active = "resolved"
            await pilot.pause()
            await pilot.pause(0.2)
            assert app.screen.query_one(DataTable).row_count == 1
    finally:
        await repository.close()
