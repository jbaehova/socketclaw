"""The log progress reader stays usable in every supported terminal size."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from textual.widgets import DataTable, Input, Markdown, Static, TabbedContent

from socketclaw.collection import CheckpointChange, LogCheckpointState
from socketclaw.config import AppConfig
from socketclaw.ui.detail import DetailScreen


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 36), (160, 48)])
async def test_log_progress_shows_committed_backlog_and_returns_to_workspace(
    app_factory, monkeypatch: pytest.MonkeyPatch, size: tuple[int, int]
) -> None:
    fixture = app_factory(configured=True, config=AppConfig(log_paths=["/tmp/socketclaw-auth.log"]))

    async def checkpoint(probe_id: str) -> CheckpointChange:
        state = LogCheckpointState(
            read_policy="resume",
            offset=500,
            sampled_size=2500,
            backlog_bytes=2000,
            last_read_at=datetime(2026, 9, 17, tzinfo=UTC),
            last_match_count=4,
            gap_count=1,
        )
        return CheckpointChange(
            probe_id=probe_id, expected_revision=2, state=state.model_dump(mode="json")
        )

    monkeypatch.setattr(fixture.repository, "load_checkpoint", checkpoint)
    async with fixture.app.run_test(size=size) as pilot:
        await pilot.press("3", "l")
        await pilot.pause()
        assert fixture.app.screen.query_one("#hosts-tabs", TabbedContent).active == "host-logs"
        assert fixture.app.screen.query_one("#logs-table", DataTable).row_count == 1
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(fixture.app.screen, DetailScreen)
        body = fixture.app.screen.query_one("#full-detail-body", Markdown)
        assert "Catching up" in body.source
        assert "2,000" in body.source
        assert "Recorded gaps: 1" in body.source
        assert "Matches in last poll: 4" in body.source
        await pilot.press("end", "escape")
        assert not isinstance(fixture.app.screen, DetailScreen)
        assert fixture.app.focused is not None
        assert fixture.app.focused.id == "logs-table"


async def test_no_configured_logs_explains_how_to_add_sources(app_factory) -> None:
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("l")
        await pilot.pause()
        body = fixture.app.screen.query_one("#logs-feedback", Static)
        assert "No log sources configured" in str(body.render())


async def test_log_sources_can_be_added_test_read_and_removed(app_factory, tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("Failed password for root from 192.0.2.1\n")
    fixture = app_factory(configured=True)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("l")
        await pilot.pause()
        fixture.app.screen.query_one("#log-source-path", Input).value = str(path)
        await pilot.click("#add-log-source")
        await pilot.pause()
        assert fixture.store.load().log_paths == [str(path)]
        assert fixture.app.screen.query_one("#logs-table", DataTable).row_count == 1
        fixture.app.screen.query_one("#logs-table", DataTable).focus()
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(fixture.app.screen, DetailScreen)
        body = fixture.app.screen.query_one("#full-detail-body", Markdown)
        assert "Showing 1 matches" in body.source
        assert "structured" in body.source
        assert fixture.repository.events_data == []
        assert fixture.monitor.diagnostics == []
        await pilot.press("escape")
        await pilot.click("#remove-log")
        await pilot.pause()
        assert fixture.store.load().log_paths == []
        assert fixture.app.screen.query_one("#logs-table", DataTable).row_count == 0


async def test_failed_source_activation_preserves_saved_configuration(app_factory) -> None:
    async def reject(_config):
        raise OSError("synthetic activation failure")

    fixture = app_factory(configured=True, reconfigure=reject)
    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.press("l")
        await pilot.pause()
        fixture.app.screen.query_one("#log-source-path", Input).value = "/tmp/new-source.log"
        await pilot.click("#add-log-source")
        await pilot.pause()
        assert fixture.store.load().log_paths == []
        assert "not added" in str(fixture.app.screen.query_one("#logs-feedback", Static).render())
