from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from textual.widgets import DataTable, Input, Markdown, Static

from socketclaw.domain import InvestigationResult, ResponseProposal
from socketclaw.storage import StoredResponseProposal

from .conftest import event_fixture, investigation_fixture


def _result_fixture(event_id: UUID) -> InvestigationResult:
    completed = investigation_fixture(event_id)
    assert completed.assessment is not None
    assert completed.usage is not None
    return InvestigationResult(
        assessment=completed.assessment,
        usage=completed.usage,
        model_id=completed.model_id,
        requested_effort=completed.requested_effort,
    )


@pytest.mark.asyncio
async def test_filter_select_investigate_export_and_live_insert(
    app_factory: Callable[..., Any],
) -> None:
    critical = event_fixture()
    informational = event_fixture(
        title="Routine reachability check",
        severity="info",
        source="ping",
        event_type="ping.result",
    )
    fixture = app_factory(
        configured=True,
        events=[critical, informational],
    )

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        await pilot.pause(0.2)
        table = fixture.app.screen.query_one("#events-table", DataTable)
        assert table.row_count == 2

        await pilot.press("c")
        await pilot.pause(0.2)
        assert table.row_count == 1
        assert "Repeated SSH" in fixture.app.screen.query_one("#event-detail", Markdown).source

        await pilot.press("i")
        await pilot.pause(0.3)
        assert fixture.repository.investigations_data[0].event_id == critical.id

        await pilot.press("e")
        await pilot.pause(0.2)
        exports = list((fixture.store.home / "exports").glob("*.md"))
        assert len(exports) == 1
        assert "sk-proj-configured" not in exports[0].read_text()

        live = event_fixture(title="Live DNS anomaly", severity="high")
        await fixture.monitor.publish(live)
        await pilot.pause(0.3)
        await pilot.press("a")
        await pilot.pause(0.2)
        assert table.row_count == 3


@pytest.mark.asyncio
async def test_event_text_filter_and_empty_state(
    app_factory: Callable[..., Any],
) -> None:
    fixture = app_factory(configured=True, events=[event_fixture()])

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        search = fixture.app.screen.query_one("#event-search", Input)
        search.value = "does-not-exist"
        await pilot.pause(0.3)

        assert fixture.app.screen.query_one("#events-table", DataTable).row_count == 0
        assert "No events match" in str(
            fixture.app.screen.query_one("#events-state", Static).render()
        )


@pytest.mark.asyncio
async def test_live_refresh_preserves_the_event_being_inspected(
    app_factory: Callable[..., Any],
) -> None:
    newest = event_fixture(title="Newest event")
    selected = event_fixture(title="Older event under review", severity="high")
    fixture = app_factory(configured=True, events=[newest, selected])

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        await pilot.pause(0.2)
        table = fixture.app.screen.query_one("#events-table", DataTable)
        table.move_cursor(row=1)
        await pilot.pause(0.1)
        assert (
            "Older event under review"
            in fixture.app.screen.query_one("#event-detail", Markdown).source
        )

        await fixture.monitor.publish(event_fixture(title="Incoming live event"))
        await pilot.pause(0.3)

        assert table.cursor_row == 1
        assert table.row_count == 2
        assert "1 new observation" in str(
            fixture.app.screen.query_one("#events-state", Static).render()
        )
        await pilot.click("#events-live")
        await pilot.pause(0.3)
        assert table.cursor_row == 2
        assert (
            "Older event under review"
            in fixture.app.screen.query_one("#event-detail", Markdown).source
        )


@pytest.mark.asyncio
async def test_untrusted_event_markdown_is_rendered_as_text(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture(title="\x1b[31m[Open me](https://malicious.invalid)\x1b[0m")
    event = event.model_copy(update={"summary": "\x9b31m# injected heading\x9b0m"})
    fixture = app_factory(configured=True, events=[event])

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        await pilot.pause(0.2)
        detail = fixture.app.screen.query_one("#event-detail", Markdown)

        assert r"\[Open me\]\(https://malicious\.invalid\)" in detail.source
        assert r"\# injected heading" in detail.source
        assert "\x1b" not in detail.source
        assert "\x9b" not in detail.source


@pytest.mark.asyncio
async def test_investigation_start_failure_becomes_durable_failed_work(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    fixture.repository.start_investigation_error = RuntimeError("queue worker unavailable")

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")
        await pilot.press("i")
        await pilot.pause(0.3)

        assert len(fixture.repository.investigations_data) == 1
        failed = fixture.repository.investigations_data[0]
        assert failed.status == "failed"
        assert failed.error == "queue worker unavailable"
        state = fixture.app.screen.query_one("#events-state", Static)
        assert "failed" in str(state.render()).lower()


@pytest.mark.asyncio
async def test_investigation_failure_redacts_api_key_before_persistence(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    key = fixture.store.load_api_key()
    assert key is not None
    fixture.repository.start_investigation_error = RuntimeError(f"provider rejected bearer {key}")

    async with fixture.app.run_test(size=(80, 24)):
        with pytest.raises(RuntimeError, match="provider rejected bearer") as error:
            await fixture.app.investigate_event(event.id)

        persisted = fixture.repository.investigations_data[0].error or ""
        assert key not in persisted
        assert key not in str(error.value)
        assert "[REDACTED]" in persisted


@pytest.mark.asyncio
async def test_cancelled_investigation_becomes_durable_failed_work(
    app_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    started = asyncio.Event()

    class BlockingClient:
        def __init__(self, _key: str) -> None:
            pass

        async def investigate(self, _event: object, *, context: object = None) -> None:
            started.set()
            await asyncio.Future()

    monkeypatch.setattr("socketclaw.ui.app.OpenAIClient", BlockingClient)

    async with fixture.app.run_test(size=(80, 24)):
        task = asyncio.create_task(fixture.app.investigate_event(event.id))
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        failed = fixture.repository.investigations_data[0]
        assert failed.status == "failed"
        assert failed.error == "Investigation canceled before completion"


@pytest.mark.asyncio
async def test_cancelled_queue_commit_becomes_durable_failed_work(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    fixture.repository.queue_started = asyncio.Event()
    fixture.repository.queue_release = asyncio.Event()

    async with fixture.app.run_test(size=(80, 24)):
        task = asyncio.create_task(fixture.app.investigate_event(event.id))
        await asyncio.wait_for(fixture.repository.queue_started.wait(), timeout=1)
        task.cancel()
        fixture.repository.queue_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        failed = fixture.repository.investigations_data[0]
        assert failed.status == "failed"
        assert failed.error == "Investigation canceled during queue persistence"


@pytest.mark.asyncio
async def test_ui_export_includes_the_matching_durable_response_status(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    investigation = investigation_fixture(event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="monitor",
            reason="Continue collecting local evidence",
        ),
        status="approved",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        events=[event],
        investigations=[investigation],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(80, 24)):
        destination = await fixture.app.export_event(event.id)

    rendered = destination.read_text(encoding="utf-8")
    assert "**Durable status:** Approved" in rendered


@pytest.mark.asyncio
async def test_completion_failure_marks_running_work_failed(
    app_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = event_fixture()
    result = _result_fixture(event.id)
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    fixture.repository.complete_investigation_error = RuntimeError("result write failed")

    class InstantClient:
        def __init__(self, _key: str) -> None:
            pass

        async def investigate(
            self, _event: object, *, context: object = None
        ) -> InvestigationResult:
            return result

    monkeypatch.setattr("socketclaw.ui.app.OpenAIClient", InstantClient)

    async with fixture.app.run_test(size=(80, 24)):
        with pytest.raises(RuntimeError, match="result write failed"):
            await fixture.app.investigate_event(event.id)

        failed = fixture.repository.investigations_data[0]
        assert failed.status == "failed"
        assert failed.error == "result write failed"


@pytest.mark.asyncio
async def test_post_commit_error_preserves_and_returns_completed_result(
    app_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = event_fixture()
    result = _result_fixture(event.id)
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    fixture.repository.complete_after_commit_error = RuntimeError("connection lost after commit")

    class InstantClient:
        def __init__(self, _key: str) -> None:
            pass

        async def investigate(
            self, _event: object, *, context: object = None
        ) -> InvestigationResult:
            return result

    monkeypatch.setattr("socketclaw.ui.app.OpenAIClient", InstantClient)

    async with fixture.app.run_test(size=(80, 24)):
        stored = await fixture.app.investigate_event(event.id)

        assert stored.status == "complete"
        assert fixture.repository.investigations_data[0].status == "complete"


@pytest.mark.asyncio
async def test_cancellation_during_completion_waits_for_durable_outcome(
    app_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = event_fixture()
    result = _result_fixture(event.id)
    fixture = app_factory(configured=True, events=[event])
    fixture.app.services.investigate = None
    fixture.repository.complete_started = asyncio.Event()
    fixture.repository.complete_release = asyncio.Event()

    class InstantClient:
        def __init__(self, _key: str) -> None:
            pass

        async def investigate(
            self, _event: object, *, context: object = None
        ) -> InvestigationResult:
            return result

    monkeypatch.setattr("socketclaw.ui.app.OpenAIClient", InstantClient)

    async with fixture.app.run_test(size=(80, 24)):
        task = asyncio.create_task(fixture.app.investigate_event(event.id))
        await asyncio.wait_for(fixture.repository.complete_started.wait(), timeout=1)
        task.cancel()
        fixture.repository.complete_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert fixture.repository.investigations_data[0].status == "complete"


async def test_inactive_event_workspace_waits_to_query_until_reentered(
    app_factory: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = app_factory(configured=True, events=[event_fixture()])
    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("3")
        await pilot.pause(0.3)
        calls = 0
        original = fixture.repository.list_events

        async def counted(query=None):
            nonlocal calls
            calls += 1
            return await original(query)

        monkeypatch.setattr(fixture.repository, "list_events", counted)
        for i in range(100):
            await fixture.monitor.publish(event_fixture(title=f"Burst {i}"))
        await pilot.pause(0.5)
        assert calls == 0
        await pilot.press("2")
        await pilot.pause(0.3)
        assert fixture.app.screen.query_one("#events-table", DataTable).row_count == 100
        assert calls <= 2
