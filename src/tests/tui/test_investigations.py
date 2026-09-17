from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from textual.containers import VerticalScroll
from textual.widgets import Button, DataTable, Markdown, Static

from socketclaw.config import AppConfig
from socketclaw.domain import ResponseProposal
from socketclaw.storage import StoredResponseProposal
from socketclaw.ui.dialogs import ConfirmResponseScreen

from .conftest import event_fixture, investigation_fixture


@pytest.mark.asyncio
async def test_investigation_detail_shows_model_usage_cost_and_failed_retry(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    complete = investigation_fixture(event.id)
    failed = investigation_fixture(event.id, status="failed")
    fixture = app_factory(
        configured=True,
        events=[event],
        investigations=[failed, complete],
    )

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        table = fixture.app.screen.query_one("#investigations-table", DataTable)
        assert table.row_count == 2
        detail = fixture.app.screen.query_one("#investigation-detail", Markdown)
        assert "Provider unavailable" in detail.source

        await pilot.click("#retry-investigation")
        await pilot.pause(0.3)
        assert len(fixture.repository.investigations_data) == 3
        assert "GPT-5.6 Luna" in detail.source
        assert "160 tokens" in detail.source
        assert "$0.004200" in detail.source


@pytest.mark.asyncio
async def test_response_approval_requires_confirmation(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    investigation = investigation_fixture(event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="block",
            target_ip="198.51.100.24",
            reason="Repeated SSH authentication failures",
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        events=[event],
        investigations=[investigation],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        await pilot.click("#approve-response")
        assert isinstance(fixture.app.screen, ConfirmResponseScreen)
        assert fixture.repository.proposals_data[0].status == "pending"

        fixture.app.screen.query_one("#response-review", VerticalScroll).scroll_end(animate=False)
        await pilot.pause(0.1)
        await pilot.click("#confirm-response")
        await pilot.pause(0.3)
        assert fixture.repository.proposals_data[0].status == "approved"


@pytest.mark.asyncio
async def test_approved_response_can_be_deliberately_rejected_at_80x24(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    investigation = investigation_fixture(event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="notify",
            target_ip=None,
            reason="Approval is no longer appropriate",
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

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)

        assert fixture.app.screen.query_one("#approve-response", Button).disabled is True
        reject = fixture.app.screen.query_one("#reject-response", Button)
        assert reject.disabled is False

        await pilot.click("#reject-response")
        assert isinstance(fixture.app.screen, ConfirmResponseScreen)
        assert "APPROVED" in str(fixture.app.screen.query_one("#response-copy", Static).render())
        fixture.app.screen.query_one("#response-review", VerticalScroll).scroll_end(animate=False)
        await pilot.pause(0.1)
        await pilot.click("#confirm-response")
        await pilot.pause(0.3)

        assert fixture.repository.proposals_data[0].status == "rejected"


@pytest.mark.asyncio
async def test_response_rejects_configured_trusted_target(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture(target="192.168.1.10")
    investigation = investigation_fixture(event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="block",
            target_ip="192.168.1.10",
            reason="Synthetic internal alert",
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        config=AppConfig(targets=["192.168.1.10"]),
        events=[event],
        investigations=[investigation],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(110, 32)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        await pilot.click("#approve-response")
        await pilot.pause(0.2)

        assert not isinstance(fixture.app.screen, ConfirmResponseScreen)
        assert fixture.repository.proposals_data[0].status == "pending"
        state = fixture.app.screen.query_one("#investigations-state")
        assert "trusted" in str(state.render()).lower()


@pytest.mark.asyncio
async def test_response_refresh_preserves_an_older_selected_investigation(
    app_factory: Callable[..., Any],
) -> None:
    newer_event = event_fixture(title="Newer event")
    selected_event = event_fixture(title="Selected older event")
    newer = investigation_fixture(newer_event.id)
    selected = investigation_fixture(selected_event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=selected_event.id,
        investigation_id=selected.id,
        proposal=ResponseProposal(
            action="monitor",
            target_ip=None,
            reason="Keep watching the older event",
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        events=[newer_event, selected_event],
        investigations=[newer, selected],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(120, 36)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        table = fixture.app.screen.query_one("#investigations-table", DataTable)
        await pilot.press("down")
        await pilot.pause(0.1)

        await pilot.click("#reject-response")
        assert isinstance(fixture.app.screen, ConfirmResponseScreen)
        fixture.app.screen.query_one("#response-review", VerticalScroll).scroll_end(animate=False)
        await pilot.pause(0.1)
        await pilot.click("#confirm-response")
        await pilot.pause(0.3)

        assert table.cursor_row == 1
        assert fixture.repository.proposals_data[0].status == "rejected"
        detail = fixture.app.screen.query_one("#investigation-detail", Markdown)
        assert "REJECTED" in detail.source


@pytest.mark.asyncio
async def test_running_investigation_has_safe_progress_detail_and_cannot_retry(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    fixture = app_factory(configured=True, events=[event])

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        fixture.repository.investigations_data.append(
            investigation_fixture(event.id, status="running")
        )
        await pilot.press("4")
        await pilot.pause(0.2)

        detail = fixture.app.screen.query_one("#investigation-detail", Markdown)
        assert "in progress" in detail.source
        assert fixture.app.screen.query_one("#retry-investigation", Button).disabled is True


@pytest.mark.asyncio
async def test_confirmation_reviews_long_reason_and_command_at_80x24(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    investigation = investigation_fixture(event.id)
    long_reason = " ".join(f"evidence-{index}" for index in range(70))
    command = "firewallctl review --source 198.51.100.24 --dry-run"
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="block",
            target_ip="198.51.100.24",
            reason=long_reason,
            command=command,
            platform="test-platform",
            reversible=True,
            requires_approval=True,
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        events=[event],
        investigations=[investigation],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        await pilot.click("#approve-response")

        assert isinstance(fixture.app.screen, ConfirmResponseScreen)
        review = fixture.app.screen.query_one("#response-review", VerticalScroll)
        rendered = "\n".join(
            str(widget.render()) for widget in fixture.app.screen.query("#response-review Static")
        )
        assert long_reason in rendered
        assert command in rendered
        assert "test-platform" in rendered
        confirm = fixture.app.screen.query_one("#confirm-response", Button)
        assert confirm.disabled is True
        review.scroll_end(animate=False)
        await pilot.pause(0.1)
        assert confirm.disabled is False

        await pilot.click("#confirm-response")
        await pilot.pause(0.3)
        assert fixture.repository.proposals_data[0].status == "approved"


@pytest.mark.asyncio
async def test_confirmation_strips_terminal_controls_from_model_fields(
    app_factory: Callable[..., Any],
) -> None:
    event = event_fixture()
    investigation = investigation_fixture(event.id)
    proposal = StoredResponseProposal(
        id=uuid4(),
        event_id=event.id,
        investigation_id=investigation.id,
        proposal=ResponseProposal(
            action="notify",
            reason="hello\x1b]52;c;QUJD\x07still visible\x00\nState APPROVED\u202e",
            command="printf safe\x1b[2J\x9b31m abc\u202etxt.exe",
            platform="linux\nState APPROVED\nReversible yes\x1b[H",
        ),
        status="pending",
        created_at=datetime(2026, 7, 27, 12, 2, tzinfo=UTC),
    )
    fixture = app_factory(
        configured=True,
        events=[event],
        investigations=[investigation],
        proposals=[proposal],
    )

    async with fixture.app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("4")
        await pilot.pause(0.2)
        await pilot.click("#approve-response")

        rendered = "\n".join(
            str(widget.render()) for widget in fixture.app.screen.query("#response-review Static")
        )
        assert "still visible" in rendered
        assert "printf safe" in rendered
        assert not any(
            control in rendered for control in ("\x00", "\x07", "\x1b", "\x9b", "\u202e")
        )
        metadata = str(fixture.app.screen.query_one("#response-copy", Static).render())
        assert metadata.count("\n") == 4
        reason = str(fixture.app.screen.query_one("#response-reason", Static).render())
        assert "\nState APPROVED" not in reason
