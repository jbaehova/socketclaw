from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from textual.widgets import DataTable, Markdown

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
        assert "GPT-5.6 Terra" in detail.source
        assert "180 tokens" in detail.source
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

        await pilot.click("#confirm-response")
        await pilot.pause(0.3)
        assert fixture.repository.proposals_data[0].status == "approved"


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
