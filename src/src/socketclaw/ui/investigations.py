"""OpenAI investigation queue, usage accounting, and response review."""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import UUID

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Markdown, Static

from ..config import OPENAI_MODEL
from ..storage import (
    ResponseStatus,
    StoredInvestigation,
    StoredResponseProposal,
    StoredResponseStatus,
)
from .context import escape_markdown, safe_text, socketclaw_app
from .detail import DetailScreen
from .dialogs import ConfirmResponseScreen


class InvestigationsView(Vertical):
    """Durable AI analysis history with explicit human response gates."""

    def __init__(self) -> None:
        super().__init__(id="investigations-view", classes="workspace-view")
        self.investigations: list[StoredInvestigation] = []
        self.proposals: list[StoredResponseProposal] = []
        self._selected_id: UUID | None = None
        self._transitioning = False

    def compose(self) -> ComposeResult:
        yield Static("INVESTIGATIONS / OPENAI", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Analysis queue", classes="view-title")
            yield Static("", id="investigation-totals", classes="view-hint")
        yield Static(
            "Loading investigation history…",
            id="investigations-state",
            classes="inline-state",
            markup=False,
        )
        with Horizontal(classes="split-workspace"):
            yield DataTable(
                id="investigations-table",
                cursor_type="row",
                zebra_stripes=True,
            )
            yield Markdown(
                "Select an investigation to inspect the model assessment.",
                id="investigation-detail",
                open_links=False,
            )
        with Horizontal(classes="action-row"):
            yield Button(
                "Retry",
                id="retry-investigation",
                variant="primary",
                disabled=True,
            )
            yield Button("Approve response", id="approve-response", disabled=True)
            yield Button("Reject response", id="reject-response", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#investigations-table", DataTable).add_columns(
            "TIME", "STATUS", "MODEL", "EFFORT", "TOKENS", "COST"
        )
        self.refresh_data()

    @work(exclusive=True, group="investigations-load")
    async def refresh_data(self) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            self._show_state("Investigation storage is unavailable.", error=True)
            return
        try:
            self.investigations, self.proposals, stats = await asyncio.gather(
                repository.list_investigations(limit=500),
                repository.list_response_proposals(limit=500),
                repository.session_stats(),
            )
        except Exception as exc:
            self._show_state(f"Could not load investigations: {exc}", error=True)
            return
        self.query_one("#investigation-totals", Static).update(
            f"{stats.total_tokens:,} tokens / ${stats.cost_usd:.6f} lifetime cost"
        )
        self._render_rows()

    def selected_investigation(self) -> StoredInvestigation | None:
        if self._selected_id is not None:
            selected = next(
                (item for item in self.investigations if item.id == self._selected_id),
                None,
            )
            if selected is not None:
                return selected
        return self.investigations[0] if self.investigations else None

    @on(DataTable.RowSelected, "#investigations-table")
    def open_detail(self) -> None:
        if self.selected_investigation() is not None:
            self._render_detail()
            socketclaw_app(self).push_screen(
                DetailScreen(self.query_one("#investigation-detail", Markdown).source)
            )

    @on(DataTable.RowHighlighted, "#investigations-table")
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            self._selected_id = UUID(str(event.row_key.value))
        except (TypeError, ValueError):
            self._selected_id = None
        self._render_detail()
        self.refresh_actions()

    @on(Button.Pressed, "#retry-investigation")
    def retry(self) -> None:
        selected = self.selected_investigation()
        if selected is None or selected.status != "failed":
            self._show_state("Select a failed investigation to retry.")
            return
        self._selected_id = None
        self._retry(selected.event_id)

    @work(exclusive=True, group="investigation-retry")
    async def _retry(self, event_id: UUID) -> None:
        button = self.query_one("#retry-investigation", Button)
        button.disabled = True
        self._show_state("Retrying with the active model…")
        try:
            app = socketclaw_app(self)
            await app.investigate_event(event_id)
        except Exception as exc:
            self._show_state(f"Retry failed: {exc}", error=True)
        else:
            self._show_state("Investigation completed.")
            self.refresh_data()
        finally:
            button.disabled = False

    @on(Button.Pressed, "#approve-response")
    def approve_response(self) -> None:
        self._transition_response("approved", confirm=True)

    @on(Button.Pressed, "#reject-response")
    def reject_response(self) -> None:
        self._transition_response("rejected", confirm=True)

    def _transition_response(self, status: ResponseStatus, *, confirm: bool) -> None:
        proposal = self._selected_proposal()
        if proposal is None:
            self._show_state("This investigation has no response proposal.")
            return
        app = socketclaw_app(self)
        permitted = (
            proposal.status in {"pending", "approved"}
            if status == "rejected"
            else proposal.status == "pending"
        )
        if not permitted:
            self._show_state(
                f"This response is already {proposal.status}; it cannot be marked {status}."
            )
            return
        target_ip = proposal.proposal.target_ip
        if (
            status == "approved"
            and proposal.proposal.action == "block"
            and target_ip in app.config.targets
        ):
            self._show_state(
                f"Response rejected: {target_ip} is a configured trusted target.",
                error=True,
            )
            return
        if confirm:
            app.push_screen(
                ConfirmResponseScreen(proposal, status),
                lambda accepted: self._confirmed_transition(
                    accepted,
                    proposal.id,
                    status,
                    proposal.status,
                ),
            )
            return
        self._update_response(proposal.id, status)

    def _confirmed_transition(
        self,
        accepted: bool | None,
        proposal_id: UUID,
        status: ResponseStatus,
        expected_status: StoredResponseStatus,
    ) -> None:
        if accepted:
            self._update_response(proposal_id, status, expected_status)

    @work(exclusive=True, group="response-transition")
    async def _update_response(
        self,
        proposal_id: UUID,
        status: ResponseStatus,
        expected_status: StoredResponseStatus,
    ) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            self._show_state("Response storage is unavailable.", error=True)
            return
        self._transitioning = True
        self.refresh_actions()
        try:
            await repository.update_response_proposal_status(
                proposal_id,
                status,
                expected_status=expected_status,
                protected_targets=app.config.targets,
            )
        except Exception as exc:
            self._show_state(f"Response was not changed: {exc}", error=True)
        else:
            self._show_state(f"Response marked {status}.")
            self.refresh_data()
        finally:
            self._transitioning = False
            self.refresh_actions()

    def _render_rows(self) -> None:
        table = cast(
            DataTable[str],
            self.query_one("#investigations-table", DataTable),
        )
        previous_selection = self._selected_id
        table.clear()
        for item in self.investigations:
            usage = item.usage
            table.add_row(
                item.created_at.astimezone().strftime("%H:%M:%S"),
                item.status.upper(),
                safe_text(_model_label(item.model_id)),
                item.requested_effort.upper(),
                str(usage.total_tokens or 0) if usage else "-",
                f"${usage.cost_usd:.6f}" if usage else "-",
                key=str(item.id),
            )
        if not self.investigations:
            self._selected_id = None
            self._show_state("No investigations yet. Select an event and press I.")
            self.query_one("#investigation-detail", Markdown).update(
                "No investigation is selected."
            )
            self.refresh_actions()
            return
        investigation_ids = {item.id for item in self.investigations}
        self._selected_id = (
            previous_selection
            if previous_selection in investigation_ids
            else self.investigations[0].id
        )
        table.move_cursor(row=table.get_row_index(str(self._selected_id)))
        self._show_state(f"{len(self.investigations)} durable investigation record(s).")
        self._render_detail()
        self.refresh_actions()

    def _render_detail(self) -> None:
        item = self.selected_investigation()
        if item is None:
            self.query_one("#investigation-detail", Markdown).update(
                "No investigation is selected."
            )
            return
        label = _model_label(item.model_id)
        rendered_label = label if item.model_id == OPENAI_MODEL.model_id else escape_markdown(label)
        if item.status == "failed":
            content = (
                f"## Investigation failed\n\n**{rendered_label}** / "
                f"`{escape_markdown(item.requested_effort.upper())}`\n\n"
                f"{escape_markdown(item.error or 'No provider error was recorded.')}"
            )
        elif item.status in {"queued", "running"}:
            state = (
                "Queued for provider execution."
                if item.status == "queued"
                else ("OpenAI analysis is in progress. Monitoring continues in the background.")
            )
            content = (
                f"## Investigation {item.status}\n\n"
                f"**{rendered_label}** / "
                f"`{escape_markdown(item.requested_effort.upper())}`\n\n{state}"
            )
        else:
            assessment = item.assessment
            usage = item.usage
            if assessment is None or usage is None:
                content = "## Invalid record\n\nThe completed result is missing data."
            else:
                rationale = "\n".join(f"- {escape_markdown(line)}" for line in assessment.rationale)
                actions = (
                    "\n".join(
                        f"- {escape_markdown(line)}" for line in assessment.recommended_actions
                    )
                    or "- No response was recommended."
                )
                content = (
                    f"## {assessment.classification.upper()} / "
                    f"{assessment.confidence:.0%}\n\n"
                    f"**{rendered_label}** / "
                    f"`{escape_markdown(item.requested_effort.upper())}`  \n"
                    f"**{usage.total_tokens or 0} tokens** / "
                    f"**${usage.cost_usd:.6f}** / {usage.latency_ms} ms\n\n"
                    f"{escape_markdown(assessment.summary)}\n\n"
                    f"### Rationale\n\n{rationale}\n\n"
                    f"### Recommended actions\n\n{actions}"
                )
        proposal = self._selected_proposal()
        if proposal is not None:
            content += (
                f"\n\n### Response proposal / {proposal.status.upper()}\n\n"
                f"`{proposal.proposal.action}` "
                f"`{escape_markdown(proposal.proposal.target_ip or 'no target')}` - "
                f"{escape_markdown(proposal.proposal.reason)}"
            )
        self.query_one("#investigation-detail", Markdown).update(content)

    def refresh_actions(self) -> None:
        selected = self.selected_investigation()
        proposal = self._selected_proposal()
        pending = proposal is not None and proposal.status == "pending"
        rejectable = proposal is not None and proposal.status in {"pending", "approved"}
        self.query_one("#retry-investigation", Button).disabled = (
            selected is None or selected.status != "failed"
        )
        self.query_one("#approve-response", Button).disabled = not pending or self._transitioning
        self.query_one("#reject-response", Button).disabled = not rejectable or self._transitioning

    def _selected_proposal(self) -> StoredResponseProposal | None:
        selected = self.selected_investigation()
        if selected is None:
            return None
        return next(
            (proposal for proposal in self.proposals if proposal.investigation_id == selected.id),
            None,
        )

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#investigations-state", Static)
        state.update(safe_text(message))
        state.set_class(error, "error")


def _model_label(model_id: str) -> str:
    return OPENAI_MODEL.label if model_id == OPENAI_MODEL.model_id else model_id
