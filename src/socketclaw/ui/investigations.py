"""OpenAI investigation queue, usage accounting, and response review."""

from __future__ import annotations

from typing import cast
from uuid import UUID

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Markdown, Static

from ..config import OPENAI_MODEL
from ..storage import ResponseStatus, StoredInvestigation, StoredResponseProposal
from .context import socketclaw_app
from .dialogs import ConfirmResponseScreen


class InvestigationsView(Vertical):
    """Durable AI analysis history with explicit human response gates."""

    def __init__(self) -> None:
        super().__init__(id="investigations-view", classes="workspace-view")
        self.investigations: list[StoredInvestigation] = []
        self.proposals: list[StoredResponseProposal] = []
        self._selected_id: UUID | None = None

    def compose(self) -> ComposeResult:
        yield Static("INVESTIGATIONS / OPENAI", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Analysis queue", classes="view-title")
            yield Static("", id="investigation-totals", classes="view-hint")
        yield Static(
            "Loading investigation history…",
            id="investigations-state",
            classes="inline-state",
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
            )
        with Horizontal(classes="action-row"):
            yield Button("Retry", id="retry-investigation", variant="primary")
            yield Button("Simulate response", id="simulate-response")
            yield Button("Approve response", id="approve-response")

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
            self.investigations = await repository.list_investigations(limit=500)
            self.proposals = await repository.list_response_proposals(limit=500)
        except Exception as exc:
            self._show_state(f"Could not load investigations: {exc}", error=True)
            return
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

    @on(DataTable.RowHighlighted, "#investigations-table")
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            self._selected_id = UUID(str(event.row_key.value))
        except (TypeError, ValueError):
            self._selected_id = None
        self._render_detail()

    @on(Button.Pressed, "#retry-investigation")
    def retry(self) -> None:
        selected = self.selected_investigation()
        if selected is None:
            self._show_state("Select a failed investigation to retry.")
            return
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

    @on(Button.Pressed, "#simulate-response")
    def simulate_response(self) -> None:
        self._transition_response("simulated", confirm=False)

    @on(Button.Pressed, "#approve-response")
    def approve_response(self) -> None:
        self._transition_response("approved", confirm=True)

    def _transition_response(self, status: ResponseStatus, *, confirm: bool) -> None:
        proposal = self._selected_proposal()
        if proposal is None:
            self._show_state("This investigation has no response proposal.")
            return
        app = socketclaw_app(self)
        target_ip = proposal.proposal.target_ip
        if (
            status in {"approved", "executed"}
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
                ),
            )
            return
        self._update_response(proposal.id, status)

    def _confirmed_transition(
        self,
        accepted: bool | None,
        proposal_id: UUID,
        status: ResponseStatus,
    ) -> None:
        if accepted:
            self._update_response(proposal_id, status)

    @work(exclusive=True, group="response-transition")
    async def _update_response(
        self,
        proposal_id: UUID,
        status: ResponseStatus,
    ) -> None:
        app = socketclaw_app(self)
        repository = app.services.repository
        if repository is None:
            self._show_state("Response storage is unavailable.", error=True)
            return
        try:
            await repository.update_response_proposal_status(proposal_id, status)
        except Exception as exc:
            self._show_state(f"Response was not changed: {exc}", error=True)
        else:
            self._show_state(f"Response marked {status}.")
            self.refresh_data()

    def _render_rows(self) -> None:
        table = cast(
            DataTable[str],
            self.query_one("#investigations-table", DataTable),
        )
        table.clear()
        for item in self.investigations:
            usage = item.usage
            table.add_row(
                item.created_at.astimezone().strftime("%H:%M:%S"),
                item.status.upper(),
                _model_label(item.model_id),
                item.requested_effort.upper(),
                str(usage.total_tokens or 0) if usage else "-",
                f"${usage.cost_usd:.6f}" if usage else "-",
                key=str(item.id),
            )
        total_tokens = sum(
            item.usage.total_tokens or 0 for item in self.investigations if item.usage is not None
        )
        total_cost = sum(
            item.usage.cost_usd for item in self.investigations if item.usage is not None
        )
        self.query_one("#investigation-totals", Static).update(
            f"{total_tokens:,} tokens / ${total_cost:.6f} estimated cost"
        )
        if not self.investigations:
            self._selected_id = None
            self._show_state("No investigations yet. Select an event and press I.")
            return
        self._selected_id = self.investigations[0].id
        table.move_cursor(row=0)
        self._show_state(f"{len(self.investigations)} durable investigation record(s).")
        self._render_detail()

    def _render_detail(self) -> None:
        item = self.selected_investigation()
        if item is None:
            self.query_one("#investigation-detail", Markdown).update(
                "No investigation is selected."
            )
            return
        label = _model_label(item.model_id)
        if item.status == "failed":
            content = (
                f"## Investigation failed\n\n**{label}** / "
                f"`{item.requested_effort.upper()}`\n\n"
                f"{item.error or 'No provider error was recorded.'}"
            )
        else:
            assessment = item.assessment
            usage = item.usage
            if assessment is None or usage is None:
                content = "## Invalid record\n\nThe completed result is missing data."
            else:
                rationale = "\n".join(f"- {line}" for line in assessment.rationale)
                actions = (
                    "\n".join(f"- {line}" for line in assessment.recommended_actions)
                    or "- No response was recommended."
                )
                content = (
                    f"## {assessment.classification.upper()} / "
                    f"{assessment.confidence:.0%}\n\n"
                    f"**{label}** / `{item.requested_effort.upper()}`  \n"
                    f"**{usage.total_tokens or 0} tokens** / "
                    f"**${usage.cost_usd:.6f}** / {usage.latency_ms} ms\n\n"
                    f"{assessment.summary}\n\n### Rationale\n\n{rationale}\n\n"
                    f"### Recommended actions\n\n{actions}"
                )
        proposal = self._selected_proposal()
        if proposal is not None:
            content += (
                f"\n\n### Response proposal / {proposal.status.upper()}\n\n"
                f"`{proposal.proposal.action}` "
                f"`{proposal.proposal.target_ip or 'no target'}` - "
                f"{proposal.proposal.reason}"
            )
        self.query_one("#investigation-detail", Markdown).update(content)

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
        state.update(message)
        state.set_class(error, "error")


def _model_label(model_id: str) -> str:
    return OPENAI_MODEL.label if model_id == OPENAI_MODEL.model_id else model_id
