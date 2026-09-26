"""A focused incident desk with a quiet list and an actionable detail reader."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import ClassVar, Literal, cast
from uuid import UUID, uuid4

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.widgets import Button, DataTable, Input, Markdown, Select, Static, Tab, Tabs, TextArea

from ..context import build_incident_context
from ..domain import utc_now
from ..incident_store import IncidentStore
from ..incidents import Incident, IncidentNote, Occurrence, Transition
from ..response_actions import ActionRecord
from .context import escape_markdown, safe_text, socketclaw_app
from .layout import ResponsiveModalScreen as ModalScreen
from .related import RelatedObservations

_FAMILIES = {
    "availability": "Availability",
    "exposure": "Port exposure",
    "authentication": "Auth failures",
    "firewall": "Firewall",
    "privilege": "Privilege",
    "malware": "Malware",
    "collector": "Collector",
}


def _state(item: Incident) -> str:
    return {"open": "OPEN", "acknowledged": "ACKNOWLEDGED", "resolved": "RESOLVED"}[item.status]


def _overview(item: Incident) -> str:
    target = escape_markdown(item.target or "Local log / collector")
    reopened = (
        f"\n\nLast reopened: {item.last_reopened_at.astimezone().strftime('%d %b %H:%M:%S')}"
        if item.last_reopened_at
        else ""
    )
    return (
        f"## {escape_markdown(item.title)}\n\n"
        f"**{_state(item)}** / {item.highest_severity.value.upper()}\n\n"
        f"{target}\n\n"
        f"Observations: **{item.observation_count}** / Occurrences: **{item.occurrence_count}**\n\n"
        f"First seen: {item.first_seen_at.astimezone().strftime('%d %b %H:%M:%S')}  \n"
        f"Last seen: {item.last_seen_at.astimezone().strftime('%d %b %H:%M:%S')}" + reopened
    )


class IncidentDesk(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]
    DEFAULT_CSS = """
    IncidentDesk { background: $background; layout: vertical; padding: 1 2; }
    #desk-heading { height: 2; }
    #desk-title { width: 1fr; height: 2; text-style: bold; color: $text; }
    #desk-shortcuts { width: auto; color: $text-muted; }
    #desk-status { height: 2; color: $text-muted; }
    #desk-toolbar { height: 3; margin-bottom: 1; }
    #desk-tabs { width: 1fr; }
    #desk-tabs Tab { padding: 0 2; }
    #desk-search { width: 30; height: 3; }
    #desk-body { height: 1fr; }
    #incident-table { width: 3fr; height: 1fr; border: none; }
    #desk-inspector { width: 2fr; height: 1fr; border-left: solid $border; padding: 0 2; }
    #desk-preview { margin: 0; padding: 0; }
    #desk-selection { height: 2; color: $text-muted; margin-top: 1; }
    #desk-actions { height: 3; align-horizontal: right; }
    #desk-actions Button { margin-left: 1; min-width: 10; width: auto; }
    IncidentDesk.compact { padding: 0 1; }
    IncidentDesk.compact #desk-inspector { display: none; }
    IncidentDesk.compact #incident-table { width: 1fr; }
    IncidentDesk.compact #desk-search { width: 22; }
    """

    def __init__(self, store: IncidentStore) -> None:
        super().__init__()
        self.store = store
        self.items: dict[str, Incident] = {}
        self.page = 0
        self.cursors: list[tuple[datetime, UUID] | None] = [None]
        self.through = utc_now()
        self.has_more = False

    def compose(self) -> ComposeResult:
        with Horizontal(id="desk-heading"):
            yield Static("INCIDENT DESK", id="desk-title")
            yield Static("Enter Open   R Refresh   Esc Back", id="desk-shortcuts")
        yield Static("Loading local incident history…", id="desk-status", markup=False)
        with Horizontal(id="desk-toolbar"):
            yield Tabs(
                Tab("Unresolved", id="needs-attention"),
                Tab("Resolved", id="resolved"),
                Tab("All", id="all-cases"),
                id="desk-tabs",
            )
            yield Input(placeholder="Search all incidents", id="desk-search")
        with Horizontal(id="desk-body"):
            yield DataTable(id="incident-table", cursor_type="row", zebra_stripes=False)
            with VerticalScroll(id="desk-inspector"):
                yield Markdown(
                    "Select an incident to read its context.", id="desk-preview", open_links=False
                )
        yield Static("", id="desk-selection", markup=False)
        with Horizontal(id="desk-actions"):
            yield Button("Previous", id="desk-prev", disabled=True)
            yield Button("Next", id="desk-next", disabled=True)
            yield Button("Refresh", id="desk-refresh")
            yield Button("Exceptions", id="desk-exceptions")
            yield Button("Open incident", id="desk-open", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.set_class(self.size.width < 120, "compact")
        table = cast(DataTable[str | Text], self.query_one("#incident-table", DataTable))
        for label, width in (
            ("STATE", 8),
            ("SEV", 8),
            ("TYPE", 13),
            ("TARGET / SOURCE", 20),
            ("OBS", 4),
        ):
            table.add_column(label, width=width)
        table.focus()
        self.refresh_data()
        self.set_interval(3, self.check_updates)

    @work(exclusive=True, group="incident-desk-watermark")
    async def check_updates(self) -> None:
        if not self.is_mounted:
            return
        try:
            counts = await self.store.counts()
        except Exception:
            return  # Explicit Refresh reports a persistent read failure.
        if self.is_mounted and counts != getattr(self, "_counts", None):
            self.query_one("#desk-status", Static).update(
                f"{max(0, sum(counts.values()) - sum(getattr(self, '_counts', {}).values()))} "
                "new incident(s); counts changed. R Refresh keeps your selection."
            )

    def on_resize(self, event: Resize) -> None:
        self.set_class(event.size.width < 120, "compact")

    def action_close(self) -> None:
        self.dismiss(None)

    def action_refresh(self) -> None:
        self.through = utc_now()
        self.refresh_data()

    @on(Button.Pressed, "#desk-exceptions")
    def exceptions(self) -> None:
        from .suppressions import MaintenanceScreen

        socketclaw_app(self).push_screen(MaintenanceScreen(self.store, self.selected()))

    @on(Button.Pressed, "#desk-refresh")
    def refresh_button(self) -> None:
        self.action_refresh()

    @on(Tabs.TabActivated, "#desk-tabs")
    def change_tab(self) -> None:
        self.page = 0
        self.cursors = [None]
        self.through = utc_now()
        self.refresh_data()

    @on(Input.Changed, "#desk-search")
    def search_changed(self) -> None:
        self.page = 0
        self.cursors = [None]
        self.through = utc_now()
        self.refresh_data()

    @on(Button.Pressed, "#desk-prev")
    def previous_page(self) -> None:
        if self.page:
            self.page -= 1
            self.cursors.pop()
            self.refresh_data()

    @on(Button.Pressed, "#desk-next")
    def next_page(self) -> None:
        if self.has_more and self.items:
            last = list(self.items.values())[-1]
            self.cursors.append((last.first_seen_at, last.id))
            self.page += 1
            self.refresh_data()

    @work(exclusive=True, group="incident-desk-load")
    async def refresh_data(self) -> None:
        if not self.is_mounted:
            return
        active = self.query_one("#desk-tabs", Tabs).active
        try:
            rows, counts = await asyncio.gather(
                self.store.list(
                    status="resolved" if active == "resolved" else None,
                    active_only=active == "needs-attention",
                    limit=101,
                    before_cursor=self.cursors[-1],
                    through=self.through,
                    text=self.query_one("#desk-search", Input).value.strip() or None,
                ),
                self.store.counts(),
            )
        except Exception as exc:
            self.query_one("#desk-status", Static).update(
                safe_text(f"Cannot load incidents: {exc}")
            )
            return
        if not self.is_mounted:
            return
        self._counts = counts
        self.has_more = len(rows) > 100
        self.items = {str(item.id): item for item in rows[:100]}
        self.query_one("#desk-status", Static).update(
            f"{counts.get('open', 0)} open   /   "
            f"{counts.get('acknowledged', 0)} acknowledged   /   "
            f"{counts.get('resolved', 0)} resolved / Page {self.page + 1} / "
            f"Refreshed {utc_now().astimezone():%H:%M:%S} (R to update)"
        )
        self.query_one("#desk-prev", Button).disabled = self.page == 0
        self.query_one("#desk-next", Button).disabled = not self.has_more
        self._render_rows()

    def _render_rows(self) -> None:
        table = cast(DataTable[str | Text], self.query_one("#incident-table", DataTable))
        selected = self.selected()
        scroll_y = table.scroll_y
        needle = self.query_one("#desk-search", Input).value.casefold().strip()
        filtered = [
            item
            for item in self.items.values()
            if needle in f"{item.title} {item.target or ''} {item.family}".casefold()
        ]
        table.clear()
        for item in filtered:
            severity = item.highest_severity.value
            color = {"critical": "bright_red", "high": "yellow", "medium": "cyan"}.get(
                severity, "grey70"
            )
            table.add_row(
                Text(
                    "ACK" if item.status == "acknowledged" else _state(item),
                    style="bold" if item.status == "open" else "dim",
                ),
                Text(severity.upper(), style=color),
                _FAMILIES[item.family],
                safe_text(item.target or "Local source"),
                str(item.observation_count),
                key=str(item.id),
            )
        if selected is not None and str(selected.id) in table.rows:
            table.move_cursor(row=table.get_row_index(str(selected.id)), scroll=False)
            table.call_after_refresh(table.scroll_to, y=scroll_y, animate=False)
        self.query_one("#desk-open", Button).disabled = not bool(filtered)
        if not filtered:
            self.query_one("#desk-preview", Markdown).update(
                "## No incidents to show\n\nAdjust the filter or use All to review closed history."
            )
            self.query_one("#desk-selection", Static).update(
                "No incidents match this page and filter."
            )
        else:
            self._preview()

    def selected(self) -> Incident | None:
        table = cast(DataTable[str | Text], self.query_one("#incident-table", DataTable))
        if not table.row_count:
            return None
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        return self.items.get(key)

    @on(DataTable.RowHighlighted, "#incident-table")
    def highlighted(self) -> None:
        self._preview()

    def _preview(self) -> None:
        item = self.selected()
        if item is not None:
            self.query_one("#desk-preview", Markdown).update(_overview(item))
            self.query_one("#desk-selection", Static).update(
                safe_text(
                    f"{item.title}   /   Occurrences: {item.occurrence_count}   /   Enter to open"
                )
            )

    @on(DataTable.RowSelected, "#incident-table")
    @on(Button.Pressed, "#desk-open")
    def open_selected(self) -> None:
        item = self.selected()
        if item is not None:
            socketclaw_app(self).push_screen(IncidentReader(self.store, item), self._reader_closed)

    def _reader_closed(self, _: None) -> None:
        self.refresh_data()


class IncidentReader(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Back to incidents"),
        Binding("r", "refresh", "Refresh"),
    ]
    DEFAULT_CSS = """
    IncidentReader { background: $background; layout: vertical; padding: 1 2; }
    #case-heading { height: 3; margin-bottom: 1; }
    #case-title { width: 1fr; padding-top: 1; text-style: bold; color: $primary; }
    #case-heading Button { width: auto; min-width: 13; margin-left: 1; }
    #case-scroll { height: 1fr; }
    #case-content { margin: 0; padding: 0 1; }
    #case-content MarkdownH2 { margin-top: 0; }
    #case-content MarkdownH3 { margin-top: 1; }
    #case-feedback { height: 2; color: $text-muted; }
    #case-actions { height: 3; align-horizontal: right; }
    #case-actions Button { margin-left: 1; }
    """

    def __init__(self, store: IncidentStore, incident: Incident) -> None:
        super().__init__()
        self.store = store
        self.incident = incident
        self._note_ids: dict[str, UUID] = {}
        self._applying = False

    def compose(self) -> ComposeResult:
        with Horizontal(id="case-heading"):
            yield Static("INCIDENT / Esc Back", id="case-title")
            yield Button("Refresh", id="case-refresh")
            yield Button("Observations", id="case-evidence")
            yield Button("Export .md", id="case-export")
        with VerticalScroll(id="case-scroll", can_focus=True):
            yield Markdown(_overview(self.incident), id="case-content", open_links=False)
        yield Static("", id="case-feedback", markup=False)
        with Horizontal(id="case-actions"):
            yield Button("Record action", id="case-action")
            yield Button("Add note", id="case-note")
            yield Button("Acknowledge", id="case-ack", variant="primary")
            yield Button("Resolve", id="case-resolve")
            yield Button("Back", id="case-back")

    def on_mount(self) -> None:
        self.query_one("#case-scroll").focus()
        self.reload_detail()
        self.set_interval(2, self.check_updates)

    @on(Button.Pressed, "#case-refresh")
    def action_refresh(self) -> None:
        self.reload_detail()

    @work(exclusive=True, group="incident-reader-watermark")
    async def check_updates(self) -> None:
        try:
            current = await self.store.get(self.incident.id)
        except Exception:
            return  # Explicit Refresh reports a persistent read failure.
        if self.is_mounted and current and current.revision != self.incident.revision:
            self.query_one("#case-feedback", Static).update(
                "New evidence or operator changes available. R Refresh keeps your place."
            )

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#case-back")
    def back_button(self) -> None:
        self.action_close()

    @work(exclusive=True, group="incident-reader")
    async def reload_detail(self) -> None:
        try:
            current, occurrences, timeline, notes = await asyncio.gather(
                self.store.get(self.incident.id),
                self.store.occurrences(self.incident.id),
                self.store.transitions(self.incident.id, newest_first=True),
                self.store.notes(self.incident.id, newest_first=True),
            )
        except Exception as exc:
            self.query_one("#case-feedback", Static).update(
                safe_text(f"Cannot load history: {exc}")
            )
            return
        if current is None:
            self.query_one("#case-feedback", Static).update("This incident is no longer available.")
            return
        if not self.is_mounted:
            return
        self.incident = current
        scroll = self.query_one("#case-scroll", VerticalScroll)
        old_y = scroll.scroll_y
        content = _detail(current, occurrences, timeline, notes)
        repository = socketclaw_app(self).services.repository
        if repository is not None:
            report = await repository.incident_report(current.id)
            if report is not None:
                context = build_incident_context(report)
                content += "\n\n### Local evidence assessment\n\n" + "\n".join(
                    "- " + escape_markdown(line) for line in context.local_summary
                )
                content += "\n\n### Next checks / runbook\n\n" + "\n".join(
                    "- " + escape_markdown(line) for line in context.runbook
                )
                content += "\n\n### Action records\n\n" + (
                    "\n\n".join(
                        f"**{record.status}** / {escape_markdown(record.summary)}\n\n"
                        + "Evidence: "
                        + ", ".join(str(identifier) for identifier in record.evidence_ids)
                        for record in report.action_records
                    )
                    or "No action has been recorded as performed or verified."
                )
        if not self.is_mounted:
            return
        self.query_one("#case-content", Markdown).update(content)
        scroll.call_after_refresh(scroll.scroll_to, y=old_y, animate=False)
        self.query_one("#case-ack", Button).disabled = current.status != "open"
        resolve = self.query_one("#case-resolve", Button)
        resolve.label = "Reopen" if current.status == "resolved" else "Resolve"
        resolve.variant = "primary" if current.status != "open" else "default"
        self.query_one("#case-feedback", Static).update(
            "Recovery observations and operator resolution are recorded separately."
        )

    @on(Button.Pressed, "#case-evidence")
    def observations(self) -> None:
        socketclaw_app(self).push_screen(RelatedObservations(self.incident.id))

    @on(Button.Pressed, "#case-export")
    @work(exclusive=True, group="incident-export")
    async def export_report(self) -> None:
        button = self.query_one("#case-export", Button)
        button.disabled = True
        try:
            destination = await socketclaw_app(self).export_incident(self.incident.id)
            self.query_one("#case-feedback", Static).update(safe_text(f"Exported: {destination}"))
        except Exception as exc:
            self.query_one("#case-feedback", Static).update(safe_text(f"Export failed: {exc}"))
        finally:
            button.disabled = False

    @on(Button.Pressed, "#case-ack")
    def acknowledge(self) -> None:
        self._prompt("acknowledged")

    @on(Button.Pressed, "#case-resolve")
    def resolve(self) -> None:
        self._prompt("open" if self.incident.status == "resolved" else "resolved")

    @on(Button.Pressed, "#case-action")
    def record_action(self) -> None:
        def reload_after_action(_: bool | None) -> None:
            self.reload_detail()

        socketclaw_app(self).push_screen(ActionEditor(self.incident), reload_after_action)

    @on(Button.Pressed, "#case-note")
    def add_note(self) -> None:
        self._prompt("note")

    def _prompt(self, action: Literal["acknowledged", "resolved", "open", "note"]) -> None:
        if self._applying:
            return
        labels = {
            "acknowledged": "Acknowledge incident",
            "resolved": "Resolve incident",
            "open": "Reopen incident",
            "note": "Add a note",
        }

        def apply_comment(body: str | None) -> None:
            if body:
                self._applying = True
                self._apply(action, body)

        socketclaw_app(self).push_screen(
            IncidentComment(labels[action], draft_key=f"incident:{self.incident.id}:{action}"),
            apply_comment,
        )

    @work(exclusive=True, group="incident-reader-action")
    async def _apply(
        self, action: Literal["acknowledged", "resolved", "open", "note"], body: str
    ) -> None:
        try:
            if action == "note":
                await self.store.add_note(
                    self.incident.id,
                    body,
                    expected_revision=self.incident.revision,
                    note_id=self._note_ids.setdefault(body, uuid4()),
                )
            else:
                await self.store.change_status(
                    self.incident.id, action, reason=body, expected_revision=self.incident.revision
                )
        except Exception as exc:
            await self.reload_detail().wait()
            self.query_one("#case-feedback", Static).update(
                safe_text(
                    f"{exc} Draft kept. Review current state, then reopen the reason to retry."
                )
            )
            self._applying = False
            return
        self._applying = False
        socketclaw_app(self).drafts.pop(f"incident:{self.incident.id}:{action}", None)
        self._note_ids.pop(body, None)
        self.reload_detail()


class IncidentComment(ModalScreen[str | None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    IncidentComment { align: center middle; background: $background 80%; }
    #case-comment-dialog {
        width: 64; max-width: 96%; height: 16; padding: 1 2;
        background: $surface; border: solid $primary;
    }
    #case-comment-title { height: 2; text-style: bold; }
    #case-comment-copy { height: 2; color: $text-muted; }
    #case-comment-body { height: 5; margin-bottom: 1; }
    #case-comment-buttons { height: 3; align-horizontal: right; }
    """

    def __init__(self, title: str, *, draft_key: str | None = None) -> None:
        super().__init__()
        self.heading = title
        self.draft_key = draft_key or f"comment:{title}"

    def compose(self) -> ComposeResult:
        with Vertical(id="case-comment-dialog"):
            yield Static(self.heading, id="case-comment-title")
            yield Static(
                "Leave a reason for the next person reviewing this incident.",
                id="case-comment-copy",
            )
            yield TextArea(
                socketclaw_app(self).drafts.get(self.draft_key, {}).get("body", ""),
                id="case-comment-body",
            )
            with Horizontal(id="case-comment-buttons"):
                yield Button("Discard", id="case-comment-discard")
                yield Button("Back (keep draft)", id="case-comment-cancel")
                yield Button("Save", id="case-comment-save", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()

    def action_cancel(self) -> None:
        self._keep_draft()
        self.dismiss(None)

    def _keep_draft(self) -> None:
        socketclaw_app(self).drafts[self.draft_key] = {"body": self.query_one(TextArea).text}

    @on(Button.Pressed, "#case-comment-discard")
    def discard(self) -> None:
        socketclaw_app(self).drafts.pop(self.draft_key, None)
        self.dismiss(None)

    @on(Button.Pressed, "#case-comment-cancel")
    def cancel_button(self) -> None:
        self.action_cancel()

    @on(TextArea.Changed)
    def comment_changed(self) -> None:
        self.query_one("#case-comment-save", Button).disabled = not bool(
            self.query_one(TextArea).text.strip()
        )

    @on(Button.Pressed, "#case-comment-save")
    def save_comment(self) -> None:
        body = self.query_one(TextArea).text.strip()
        if body:
            self._keep_draft()
            self.dismiss(body)


def _detail(
    item: Incident,
    occurrences: list[Occurrence],
    timeline: list[Transition],
    notes: list[IncidentNote],
) -> str:
    content = _overview(item)
    content += "\n\n---\n\n### Timeline\n\n"
    content += (
        "\n\n".join(
            f"**{change.at.astimezone().strftime('%d %b %H:%M:%S')} / "
            f"{change.action.replace('_', ' ').title()}**  \n"
            f"{escape_markdown(change.reason)}"
            for change in timeline
        )
        or "No transitions recorded."
    )
    content += "\n\n### Occurrences\n\n" + "\n\n".join(
        f"**#{occurrence.number}** / {occurrence.observation_count} observations  \n"
        f"Started {occurrence.started_at.astimezone().strftime('%d %b %H:%M:%S')}"
        + (
            f" / recovery observed {occurrence.recovered_at.astimezone().strftime('%H:%M:%S')}"
            if occurrence.recovered_at
            else ""
        )
        for occurrence in occurrences
    )
    content += "\n\n### Notes\n\n"
    content += (
        "\n\n".join(
            f"**{note.at.astimezone().strftime('%d %b %H:%M:%S')}**  \n{escape_markdown(note.body)}"
            for note in notes
        )
        or "No notes yet. Add context for the next review."
    )
    return content


class ActionEditor(ModalScreen[bool]):
    """Record operator work without executing commands or implying automatic verification."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back")]
    DEFAULT_CSS = """
    ActionEditor { background: $background; layout: vertical; padding: 0 2; }
    ActionEditor VerticalScroll { height: 1fr; }
    ActionEditor Static { height: auto; margin-bottom: 1; }
    ActionEditor TextArea { height: 5; margin: 1 0; }
    ActionEditor Input, ActionEditor Select { margin-bottom: 1; }
    """

    def __init__(self, incident: Incident) -> None:
        super().__init__()
        self.incident = incident
        self.draft_key = f"action:{incident.id}"
        self.record_id = uuid4()

    def compose(self) -> ComposeResult:
        yield Static("RECORD MANUAL ACTION / no commands are executed")
        with VerticalScroll():
            yield Static(
                "Choose the outcome you actually observed. Approval alone is not execution."
            )
            yield Select(
                [
                    ("User performed", "user_performed"),
                    ("Failed", "failed"),
                    ("Rolled back", "rolled_back"),
                    ("Verified against evidence", "verified"),
                ],
                value="user_performed",
                allow_blank=False,
                id="action-status",
            )
            yield Static("What did you do, and what happened?")
            yield TextArea(id="action-summary")
            yield Static(
                "Observation IDs (comma separated). Verification requires related evidence."
            )
            yield Input(id="action-evidence")
            yield Static("", id="action-feedback", markup=False)
        with Horizontal(classes="action-row"):
            yield Button("Save record", id="action-save", variant="primary")
            yield Button("Back (keep draft)", id="action-back")
            yield Button("Discard", id="action-discard")

    def on_mount(self) -> None:
        draft = socketclaw_app(self).drafts.get(self.draft_key, {})
        self.query_one("#action-summary", TextArea).load_text(draft.get("summary", ""))
        self.query_one("#action-evidence", Input).value = draft.get("evidence", "")
        self.query_one("#action-status", Select).value = draft.get("status", "user_performed")
        self.query_one(TextArea).focus()

    @on(Button.Pressed, "#action-back")
    def action_close(self) -> None:
        socketclaw_app(self).drafts[self.draft_key] = {
            "summary": self.query_one(TextArea).text,
            "evidence": self.query_one(Input).value,
            "status": str(cast(Select[str], self.query_one(Select)).value),
        }
        self.dismiss(False)

    @on(Button.Pressed, "#action-discard")
    def discard(self) -> None:
        socketclaw_app(self).drafts.pop(self.draft_key, None)
        self.dismiss(False)

    @on(Button.Pressed, "#action-save")
    @work(exclusive=True, group="manual-action-save")
    async def save_record(self) -> None:
        button = self.query_one("#action-save", Button)
        button.disabled = True
        try:
            repository = socketclaw_app(self).services.repository
            if repository is None:
                raise RuntimeError("Action storage is unavailable")
            record = ActionRecord(
                id=self.record_id,
                incident_id=self.incident.id,
                status=cast(
                    Literal["user_performed", "failed", "rolled_back", "verified"],
                    cast(Select[str], self.query_one(Select)).value,
                ),
                summary=self.query_one(TextArea).text.strip(),
                evidence_ids=tuple(
                    UUID(value.strip())
                    for value in self.query_one(Input).value.split(",")
                    if value.strip()
                ),
            )
            await repository.record_action(record)
        except Exception as exc:
            self.query_one("#action-feedback", Static).update(safe_text(str(exc)))
            button.disabled = False
            return
        socketclaw_app(self).drafts.pop(self.draft_key, None)
        self.dismiss(True)
