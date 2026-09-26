"""Time-bounded maintenance exceptions with visible scope and audit reasons."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import ClassVar, cast

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Input, Select, Static, TextArea

from ..domain import utc_now
from ..incident_store import IncidentStore
from ..incidents import Family, Incident, SuppressionRule
from ..rules import RulePoints
from .context import safe_text, socketclaw_app
from .detail import DetailScreen
from .incidents import IncidentComment
from .layout import ResponsiveModalScreen as ModalScreen

_FAMILIES: tuple[Family, ...] = (
    "availability",
    "exposure",
    "authentication",
    "firewall",
    "privilege",
    "malware",
    "collector",
)


def _status(item: SuppressionRule) -> str:
    now = utc_now()
    if item.disabled_at:
        return "Ended"
    if item.expires_at <= now:
        return "Expired"
    return "Scheduled" if item.starts_at > now else "Active"


def _scope(item: SuppressionRule) -> str:
    return " / ".join(
        value for value in (item.target, item.log_path, item.rule_code, item.family) if value
    )


class MaintenanceScreen(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]
    DEFAULT_CSS = """
    MaintenanceScreen { background: $background; padding: 1 2; }
    #maintenance-heading { height: 2; text-style: bold; }
    #maintenance-copy { height: 2; color: $text-muted; }
    #maintenance-table { height: 1fr; }
    #maintenance-selection { height: 4; margin-top: 1; color: $text-muted; }
    #maintenance-actions { height: 3; align-horizontal: right; }
    #maintenance-actions Button { min-width: 11; width: auto; margin-left: 1; }
    """

    def __init__(self, store: IncidentStore, context: Incident | None = None) -> None:
        super().__init__()
        self.store = store
        self.context = context
        self.page = 0
        self.has_more = False
        self.items: dict[str, SuppressionRule] = {}

    def compose(self) -> ComposeResult:
        yield Static("MAINTENANCE EXCEPTIONS / Enter Details / Esc Back", id="maintenance-heading")
        yield Static(
            "Limit incident creation for planned work. Original observations stay available.",
            id="maintenance-copy",
            markup=False,
        )
        yield DataTable(id="maintenance-table", cursor_type="row")
        yield Static("Loading exceptions…", id="maintenance-selection", markup=False)
        with Horizontal(id="maintenance-actions"):
            yield Button("Previous", id="maintenance-prev", disabled=True)
            yield Button("Next", id="maintenance-next", disabled=True)
            yield Button("Refresh", id="maintenance-refresh")
            yield Button("New exception", id="maintenance-new", variant="primary")
            yield Button("End early", id="maintenance-end", disabled=True)
            yield Button("Back", id="maintenance-back")

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one(DataTable))
        for label, width in (("STATE", 10), ("SCOPE", 34), ("EXPIRES", 18)):
            table.add_column(label, width=width)
        table.focus()
        self.reload()
        self.set_interval(1, self.refresh_expiry)

    def action_refresh(self) -> None:
        self.reload()

    def refresh_expiry(self) -> None:
        if not self.is_mounted:
            return
        table = cast(DataTable[str], self.query_one(DataTable))
        for key, item in self.items.items():
            table.update_cell(key, table.ordered_columns[0].key, _status(item))
        self.preview()

    def action_close(self) -> None:
        self.dismiss(None)

    @work(exclusive=True, group="maintenance-list")
    async def reload(self) -> None:
        try:
            items = await self.store.suppressions(limit=101, offset=100 * self.page)
        except Exception as exc:
            self.query_one("#maintenance-selection", Static).update(safe_text(str(exc)))
            return
        if not self.is_mounted:
            return
        selected = self.selected()
        self.has_more = len(items) > 100
        self.items = {str(item.id): item for item in items[:100]}
        table = cast(DataTable[str], self.query_one(DataTable))
        scroll_y = table.scroll_y
        table.clear()
        for item in self.items.values():
            table.add_row(
                _status(item),
                safe_text(_scope(item)),
                item.expires_at.astimezone().strftime("%d %b %H:%M %Z"),
                key=str(item.id),
            )
        if selected and str(selected.id) in table.rows:
            table.move_cursor(row=table.get_row_index(str(selected.id)), scroll=False)
            table.call_after_refresh(table.scroll_to, y=scroll_y, animate=False)
        self.query_one("#maintenance-copy", Static).update(
            f"Refreshed {utc_now().astimezone():%H:%M:%S}. Expiry updates live. R reloads changes."
        )
        self.query_one("#maintenance-prev", Button).disabled = self.page == 0
        self.query_one("#maintenance-next", Button).disabled = not self.has_more
        self.preview()

    def selected(self) -> SuppressionRule | None:
        table = cast(DataTable[str], self.query_one(DataTable))
        if not table.row_count:
            return None
        return self.items.get(
            str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        )

    @on(DataTable.RowHighlighted)
    def preview(self) -> None:
        item = self.selected()
        self.query_one("#maintenance-end", Button).disabled = item is None or _status(item) not in {
            "Active",
            "Scheduled",
        }
        self.query_one("#maintenance-selection", Static).update(
            safe_text(
                f"Page {self.page + 1} / {_scope(item)}\nReason: {item.reason}"
                + (f"\nEnded early: {item.disabled_reason}" if item.disabled_at else "")
            )
            if item
            else "No exceptions. New exception adds a scope, reason, and automatic expiry."
        )

    @on(DataTable.RowSelected)
    def details(self) -> None:
        item = self.selected()
        if item:
            from .context import escape_markdown

            content = (
                f"## {_status(item)} exception\n\n{escape_markdown(_scope(item))}\n\n"
                f"Starts: {item.starts_at.astimezone().isoformat(timespec='minutes')}  \n"
                f"Expires: {item.expires_at.astimezone().isoformat(timespec='minutes')}\n\n"
                f"{escape_markdown(item.reason)}"
            )
            if item.disabled_at:
                content += (
                    f"\n\nEnded {item.disabled_at.isoformat()}: "
                    f"{escape_markdown(item.disabled_reason or '')}"
                )
            socketclaw_app(self).push_screen(DetailScreen(content))

    @on(Button.Pressed)
    def button(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "maintenance-refresh":
                self.reload()
            case "maintenance-prev":
                self.page = max(0, self.page - 1)
                self.reload()
            case "maintenance-next":
                if self.has_more:
                    self.page += 1
                    self.reload()
            case "maintenance-new":
                socketclaw_app(self).push_screen(
                    MaintenanceEditor(self.store, self.context), self.created
                )
            case "maintenance-end":
                item = self.selected()
                if item:

                    def end(reason: str | None) -> None:
                        if reason:
                            self.end_exception(item, reason)

                    socketclaw_app(self).push_screen(
                        IncidentComment(
                            "End exception early", draft_key=f"maintenance-end:{item.id}"
                        ),
                        end,
                    )
            case "maintenance-back":
                self.action_close()
            case _:
                pass

    def created(self, saved: bool | None) -> None:
        if saved:
            self.page = 0
            self.reload()

    @work(exclusive=True, group="maintenance-end")
    async def end_exception(self, item: SuppressionRule, reason: str) -> None:
        try:
            await self.store.disable_suppression(item.id, reason)
        except Exception as exc:
            self.query_one("#maintenance-selection", Static).update(safe_text(str(exc)))
            return
        socketclaw_app(self).drafts.pop(f"maintenance-end:{item.id}", None)
        self.reload()


class MaintenanceEditor(ModalScreen[bool]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    MaintenanceEditor { align: center middle; background: $background 80%; }
    #exception-dialog { width: 76; max-width: 100%; height: 100%; max-height: 38;
        padding: 1 2; background: $surface; }
    #exception-title { height: 2; text-style: bold; }
    #exception-scroll { height: 1fr; }
    #exception-scroll Static { height: auto; margin-top: 1; }
    #exception-scroll Input, #exception-scroll Select { margin-top: 0; }
    #exception-reason { height: 4; }
    #exception-feedback { height: 2; color: $text-muted; }
    #exception-actions { height: 3; align-horizontal: right; }
    """

    def __init__(self, store: IncidentStore, context: Incident | None) -> None:
        super().__init__()
        self.store = store
        self.context = context
        self.draft_key = f"maintenance:{context.id if context else 'new'}"

    def compose(self) -> ComposeResult:
        with Vertical(id="exception-dialog"):
            yield Static("NEW MAINTENANCE EXCEPTION", id="exception-title")
            with VerticalScroll(id="exception-scroll"):
                yield Static("All filled scope fields must match. Choose at least one scope field.")
                yield Static("Target (optional, exact match)")
                yield Input(
                    value=self.context.target or "" if self.context else "", id="exception-target"
                )
                yield Static("Log path (optional, exact match)")
                yield Input(id="exception-path", placeholder="/var/log/auth.log")
                yield Static("Detection family")
                yield Select(
                    [("Any family", "any"), *((name.title(), name) for name in _FAMILIES)],
                    value=self.context.family if self.context else "any",
                    allow_blank=False,
                    id="exception-family",
                )
                yield Static("Rule")
                codes = [field.replace("_", ".", 1) for field in RulePoints.model_fields] + [
                    "system.probe_error"
                ]
                yield Select(
                    [("Any rule", "any"), *((code, code) for code in codes)],
                    value="any",
                    allow_blank=False,
                    id="exception-rule",
                )
                yield Static("Start (blank starts now; otherwise ISO date/time with timezone)")
                yield Input(id="exception-start", placeholder="2026-09-17T22:00:00+09:00")
                yield Static("Duration")
                yield Select(
                    [
                        ("15 minutes", 15),
                        ("1 hour", 60),
                        ("4 hours", 240),
                        ("24 hours", 1440),
                        ("7 days", 10080),
                        ("30 days", 43200),
                    ],
                    value=60,
                    allow_blank=False,
                    id="exception-duration",
                )
                yield Static("Reason")
                yield TextArea(id="exception-reason")
            yield Static(
                "Observations and scores are preserved. The exception expires automatically.",
                id="exception-feedback",
                markup=False,
            )
            with Horizontal(id="exception-actions"):
                yield Button("Discard", id="exception-discard")
                yield Button("Back (keep draft)", id="exception-cancel")
                yield Button("Create exception", id="exception-save", variant="primary")

    def on_mount(self) -> None:
        draft = socketclaw_app(self).drafts.get(self.draft_key, {})
        for field in self.query(Input):
            if field.id in draft:
                field.value = draft[field.id]
        for selector in ("exception-family", "exception-rule", "exception-duration"):
            field = cast(Select[object], self.query_one(f"#{selector}", Select))
            if field.id in draft:
                field.value = (
                    int(draft[field.id]) if field.id == "exception-duration" else draft[field.id]
                )
        self.query_one(TextArea).load_text(draft.get("reason", ""))
        self.query_one("#exception-target", Input).focus()

    def action_cancel(self) -> None:
        draft = {str(field.id): field.value for field in self.query(Input)}
        for selector in ("exception-family", "exception-rule", "exception-duration"):
            select = cast(Select[object], self.query_one(f"#{selector}", Select))
            draft[selector] = str(select.value)
        draft["reason"] = self.query_one(TextArea).text
        socketclaw_app(self).drafts[self.draft_key] = draft
        self.dismiss(False)

    @on(Button.Pressed, "#exception-discard")
    def discard(self) -> None:
        socketclaw_app(self).drafts.pop(self.draft_key, None)
        self.dismiss(False)

    @on(Button.Pressed, "#exception-cancel")
    def cancel(self) -> None:
        self.action_cancel()

    @on(Button.Pressed, "#exception-save")
    @work(exclusive=True, group="exception-save")
    async def save(self) -> None:
        button = self.query_one("#exception-save", Button)
        button.disabled = True
        try:
            start_text = self.query_one("#exception-start", Input).value.strip()
            start = datetime.fromisoformat(start_text) if start_text else utc_now()
            family = cast(Select[str], self.query_one("#exception-family", Select)).value
            rule = cast(Select[str], self.query_one("#exception-rule", Select)).value
            duration = cast(Select[int], self.query_one("#exception-duration", Select)).value
            if not isinstance(duration, int):
                raise ValueError("Choose a duration")
            item = SuppressionRule.model_validate(
                dict(
                    target=self.query_one("#exception-target", Input).value.strip() or None,
                    log_path=self.query_one("#exception-path", Input).value.strip() or None,
                    family=None if family == "any" else family,
                    rule_code=None if rule == "any" else rule,
                    starts_at=start,
                    expires_at=start + timedelta(minutes=duration),
                    reason=self.query_one("#exception-reason", TextArea).text.strip(),
                )
            )
            await self.store.create_suppression(item)
        except Exception as exc:
            self.query_one("#exception-feedback", Static).update(safe_text(str(exc)))
            button.disabled = False
            return
        socketclaw_app(self).drafts.pop(self.draft_key, None)
        self.dismiss(True)
