"""Owner-backed history cleanup and notification diagnostics in either TUI mode."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, DataTable, Input, Static

from .context import safe_text, socketclaw_app
from .layout import ResponsiveModalScreen


class OperationsScreen(ResponsiveModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back")]
    DEFAULT_CSS = """
    OperationsScreen { layout: vertical; padding: 0 1; background: $surface; }
    OperationsScreen > Static { height: auto; }
    #operations-days { height: 3; }
    #operations-actions, #operations-job-actions { height: 3; }
    #operations-actions Button, #operations-job-actions Button { width: 1fr; min-width: 8; }
    #operations-jobs { height: 5; }
    #operations-result-scroll { height: 1fr; min-height: 2; }
    #operations-result { height: auto; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            (
                "STORAGE AND NOTIFICATIONS / Apply creates a backup before "
                "deleting old normal records."
            ),
            markup=False,
        )
        yield Input(
            "30",
            placeholder="Normal history retention in days",
            id="operations-days",
            type="integer",
        )
        with Horizontal(id="operations-actions"):
            yield Button("Preview", id="operations-preview")
            yield Button("Apply cleanup", id="operations-apply", variant="warning")
            yield Button("Backups", id="operations-backups")
            yield Button("Alerts", id="operations-alerts")
        yield DataTable(id="operations-jobs", cursor_type="row")
        with Horizontal(id="operations-job-actions"):
            yield Button("Refresh", id="operations-refresh")
            yield Button("Resume", id="operations-resume")
            yield Button("Cancel job", id="operations-cancel")
            yield Button("Back", id="operations-close")
        with VerticalScroll(id="operations-result-scroll"):
            yield Static("", id="operations-result", markup=False)

    def on_mount(self) -> None:
        self.query_one("#operations-jobs", DataTable).add_columns(
            "JOB", "STATE", "DELETED", "REMAINING"
        )
        self.refresh_jobs()
        self.set_interval(2, self.refresh_jobs)

    @work(exclusive=True, group="operations-refresh")
    async def refresh_jobs(self) -> None:
        application = socketclaw_app(self).services.application
        if application is None:
            return
        try:
            jobs = await application.execute("retention.list", {})
            table = cast(DataTable[str], self.query_one("#operations-jobs", DataTable))
            selected = (
                table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
                if table.row_count
                else None
            )
            table.clear()
            for job in jobs:
                table.add_row(
                    job["id"][:8],
                    job["status"],
                    str(job["deleted"]),
                    str(job["remaining"]),
                    key=job["id"],
                )
            if selected is not None and selected in [job["id"] for job in jobs]:
                table.move_cursor(row=table.get_row_index(selected), scroll=False)
        except Exception as exc:
            self.query_one("#operations-result", Static).update(safe_text(str(exc)))

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        identifier = event.button.id or ""
        if identifier == "operations-close":
            self.action_close()
        elif identifier == "operations-refresh":
            self.refresh_jobs()
        elif identifier.startswith("operations-"):
            self.run_operation(identifier.removeprefix("operations-"))

    @work(exclusive=True, group="operations-action")
    async def run_operation(self, action: str) -> None:
        application = socketclaw_app(self).services.application
        if application is None:
            return
        try:
            if action in {"preview", "apply"}:
                value = await application.execute(
                    f"retention.{action}",
                    {"days": int(self.query_one("#operations-days", Input).value)},
                )
            elif action in {"resume", "cancel"}:
                table = cast(DataTable[str], self.query_one("#operations-jobs", DataTable))
                if not table.row_count:
                    raise ValueError("Select a cleanup job first")
                key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
                value = await application.execute(f"retention.{action}", {"identifier": key})
            else:
                value = await application.execute(
                    "backups.list" if action == "backups" else "notification.status", {}
                )
            self.query_one("#operations-result", Static).update(
                safe_text(describe_operation(action, value))
            )
            self.refresh_jobs()
        except Exception as exc:
            self.query_one("#operations-result", Static).update(safe_text(str(exc)))

    def action_close(self) -> None:
        self.dismiss(None)


def describe_operation(action: str, value: Any) -> str:
    if action == "preview":
        return (
            f"Eligible normal records: {value['eligible']:,}\n"
            f"Protected records: {value['protected']:,}\n"
            f"Before: {value['cutoff']}\n"
            f"Backup headroom needed: {value['backup_required_bytes'] / 1048576:,.1f} MiB\n"
            f"Available space: {value['free_bytes'] / 1048576:,.1f} MiB\n"
            "Apply creates a verified backup and deletes eligible records in small batches. "
            "Database file size may remain unchanged."
        )
    if action == "backups":
        return (
            "\n".join(
                f"{Path(item['path']).name}\n"
                f"  {item['bytes'] / 1048576:,.1f} MiB / "
                f"{'protected' if item['pinned'] else 'eligible for retention policy'}"
                for item in value
            )
            or "No managed backups yet."
        )
    if action == "alerts":
        return (
            f"Notification worker: {value['worker_state']}\n"
            f"Pending: {value['pending']} / Failed: {value['failed']} / Held: {value['held']}\n"
            f"Delivered: {value['delivered']} / Cancelled: {value.get('cancelled', 0)}\n"
            f"Historical delivery review: {value['reconciliation']}\n"
            f"Last error: {value.get('last_error') or 'None'}\n"
            "Use notification-status --details to inspect held delivery IDs."
        )
    return (
        f"Cleanup {value['id'][:8]}: {value['status']}\n"
        f"Deleted: {value['deleted']:,} / Remaining: {value['remaining']:,}\n"
        f"Protected: {value['protected']:,}\n"
        f"Backup: {value.get('backup') or 'Preparing'}\n"
        f"{value.get('error') or 'Collection continues while cleanup runs.'}"
    )


class StopCollectorScreen(ResponsiveModalScreen[bool]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    StopCollectorScreen { background: $surface; padding: 1; layout: vertical; }
    StopCollectorScreen Static { height: auto; }
    StopCollectorScreen Horizontal { height: 3; }
    """

    def compose(self) -> ComposeResult:
        yield Static("Stop the collector? Closing a viewer normally leaves collection running.")
        yield Static("This action stops scheduled monitoring for every connected viewer.")
        with Horizontal():
            yield Button("Cancel", id="stop-owner-cancel")
            yield Button("Stop collector", id="stop-owner-confirm", variant="error")

    def action_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed)
    def confirm(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "stop-owner-confirm")
