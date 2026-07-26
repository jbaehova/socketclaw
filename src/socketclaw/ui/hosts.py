"""Watch-target management and manual diagnostics."""

from __future__ import annotations

from typing import cast

from pydantic import ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static

from ..config import AppConfig
from .context import socketclaw_app


class HostsView(Vertical):
    """Editable monitoring target inventory."""

    def __init__(self) -> None:
        super().__init__(id="hosts-view", classes="workspace-view")

    def compose(self) -> ComposeResult:
        yield Static("HOSTS / WATCH TARGETS", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Local watch inventory", classes="view-title")
            yield Static("Manual diagnostics are read-only.", classes="view-hint")
        with Horizontal(classes="filter-row"):
            yield Input(placeholder="IP address or hostname", id="host-target")
            yield Button("Add target", id="add-host", variant="primary")
        yield Static("", id="hosts-state", classes="inline-state")
        yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="action-row"):
            yield Button("Ping now", id="ping-host", variant="primary")
            yield Button("Scan ports", id="scan-host")
            yield Button("Remove", id="remove-host", variant="error")

    def on_mount(self) -> None:
        self.query_one("#hosts-table", DataTable).add_columns(
            "TARGET", "PING", "PORT SCAN", "PORTS"
        )
        self.refresh_targets()

    def refresh_targets(self) -> None:
        app = socketclaw_app(self)
        table = cast(DataTable[str], self.query_one("#hosts-table", DataTable))
        table.clear()
        for target in app.config.targets:
            table.add_row(
                target,
                f"{app.config.ping_interval:g}s",
                f"{app.config.scan_interval:g}s",
                ", ".join(str(port) for port in app.config.ports),
                key=target,
            )
        self._show_state(f"{len(app.config.targets)} target(s) monitored.")

    @on(Button.Pressed, "#add-host")
    def add_target(self) -> None:
        app = socketclaw_app(self)
        target = self.query_one("#host-target", Input).value.strip()
        try:
            updated = app.config.model_copy(update={"targets": [*app.config.targets, target]})
            updated = AppConfig.model_validate(updated.model_dump())
        except ValidationError as exc:
            self._show_state(_validation_message(exc), error=True)
            return
        app.save_config(updated)
        self.query_one("#host-target", Input).value = ""
        self.refresh_targets()

    @on(Button.Pressed, "#remove-host")
    def remove_target(self) -> None:
        app = socketclaw_app(self)
        selected = self.selected_target()
        if selected is None:
            self._show_state("Select a target to remove.")
            return
        if len(app.config.targets) == 1:
            self._show_state("At least one monitoring target is required.", error=True)
            return
        updated = app.config.model_copy(
            update={"targets": [target for target in app.config.targets if target != selected]}
        )
        app.save_config(updated)
        self.refresh_targets()

    @on(Button.Pressed, "#ping-host")
    def ping_target(self) -> None:
        self.run_diagnostic("ping")

    @on(Button.Pressed, "#scan-host")
    def scan_target(self) -> None:
        self.run_diagnostic("ports")

    @work(exclusive=True, group="host-diagnostic")
    async def run_diagnostic(self, kind: str) -> None:
        selected = self.selected_target()
        if selected is None:
            self._show_state("Select a target before running a diagnostic.")
            return
        buttons = (
            self.query_one("#ping-host", Button),
            self.query_one("#scan-host", Button),
        )
        for button in buttons:
            button.disabled = True
        self._show_state(f"Running {kind} diagnostic for {selected}…")
        try:
            app = socketclaw_app(self)
            await app.services.monitor.run_diagnostic(kind, selected)
        except Exception as exc:
            self._show_state(f"Diagnostic failed: {exc}", error=True)
        else:
            self._show_state(f"{kind.title()} diagnostic completed for {selected}.")
        finally:
            for button in buttons:
                button.disabled = False

    def selected_target(self) -> str | None:
        table = cast(DataTable[str], self.query_one("#hosts-table", DataTable))
        if table.row_count == 0:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return str(key) if key is not None else None

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#hosts-state", Static)
        state.update(message)
        state.set_class(error, "error")


def _validation_message(error: ValidationError) -> str:
    message = str(error.errors()[0].get("msg", "Invalid monitoring target."))
    return message.removeprefix("Value error, ")
