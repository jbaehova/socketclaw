"""Watch-target management and manual diagnostics."""

from __future__ import annotations

from typing import cast

from pydantic import ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static, TabbedContent, TabPane

from ..config import AppConfig
from .context import safe_text, socketclaw_app
from .dialogs import ConfirmTargetRemovalScreen
from .logs import LogSourcesView


class HostsView(Vertical):
    """Editable monitoring target inventory."""

    def __init__(self) -> None:
        super().__init__(id="hosts-view", classes="workspace-view")

    def compose(self) -> ComposeResult:
        yield Static("HOSTS / WATCH TARGETS", classes="view-kicker")
        with Horizontal(classes="view-heading"):
            yield Static("Local watch inventory", classes="view-title")
            yield Static("Manual diagnostics are read-only.", classes="view-hint")
        with TabbedContent(initial="host-targets", id="hosts-tabs"):
            with TabPane("Targets", id="host-targets"):
                with Horizontal(classes="filter-row"):
                    yield Input(placeholder="IP address or hostname", id="host-target")
                    yield Button("Add target", id="add-host", variant="primary")
                yield Static("", id="hosts-state", classes="inline-state", markup=False)
                yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
                with Horizontal(classes="action-row"):
                    yield Button("Ping now", id="ping-host", variant="primary")
                    yield Button("Scan ports", id="scan-host")
                    yield Button("Remove", id="remove-host", variant="error")
            with TabPane("Logs", id="host-logs"):
                yield LogSourcesView()

    def on_mount(self) -> None:
        self.query_one("#hosts-table", DataTable).add_columns(
            "TARGET", "PING", "PORT SCAN", "PORTS"
        )
        self.refresh_targets()

    def open_logs(self) -> None:
        self.query_one("#hosts-tabs", TabbedContent).active = "host-logs"
        self.query_one(LogSourcesView).refresh_data()
        self.call_after_refresh(self.focus_workspace)

    def focus_workspace(self) -> None:
        logs = self.query_one("#hosts-tabs", TabbedContent).active == "host-logs"
        self.query_one("#logs-table" if logs else "#hosts-table").focus()

    def run_context_action(self) -> None:
        if self.query_one("#hosts-tabs", TabbedContent).active == "host-logs":
            self.query_one(LogSourcesView).test_source()
        else:
            self.run_diagnostic("ping")

    @on(TabbedContent.TabActivated, "#hosts-tabs")
    def activate_tab(self) -> None:
        logs = self.query_one("#hosts-tabs", TabbedContent).active == "host-logs"
        self.query_one(".view-kicker", Static).update(
            "HOSTS / LOG SOURCES" if logs else "HOSTS / WATCH TARGETS"
        )
        self.query_one(".view-title", Static).update(
            "Log source inventory" if logs else "Local watch inventory"
        )
        if logs:
            self.query_one(LogSourcesView).refresh_data()
        self.call_after_refresh(self.focus_workspace)

    def refresh_targets(self) -> None:
        app = socketclaw_app(self)
        table = cast(DataTable[str], self.query_one("#hosts-table", DataTable))
        selected = self.selected_target()
        table.clear()
        for target in app.config.targets:
            table.add_row(
                target,
                f"{app.config.ping_interval:g}s",
                f"{app.config.scan_interval:g}s",
                ", ".join(str(port) for port in app.config.ports),
                key=target,
            )
        if app.config.targets:
            target = selected if selected in app.config.targets else app.config.targets[0]
            table.move_cursor(row=table.get_row_index(target))
        self._refresh_diagnostic_buttons()
        if "ping" not in app.services.monitor.status.diagnostics:
            self._show_state(
                f"{len(app.config.targets)} target(s) monitored. System ping is unavailable."
            )
        else:
            self._show_state(f"{len(app.config.targets)} target(s) monitored.")

    @on(Button.Pressed, "#add-host")
    def add_target(self) -> None:
        self._add_target()

    @on(Input.Submitted, "#host-target")
    def submit_target(self) -> None:
        self._add_target()

    @work(exclusive=True, group="host-update")
    async def _add_target(self) -> None:
        app = socketclaw_app(self)
        target = self.query_one("#host-target", Input).value.strip()
        if target in app.config.targets:
            self._show_state(f"{target} is already monitored.")
            return
        button = self.query_one("#add-host", Button)
        button.disabled = True
        try:
            added = False

            def add_to_latest(current: AppConfig) -> AppConfig:
                nonlocal added
                if target in current.targets:
                    return current
                added = True
                updated = current.model_copy(update={"targets": [*current.targets, target]})
                return AppConfig.model_validate(updated.model_dump())

            await app.update_config(add_to_latest)
            if not added:
                self._show_state(f"{target} is already monitored.")
                return
        except ValidationError as exc:
            self._show_state(_validation_message(exc), error=True)
        except Exception as exc:
            self._show_state(f"Target was not added: {exc}", error=True)
        else:
            self.query_one("#host-target", Input).value = ""
            self._show_state(f"Added {target} to active monitoring.")
        finally:
            button.disabled = False

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
        app.push_screen(
            ConfirmTargetRemovalScreen(selected),
            lambda accepted: self._confirmed_removal(accepted, selected),
        )

    def _confirmed_removal(self, accepted: bool | None, target: str) -> None:
        if accepted:
            self._remove_target(target)

    @work(exclusive=True, group="host-update")
    async def _remove_target(self, selected: str) -> None:
        app = socketclaw_app(self)
        button = self.query_one("#remove-host", Button)
        button.disabled = True
        try:
            removed = False

            def remove_from_latest(current: AppConfig) -> AppConfig:
                nonlocal removed
                if selected not in current.targets:
                    return current
                if len(current.targets) == 1:
                    raise ValueError("At least one monitoring target is required.")
                removed = True
                return current.model_copy(
                    update={"targets": [target for target in current.targets if target != selected]}
                )

            await app.update_config(remove_from_latest)
            if not removed:
                self._show_state(f"{selected} is no longer monitored.")
                return
        except Exception as exc:
            self._show_state(f"Target was not removed: {exc}", error=True)
        else:
            self._show_state(f"Removed {selected} from active monitoring.")
        finally:
            button.disabled = False

    @on(Button.Pressed, "#ping-host")
    def ping_target(self) -> None:
        self.run_diagnostic("ping")

    @on(Button.Pressed, "#scan-host")
    def scan_target(self) -> None:
        self.run_diagnostic("ports")

    @work(exclusive=True, group="host-diagnostic")
    async def run_diagnostic(self, kind: str) -> None:
        app = socketclaw_app(self)
        if kind not in app.services.monitor.status.diagnostics:
            self._show_state(
                f"{kind.title()} diagnostic is unavailable on this system.",
                error=True,
            )
            self._refresh_diagnostic_buttons()
            return
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
            await app.services.monitor.run_diagnostic(kind, selected)
        except Exception as exc:
            self._show_state(f"Diagnostic failed: {exc}", error=True)
        else:
            self._show_state(f"{kind.title()} diagnostic completed for {selected}.")
        finally:
            self._refresh_diagnostic_buttons()

    def _refresh_diagnostic_buttons(self) -> None:
        diagnostics = socketclaw_app(self).services.monitor.status.diagnostics
        ping = self.query_one("#ping-host", Button)
        ports = self.query_one("#scan-host", Button)
        ping.label = "Ping now" if "ping" in diagnostics else "Ping unavailable"
        ping.disabled = "ping" not in diagnostics
        ports.disabled = "ports" not in diagnostics

    def selected_target(self) -> str | None:
        table = cast(DataTable[str], self.query_one("#hosts-table", DataTable))
        if table.row_count == 0:
            return None
        row = min(table.cursor_row, table.row_count - 1)
        return str(table.get_row_at(row)[0])

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#hosts-state", Static)
        state.update(safe_text(message))
        state.set_class(error, "error")


def _validation_message(error: ValidationError) -> str:
    message = str(error.errors()[0].get("msg", "Invalid monitoring target."))
    return message.removeprefix("Value error, ")
