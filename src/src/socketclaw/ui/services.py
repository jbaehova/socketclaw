"""Explicit service expectations, measured status and bounded manual checks."""

from __future__ import annotations

from typing import ClassVar, cast

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static

from ..config import AppConfig, ServiceConfig
from ..domain import EventSource
from ..storage import EventQuery
from .context import safe_text, socketclaw_app
from .layout import ResponsiveModalScreen


class ServiceEditor(ResponsiveModalScreen[bool]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel", show=False)]
    DEFAULT_CSS = """
    ServiceEditor { align: center middle; }
    #service-editor { width: 72; max-width: 100%; height: 95%; border: round $primary;
                      background: $surface; padding: 0 1; }
    #service-fields { height: 1fr; }
    #service-fields Static { height: auto; margin-top: 1; }
    #service-fields Input, #service-fields Select { width: 100%; }
    #service-editor-feedback { height: auto; max-height: 3; }
    #service-editor-actions { height: 3; }
    #service-editor-actions Button { min-width: 12; margin-right: 1; }
    """

    def __init__(self, service: ServiceConfig | None = None) -> None:
        super().__init__()
        self.original = service
        self._saving = False

    def compose(self) -> ComposeResult:
        values = self.original.model_dump() if self.original else {}
        with Vertical(id="service-editor"):
            yield Static("Edit service expectation" if self.original else "Add service expectation")
            with VerticalScroll(id="service-fields"):
                for key, label, default in (
                    ("id", "Stable service ID", ""),
                    ("name", "Service name", ""),
                    ("host", "Host or IP address", "127.0.0.1"),
                    ("port", "Port", "8080"),
                ):
                    yield Static(label)
                    yield Input(
                        str(values.get(key, default)),
                        id=f"service-{key}",
                        disabled=key == "id" and self.original is not None,
                    )
                yield Static("Protocol")
                yield Select(
                    [(value.upper(), value) for value in ("tcp", "http", "https")],
                    value=values.get("protocol", "tcp"),
                    allow_blank=False,
                    id="service-protocol",
                )
                for key, label, default in (
                    ("path", "HTTP path (ignored for TCP)", "/"),
                    ("expected_status", "Expected HTTP status", "200"),
                    ("body_contains", "Expected body text (optional)", ""),
                    ("failure_threshold", "Failures before incident", "3"),
                    ("recovery_threshold", "Successes before recovery", "2"),
                    ("interval", "Check interval in seconds", "10"),
                    ("timeout", "Timeout in seconds", "3"),
                ):
                    yield Static(label)
                    yield Input(str(values.get(key) or default), id=f"service-{key}")
                yield Static("Allowed exposure (intent, not proof of internet reachability)")
                yield Select(
                    [(value.title(), value) for value in ("loopback", "private", "any")],
                    value=values.get("allowed_exposure", "loopback"),
                    allow_blank=False,
                    id="service-allowed_exposure",
                )
                yield Checkbox(
                    "Required service",
                    value=bool(values.get("required", True)),
                    id="service-required",
                )
            yield Static("", id="service-editor-feedback", markup=False)
            with Horizontal(id="service-editor-actions"):
                yield Button("Save", id="service-save", variant="primary")
                yield Button("Cancel", id="service-cancel")

    def on_mount(self) -> None:
        self.query_one("#service-name" if self.original else "#service-id", Input).focus()

    @on(Button.Pressed, "#service-save")
    def save(self) -> None:
        if not self._saving:
            self._saving = True
            self._save()

    @work(group="service-editor-save")
    async def _save(self) -> None:
        app = socketclaw_app(self)
        button = self.query_one("#service-save", Button)
        button.disabled = True
        try:
            values: dict[str, object] = {
                key: self.query_one(f"#service-{key}", Input).value.strip()
                for key in (
                    "id",
                    "name",
                    "host",
                    "port",
                    "path",
                    "expected_status",
                    "body_contains",
                    "failure_threshold",
                    "recovery_threshold",
                    "interval",
                    "timeout",
                )
            }
            values["port"] = int(str(values["port"]))
            values["body_contains"] = self.query_one("#service-body_contains", Input).value or None
            for key in ("protocol", "allowed_exposure"):
                values[key] = cast(Select[str], self.query_one(f"#service-{key}", Select)).value
            values["required"] = self.query_one("#service-required", Checkbox).value
            service = ServiceConfig.model_validate(values)

            def update(current: AppConfig) -> AppConfig:
                existing = next((item for item in current.services if item.id == service.id), None)
                if existing != self.original:
                    raise ValueError(
                        "Service changed or its ID already exists. Review current settings."
                    )
                entries = [service if item.id == service.id else item for item in current.services]
                if existing is None:
                    entries.append(service)
                return AppConfig.model_validate({**current.model_dump(), "services": entries})

            await app.update_config(update)
        except Exception as exc:
            self.query_one("#service-editor-feedback", Static).update(
                safe_text(f"Not saved: {exc}")
            )
        else:
            self.dismiss(True)
        finally:
            self._saving = False
            if button.is_mounted:
                button.disabled = False

    @on(Button.Pressed, "#service-cancel")
    def action_cancel(self) -> None:
        if not self._saving:
            self.dismiss(False)


class ServicesView(Vertical):
    DEFAULT_CSS = """
    ServicesView { height: 1fr; }
    #services-table { height: 1fr; min-height: 3; }
    #service-actions { height: 3; }
    #service-actions Button { min-width: 9; width: 1fr; margin-right: 1; }
    #services-state { height: auto; max-height: 3; }
    """

    def __init__(self) -> None:
        super().__init__(id="services-view")
        self._diagnosing = False
        self._removing = False

    def compose(self) -> ComposeResult:
        yield Static(
            "No measurements yet. Configure a service to begin.", id="services-state", markup=False
        )
        yield DataTable(id="services-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(id="service-actions"):
            yield Button("Add", id="service-add", variant="primary")
            yield Button("Edit", id="service-edit")
            yield Button("Remove", id="service-remove", variant="error")
            yield Button("Check", id="service-check")
            yield Button("Refresh", id="service-refresh")

    def on_mount(self) -> None:
        self.query_one("#services-table", DataTable).add_columns(
            "SERVICE", "ENDPOINT", "MEASURED", "AT"
        )
        self.refresh_data()
        self.set_interval(5, self._refresh_visible)

    def _refresh_visible(self) -> None:
        if self.is_mounted and self.visible and socketclaw_app(self).screen is self.screen:
            self.refresh_data()

    @on(Button.Pressed, "#service-refresh")
    def refresh_button(self) -> None:
        self.refresh_data()

    @work(exclusive=True, group="service-status")
    async def refresh_data(self, feedback: str | None = None) -> None:
        app = socketclaw_app(self)
        services = tuple(app.config.services)
        selected = self.selected_service()
        events = []
        try:
            if app.services.repository is not None:
                events = await app.services.repository.list_events(
                    EventQuery(source=EventSource.SYSTEM, limit=500)
                )
        except Exception as exc:
            self._message(f"Cannot load measured status: {exc}")
            return
        if not self.is_mounted or services != tuple(app.config.services):
            return
        table = cast(DataTable[str], self.query_one("#services-table", DataTable))
        table.clear()
        for service in services:
            event = next(
                (
                    event
                    for event in events
                    if event.evidence.get("service_id") == service.id
                    and event.event_type
                    in {"service.available", "service.failed", "service.unknown"}
                ),
                None,
            )
            status = "No recent observation"
            when = "-"
            if event is not None:
                status = str(
                    event.evidence.get("status", event.event_type.removeprefix("service."))
                )
                status += " confirmed" if event.evidence.get("confirmed") else " pending"
                when = event.observed_at.strftime("%m-%d %H:%M")
            endpoint = f"{service.protocol}://{service.host}:{service.port}"
            if service.protocol != "tcp":
                endpoint += service.path
            if event is not None and event.evidence.get("endpoint") not in {None, endpoint}:
                status = "Previous endpoint"
            table.add_row(
                safe_text(service.name),
                safe_text(endpoint),
                safe_text(status),
                when,
                key=service.id,
            )
        if selected and selected.id in {service.id for service in services}:
            table.move_cursor(row=table.get_row_index(selected.id))
        self.query_one("#service-check", Button).disabled = (
            self._diagnosing or "service" not in app.services.monitor.status.diagnostics
        )
        if feedback:
            self._message(feedback)
        elif not services:
            self._message("No service expectations configured. Add a TCP or HTTP endpoint.")
        else:
            self._message(
                "Recent 500 system records. No matching record means no measured state here."
            )

    def selected_service(self) -> ServiceConfig | None:
        table = cast(DataTable[str], self.query_one("#services-table", DataTable))
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return next(
            (service for service in socketclaw_app(self).config.services if service.id == key), None
        )

    def _editor_closed(self, _: bool | None) -> None:
        self.refresh_data()

    @on(Button.Pressed, "#service-add")
    def add_service(self) -> None:
        socketclaw_app(self).push_screen(ServiceEditor(), self._editor_closed)

    @on(Button.Pressed, "#service-edit")
    @on(DataTable.RowSelected, "#services-table")
    def edit_service(self) -> None:
        service = self.selected_service()
        if service:
            socketclaw_app(self).push_screen(ServiceEditor(service), self._editor_closed)
        else:
            self._message("Select a service first.")

    @on(Button.Pressed, "#service-remove")
    def remove_service(self) -> None:
        service = self.selected_service()
        if service and not self._removing:
            self._removing = True
            self._remove_service(service)

    @work(group="service-removal")
    async def _remove_service(self, service: ServiceConfig) -> None:
        feedback = "Service removed. Historical observations are retained."
        try:
            await socketclaw_app(self).update_config(
                lambda current: current.model_copy(
                    update={
                        "services": [item for item in current.services if item.id != service.id],
                    }
                )
            )
        except Exception as exc:
            feedback = f"Service was not removed: {exc}"
        finally:
            self._removing = False
            self.refresh_data(feedback)

    @on(Button.Pressed, "#service-check")
    def check_service(self) -> None:
        service = self.selected_service()
        if not service:
            self._message("Select a service first.")
        elif not self._diagnosing:
            self._diagnosing = True
            self._check_service(service)

    @work(group="service-diagnostic")
    async def _check_service(self, service: ServiceConfig) -> None:
        self.query_one("#service-check", Button).disabled = True
        self._message(f"Checking {service.name}...")
        feedback = f"Check completed for {service.name}. Review the measured state."
        try:
            await socketclaw_app(self).services.monitor.run_diagnostic("service", service.id)
        except Exception as exc:
            feedback = f"Service check failed: {exc}"
        finally:
            self._diagnosing = False
            if self.is_mounted:
                self.refresh_data(feedback)

    def _message(self, message: str) -> None:
        if self.is_mounted:
            self.query_one("#services-state", Static).update(safe_text(message))
