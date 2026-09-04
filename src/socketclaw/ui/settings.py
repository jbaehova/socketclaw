"""Validated runtime configuration editor."""

from __future__ import annotations

from typing import cast

from pydantic import ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Input, Select, Static

from ..config import AppConfig
from .context import safe_text, socketclaw_app


class SettingsView(Vertical):
    """Keyboard-accessible editor for runtime-reconfigurable settings."""

    def __init__(self) -> None:
        super().__init__(id="settings-view", classes="workspace-view")

    def compose(self) -> ComposeResult:
        app = socketclaw_app(self)
        config = app.config
        theme_value = _theme_value(app.available_themes, config.theme)
        theme_options = [
            ("SocketClaw dark", "textual-dark"),
            ("SocketClaw light", "textual-light"),
        ]
        if theme_value not in {value for _, value in theme_options}:
            theme_options.append((_theme_label(theme_value), theme_value))
        with VerticalScroll(id="settings-scroll"):
            yield Static("SETTINGS / PRIVATE LOCAL CONFIG", classes="view-kicker")
            with Horizontal(classes="view-heading"):
                yield Static("Runtime configuration", classes="view-title")
                yield Static("Secrets remain in ~/.socketclaw/.env", classes="view-hint")
            with Horizontal(classes="settings-grid"):
                with Vertical():
                    yield Static("ANALYSIS MODEL", classes="field-label")
                    yield Static(
                        f"{config.preset.label} / {config.preset.reasoning_label}",
                        id="model-policy",
                    )
                    yield Static(
                        "Investigations and response transitions are always operator initiated.",
                        classes="settings-guidance",
                        markup=False,
                    )
                    yield Static(
                        (
                            "REPLACE OPENAI KEY / OPTIONAL"
                            if app.config_store.load_api_key() is not None
                            else "ADD OPENAI KEY / OPTIONAL"
                        ),
                        id="settings-key-label",
                        classes="field-label",
                    )
                    yield Input(
                        placeholder="Leave blank to keep the configured key",
                        password=True,
                        id="settings-api-key",
                    )
                    yield Static("THEME", classes="field-label")
                    yield Select(
                        theme_options,
                        value=theme_value,
                        allow_blank=False,
                        id="settings-theme",
                    )
                with Vertical():
                    yield Static("WATCH TARGETS / COMMA SEPARATED", classes="field-label")
                    yield Input(
                        value=", ".join(config.targets),
                        id="settings-targets",
                    )
                    with Horizontal(classes="compact-fields"):
                        with Vertical():
                            yield Static("PING SECONDS", classes="field-label")
                            yield Input(
                                value=f"{config.ping_interval:g}",
                                type="number",
                                id="settings-ping",
                            )
                        with Vertical():
                            yield Static("SCAN SECONDS", classes="field-label")
                            yield Input(
                                value=f"{config.scan_interval:g}",
                                type="number",
                                id="settings-scan",
                            )
                    yield Static("TCP PORTS / COMMA SEPARATED", classes="field-label")
                    yield Input(
                        value=", ".join(str(port) for port in config.ports),
                        id="settings-ports",
                    )
                    yield Static("LOG PATHS / COMMA SEPARATED", classes="field-label")
                    yield Input(
                        value=", ".join(config.log_paths),
                        placeholder="/var/log/auth.log, /var/log/system.log",
                        id="settings-log-paths",
                    )
        with Vertical(id="settings-footer"):
            yield Static("", id="settings-state", classes="inline-state", markup=False)
            with Horizontal(classes="action-row"):
                yield Button("Save settings", id="save-settings", variant="primary")

    @on(Button.Pressed, "#save-settings")
    def save(self) -> None:
        self._save()

    @on(Input.Submitted)
    def submit(self) -> None:
        self._save()

    def on_mount(self) -> None:
        app = socketclaw_app(self)
        if app.config.theme not in app.available_themes:
            self._show_state(
                f"Theme {app.config.theme!r} is unavailable; using SocketClaw dark.",
                error=True,
            )

    @work(exclusive=True, group="settings-save")
    async def _save(self) -> None:
        app = socketclaw_app(self)
        button = self.query_one("#save-settings", Button)
        button.disabled = True
        key_input = self.query_one("#settings-api-key", Input)
        replacement_key = key_input.value.strip()
        try:
            previous_key = app.services.config_store.load_api_key()
            baseline = app.config
            submitted = AppConfig.model_validate(
                {
                    "model": app.config.model,
                    "targets": [
                        target.strip()
                        for target in self.query_one("#settings-targets", Input).value.split(",")
                        if target.strip()
                    ],
                    "ping_interval": float(self.query_one("#settings-ping", Input).value),
                    "scan_interval": float(self.query_one("#settings-scan", Input).value),
                    "ports": _parse_ports(self.query_one("#settings-ports", Input).value),
                    "log_paths": [
                        path.strip()
                        for path in self.query_one(
                            "#settings-log-paths",
                            Input,
                        ).value.split(",")
                        if path.strip()
                    ],
                    "theme": _select_value(
                        cast(
                            Select[object],
                            self.query_one("#settings-theme", Select),
                        )
                    ),
                }
            )
            changed = {
                field: getattr(submitted, field)
                for field in (
                    "model",
                    "targets",
                    "ping_interval",
                    "scan_interval",
                    "ports",
                    "log_paths",
                    "theme",
                )
                if getattr(submitted, field) != getattr(baseline, field)
            }
            if replacement_key:
                await app.services.validate_key(replacement_key)
                app.services.config_store.save_api_key(replacement_key)
            try:
                config = await app.update_config(
                    lambda current: AppConfig.model_validate(current.model_copy(update=changed))
                )
            except BaseException:
                if replacement_key:
                    if previous_key is None:
                        app.services.config_store.clear_api_key()
                    else:
                        app.services.config_store.save_api_key(previous_key)
                raise
        except (ValidationError, ValueError) as exc:
            self._show_state(_validation_message(exc), error=True)
        except Exception as exc:
            self._show_state(f"Settings were not saved: {exc}", error=True)
        else:
            key_input.value = ""
            if replacement_key:
                self.query_one("#settings-key-label", Static).update(
                    "REPLACE OPENAI KEY / OPTIONAL"
                )
            self._show_state(f"Saved / {config.preset.label} / {config.preset.reasoning_label}")
        finally:
            button.disabled = False

    def apply_config(self, config: AppConfig) -> None:
        """Synchronize the mounted editor after changes from another workspace."""
        app = socketclaw_app(self)
        self.query_one("#model-policy", Static).update(
            f"{config.preset.label} / {config.preset.reasoning_label}"
        )
        self.query_one("#settings-targets", Input).value = ", ".join(config.targets)
        self.query_one("#settings-ping", Input).value = f"{config.ping_interval:g}"
        self.query_one("#settings-scan", Input).value = f"{config.scan_interval:g}"
        self.query_one("#settings-ports", Input).value = ", ".join(
            str(port) for port in config.ports
        )
        self.query_one("#settings-log-paths", Input).value = ", ".join(config.log_paths)
        self.query_one("#settings-theme", Select).value = _theme_value(
            app.available_themes,
            config.theme,
        )

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#settings-state", Static)
        state.update(safe_text(message))
        state.set_class(error, "error")


def _validation_message(error: Exception) -> str:
    if isinstance(error, ValidationError) and error.errors():
        return str(error.errors()[0].get("msg", "Invalid settings.")).removeprefix("Value error, ")
    return "Enter valid targets and intervals."


def _select_value(widget: Select[object]) -> str:
    value = widget.value
    if not isinstance(value, str):
        raise ValueError("a settings selection is required")
    return value


def _theme_value(available: object, configured: str) -> str:
    if isinstance(available, dict) and configured in available:
        return configured
    return "textual-dark"


def _theme_label(value: str) -> str:
    return value.replace("-", " ").title()


def _parse_ports(value: str) -> list[int]:
    try:
        return [int(port.strip()) for port in value.split(",") if port.strip()]
    except ValueError as exc:
        raise ValueError("TCP ports must be comma-separated numbers") from exc
