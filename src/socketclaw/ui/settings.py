"""Validated runtime configuration editor."""

from __future__ import annotations

from typing import cast

from pydantic import ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Select, Static

from ..config import AppConfig
from .context import socketclaw_app


class SettingsView(Vertical):
    """One dense, keyboard-accessible editor for all persisted settings."""

    def __init__(self) -> None:
        super().__init__(id="settings-view", classes="workspace-view")

    def compose(self) -> ComposeResult:
        app = socketclaw_app(self)
        config = app.config
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
                yield Static("INVESTIGATE AT", classes="field-label")
                yield Select(
                    [(value.title(), value) for value in ("medium", "high", "critical")],
                    value=config.investigation_threshold,
                    allow_blank=False,
                    id="threshold",
                )
                yield Static("RESPONSE MODE", classes="field-label")
                yield Select(
                    [
                        ("Simulation only", "simulation"),
                        ("Operator approval", "approval"),
                        ("Automatic (safe proposals)", "automatic"),
                    ],
                    value=config.response_mode,
                    allow_blank=False,
                    id="response-mode",
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
                yield Static("REPLACE OPENAI KEY / OPTIONAL", classes="field-label")
                yield Input(
                    placeholder="Leave blank to keep the configured key",
                    password=True,
                    id="settings-api-key",
                )
                yield Static("THEME", classes="field-label")
                yield Select(
                    [
                        ("SocketClaw dark", "textual-dark"),
                        ("Textual light", "textual-light"),
                    ],
                    value=config.theme,
                    allow_blank=False,
                    id="settings-theme",
                )
        yield Static("", id="settings-state", classes="inline-state")
        with Horizontal(classes="action-row"):
            yield Button("Save settings", id="save-settings", variant="primary")

    @on(Button.Pressed, "#save-settings")
    def save(self) -> None:
        self._save()

    @work(exclusive=True, group="settings-save")
    async def _save(self) -> None:
        app = socketclaw_app(self)
        button = self.query_one("#save-settings", Button)
        button.disabled = True
        key_input = self.query_one("#settings-api-key", Input)
        replacement_key = key_input.value.strip()
        try:
            config = AppConfig.model_validate(
                {
                    "model": app.config.model,
                    "targets": [
                        target.strip()
                        for target in self.query_one("#settings-targets", Input).value.split(",")
                        if target.strip()
                    ],
                    "ping_interval": float(self.query_one("#settings-ping", Input).value),
                    "scan_interval": float(self.query_one("#settings-scan", Input).value),
                    "ports": app.config.ports,
                    "log_paths": app.config.log_paths,
                    "investigation_threshold": _select_value(
                        cast(Select[object], self.query_one("#threshold", Select))
                    ),
                    "response_mode": _select_value(
                        cast(
                            Select[object],
                            self.query_one("#response-mode", Select),
                        )
                    ),
                    "theme": _select_value(
                        cast(
                            Select[object],
                            self.query_one("#settings-theme", Select),
                        )
                    ),
                }
            )
            if replacement_key:
                await app.services.validate_key(replacement_key)
                app.services.config_store.save_api_key(replacement_key)
            app.save_config(config)
        except (ValidationError, ValueError) as exc:
            self._show_state(_validation_message(exc), error=True)
        except Exception as exc:
            self._show_state(f"Settings were not saved: {exc}", error=True)
        else:
            key_input.value = ""
            self._show_state(f"Saved / {config.preset.label} / {config.preset.reasoning_label}")
        finally:
            button.disabled = False

    def _show_state(self, message: str, *, error: bool = False) -> None:
        state = self.query_one("#settings-state", Static)
        state.update(message)
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
