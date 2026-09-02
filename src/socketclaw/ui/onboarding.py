"""Four-step first-run setup for local files and OpenAI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, ContentSwitcher, Input, Static

from ..config import AppConfig
from ..openai import OpenAIError
from .context import socketclaw_app

if TYPE_CHECKING:
    from .app import AppServices


class OnboardingScreen(Screen[None]):
    """Collect, validate, and persist the minimum useful first-run settings."""

    def __init__(self, services: AppServices, initial_config: AppConfig) -> None:
        super().__init__()
        self.services = services
        self.current_step = 0
        self._pending_key = ""
        self._pending_config = initial_config.model_copy(deep=True)

    def on_mount(self) -> None:
        self.query_one("#onboarding-next", Button).focus()

    def compose(self) -> ComposeResult:
        with Vertical(id="onboarding-shell"):
            yield Static("SOCKETCLAW", id="onboarding-brand")
            yield Static(
                "LOCAL NETWORK OPERATIONS / FIRST RUN",
                id="onboarding-kicker",
            )
            yield Static("01  02  03  04", id="onboarding-progress")
            with ContentSwitcher(
                initial="onboarding-welcome",
                id="onboarding-steps",
            ):
                with Vertical(id="onboarding-welcome", classes="onboarding-step"):
                    yield Static("See what changed on your network.", classes="step-title")
                    yield Static(
                        "SocketClaw watches configured hosts and logs, keeps a local "
                        "incident timeline, and asks OpenAI only when an event needs "
                        "deeper analysis.",
                        classes="step-copy",
                    )
                    yield Static(
                        "Files stay under ~/.socketclaw by default.",
                        classes="step-note",
                    )
                with Vertical(id="onboarding-key", classes="onboarding-step"):
                    yield Static("Connect OpenAI", classes="step-title")
                    yield Static(
                        "The key and GPT-5.6 Luna access are validated without generating "
                        "tokens, then stored in ~/.socketclaw/.env with private permissions.",
                        classes="step-copy",
                    )
                    yield Input(
                        placeholder="sk-proj-...",
                        password=True,
                        id="api-key",
                    )
                with Vertical(id="onboarding-target-step", classes="onboarding-step"):
                    yield Static("Set the first watch targets", classes="step-title")
                    yield Static(
                        "Use hostnames or IP addresses separated by commas.",
                        classes="step-copy",
                    )
                    yield Input(
                        value=", ".join(self._pending_config.targets),
                        placeholder="1.1.1.1, gateway.local",
                        id="onboarding-targets",
                    )
                    with Horizontal(classes="interval-row"):
                        with Vertical():
                            yield Static("PING / SECONDS", classes="field-label")
                            yield Input(
                                value=f"{self._pending_config.ping_interval:g}",
                                type="number",
                                id="onboarding-ping-interval",
                            )
                        with Vertical():
                            yield Static("PORT SCAN / SECONDS", classes="field-label")
                            yield Input(
                                value=f"{self._pending_config.scan_interval:g}",
                                type="number",
                                id="onboarding-scan-interval",
                            )
                with Vertical(id="onboarding-ready", classes="onboarding-step"):
                    yield Static("Ready to watch.", classes="step-title")
                    yield Static(
                        "Monitoring starts immediately. You can pause it with Space and "
                        "change every setting from workspace 5.",
                        classes="step-copy",
                    )
                    yield Static("", id="onboarding-summary", classes="step-note")
            yield Static("", id="onboarding-error")
            with Horizontal(id="onboarding-actions"):
                yield Button("Back", id="onboarding-back")
                yield Button("Continue", id="onboarding-next", variant="primary")

    @on(Button.Pressed, "#onboarding-back")
    def previous_step(self) -> None:
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    @on(Button.Pressed, "#onboarding-next")
    async def next_step(self) -> None:
        self._set_error("")
        if self.current_step == 0:
            self._show_step(1)
            return
        if self.current_step == 1:
            await self._validate_key()
            return
        if self.current_step == 2:
            if not self._validate_targets():
                return
            self._show_step(3)
            self._render_summary()
            self.query_one("#onboarding-next", Button).label = "Start monitoring"
            return
        app = socketclaw_app(self)
        await app.complete_onboarding(self._pending_config, self._pending_key)

    async def _validate_key(self) -> None:
        key = self.query_one("#api-key", Input).value
        if not key.strip():
            self._set_error("Enter an OpenAI API key.")
            return
        button = self.query_one("#onboarding-next", Button)
        button.disabled = True
        button.label = "Validating…"
        try:
            await self.services.validate_key(key)
        except OpenAIError as exc:
            self._set_error(str(exc))
            return
        except Exception:
            self._set_error("OpenAI validation failed. Check your connection.")
            return
        finally:
            button.disabled = False
            button.label = "Continue"
        self._pending_key = key
        self._show_step(2)

    def _validate_targets(self) -> bool:
        raw_targets = self.query_one("#onboarding-targets", Input).value
        targets = [value.strip() for value in raw_targets.split(",") if value.strip()]
        try:
            self._pending_config = AppConfig.model_validate(
                {
                    **self._pending_config.model_dump(),
                    "targets": targets,
                    "ping_interval": float(
                        self.query_one("#onboarding-ping-interval", Input).value
                    ),
                    "scan_interval": float(
                        self.query_one("#onboarding-scan-interval", Input).value
                    ),
                }
            )
        except (ValidationError, ValueError) as exc:
            self._set_error(_validation_message(exc))
            return False
        return True

    def _show_step(self, step: int) -> None:
        ids = (
            "onboarding-welcome",
            "onboarding-key",
            "onboarding-target-step",
            "onboarding-ready",
        )
        self.current_step = step
        self.query_one("#onboarding-steps", ContentSwitcher).current = ids[step]
        progress = "  ".join(
            f"[b reverse]{index:02d}[/]" if index == step + 1 else f"{index:02d}"
            for index in range(1, 5)
        )
        self.query_one("#onboarding-progress", Static).update(progress)
        self.query_one("#onboarding-back", Button).disabled = step == 0
        if step < 3:
            self.query_one("#onboarding-next", Button).label = "Continue"

    def _render_summary(self) -> None:
        preset = self._pending_config.preset
        self.query_one("#onboarding-summary", Static).update(
            f"{len(self._pending_config.targets)} target(s) / "
            f"{preset.label} / {preset.reasoning_label} / "
            f"Ping {self._pending_config.ping_interval:g}s / "
            f"Scan {self._pending_config.scan_interval:g}s"
        )

    def _set_error(self, message: str) -> None:
        self.query_one("#onboarding-error", Static).update(message)


def _validation_message(error: Exception) -> str:
    if isinstance(error, ValidationError) and error.errors():
        return str(error.errors()[0].get("msg", "Invalid settings."))
    return "Enter valid targets and intervals."
