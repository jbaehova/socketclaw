"""Five-step first-run setup for local files and OpenRouter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, ContentSwitcher, Input, Select, Static

from ..config import MODEL_PRESETS, AppConfig, ModelKey
from ..openrouter import OpenRouterError

if TYPE_CHECKING:
    from .app import SocketClawApp


class OnboardingScreen(Screen[None]):
    """Collect, validate, and persist the minimum useful first-run settings."""

    def __init__(self, services: object) -> None:
        super().__init__()
        self.services = services
        self.current_step = 0
        self._pending_key = ""
        self._selected_model: ModelKey = "terra"
        self._pending_config = AppConfig()

    def compose(self) -> ComposeResult:
        with Vertical(id="onboarding-shell"):
            yield Static("SOCKETCLAW", id="onboarding-brand")
            yield Static(
                "LOCAL NETWORK OPERATIONS / FIRST RUN",
                id="onboarding-kicker",
            )
            yield Static("01  02  03  04  05", id="onboarding-progress")
            with ContentSwitcher(
                initial="onboarding-welcome",
                id="onboarding-steps",
            ):
                with Vertical(id="onboarding-welcome", classes="onboarding-step"):
                    yield Static("See what changed on your network.", classes="step-title")
                    yield Static(
                        "SocketClaw watches configured hosts and logs, keeps a local "
                        "incident timeline, and asks OpenRouter only when an event needs "
                        "deeper analysis.",
                        classes="step-copy",
                    )
                    yield Static(
                        "Files stay under ~/.socketclaw by default.",
                        classes="step-note",
                    )
                with Vertical(id="onboarding-key", classes="onboarding-step"):
                    yield Static("Connect OpenRouter", classes="step-title")
                    yield Static(
                        "The key is validated without a model request, then stored in "
                        "~/.socketclaw/.env with private permissions.",
                        classes="step-copy",
                    )
                    yield Input(
                        placeholder="sk-or-v1-…",
                        password=True,
                        id="api-key",
                    )
                with Vertical(id="onboarding-model-step", classes="onboarding-step"):
                    yield Static("Choose the analysis model", classes="step-title")
                    yield Static(
                        "Each preset has a fixed reasoning effort so investigations are "
                        "consistent and auditable.",
                        classes="step-copy",
                    )
                    yield Select(
                        [
                            (
                                f"{preset.label}  /  {preset.effort.upper()}",
                                preset.key,
                            )
                            for preset in MODEL_PRESETS.values()
                        ],
                        value="terra",
                        allow_blank=False,
                        id="onboarding-model",
                    )
                with Vertical(id="onboarding-target-step", classes="onboarding-step"):
                    yield Static("Set the first watch targets", classes="step-title")
                    yield Static(
                        "Use hostnames or IP addresses separated by commas.",
                        classes="step-copy",
                    )
                    yield Input(
                        value="1.1.1.1",
                        placeholder="1.1.1.1, gateway.local",
                        id="onboarding-targets",
                    )
                    with Horizontal(classes="interval-row"):
                        with Vertical():
                            yield Static("PING / SECONDS", classes="field-label")
                            yield Input(
                                value="5",
                                type="number",
                                id="onboarding-ping-interval",
                            )
                        with Vertical():
                            yield Static("PORT SCAN / SECONDS", classes="field-label")
                            yield Input(
                                value="60",
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
            selected = self.query_one("#onboarding-model", Select).value
            if selected not in MODEL_PRESETS:
                self._set_error("Choose one of the three curated models.")
                return
            self._selected_model = selected
            self._show_step(3)
            return
        if self.current_step == 3:
            if not self._validate_targets():
                return
            self._show_step(4)
            self._render_summary()
            self.query_one("#onboarding-next", Button).label = "Start monitoring"
            return
        app: SocketClawApp = self.app
        await app.complete_onboarding(self._pending_config, self._pending_key)

    async def _validate_key(self) -> None:
        key = self.query_one("#api-key", Input).value
        if not key.strip():
            self._set_error("Enter an OpenRouter API key.")
            return
        button = self.query_one("#onboarding-next", Button)
        button.disabled = True
        button.label = "Validating…"
        try:
            await self.services.validate_key(key)
        except OpenRouterError as exc:
            self._set_error(str(exc))
            return
        except Exception:
            self._set_error("OpenRouter validation failed. Check your connection.")
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
            self._pending_config = AppConfig(
                model=self._selected_model,
                targets=targets,
                ping_interval=float(self.query_one("#onboarding-ping-interval", Input).value),
                scan_interval=float(self.query_one("#onboarding-scan-interval", Input).value),
            )
        except (ValidationError, ValueError) as exc:
            self._set_error(_validation_message(exc))
            return False
        return True

    def _show_step(self, step: int) -> None:
        ids = (
            "onboarding-welcome",
            "onboarding-key",
            "onboarding-model-step",
            "onboarding-target-step",
            "onboarding-ready",
        )
        self.current_step = step
        self.query_one("#onboarding-steps", ContentSwitcher).current = ids[step]
        progress = "  ".join(
            f"[b reverse]{index:02d}[/]" if index == step + 1 else f"{index:02d}"
            for index in range(1, 6)
        )
        self.query_one("#onboarding-progress", Static).update(progress)
        self.query_one("#onboarding-back", Button).disabled = step == 0
        if step < 4:
            self.query_one("#onboarding-next", Button).label = "Continue"

    def _render_summary(self) -> None:
        preset = self._pending_config.preset
        self.query_one("#onboarding-summary", Static).update(
            f"{len(self._pending_config.targets)} target(s)  •  "
            f"{preset.label} / {preset.effort.upper()}  •  "
            f"Ping {self._pending_config.ping_interval:g}s  •  "
            f"Scan {self._pending_config.scan_interval:g}s"
        )

    def _set_error(self, message: str) -> None:
        self.query_one("#onboarding-error", Static).update(message)


def _validation_message(error: Exception) -> str:
    if isinstance(error, ValidationError) and error.errors():
        return str(error.errors()[0].get("msg", "Invalid settings."))
    return "Enter valid targets and intervals."
