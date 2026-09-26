"""Four-step first-run setup for local files and OpenAI."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from pydantic import TypeAdapter, ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.widgets import Button, ContentSwitcher, Input, Select, SelectionList, Static

from ..config import AppConfig, ServiceConfig
from ..discovery import DiscoveryReport, discover_sources
from ..openai import OpenAIError
from .context import safe_text, socketclaw_app
from .layout import ResponsiveScreen as Screen

if TYPE_CHECKING:
    from .app import AppServices


class OnboardingScreen(Screen[None]):
    """Collect, validate, and persist the minimum useful first-run settings."""

    def __init__(
        self,
        services: AppServices,
        initial_config: AppConfig,
        *,
        existing_api_key: str | None = None,
    ) -> None:
        super().__init__()
        self.services = services
        self.current_step = 0
        self._existing_api_key = existing_api_key
        self._pending_key = existing_api_key
        self._pending_config = initial_config.model_copy(deep=True)
        self.discovery: DiscoveryReport | None = None

    def set_appearance(self, theme: str) -> None:
        self._pending_config = self._pending_config.model_copy(update={"theme": theme})

    def on_mount(self) -> None:
        self.set_class(self.size.height < 27 or self.size.width < 82, "compact")
        self.query_one("#onboarding-skip", Button).display = False
        self.query_one("#onboarding-next", Button).focus()
        self.discover()

    def on_resize(self, event: Resize) -> None:
        self.set_class(event.size.height < 27 or event.size.width < 82, "compact")

    def compose(self) -> ComposeResult:
        with Vertical(id="onboarding-shell"):
            yield Static("socketclaw", id="onboarding-brand")
            yield Static(
                "A quiet watch on your network",
                id="onboarding-kicker",
            )
            yield Static("1 / 4   Welcome", id="onboarding-progress")
            with ContentSwitcher(
                initial="onboarding-welcome",
                id="onboarding-steps",
            ):
                with VerticalScroll(id="onboarding-welcome", classes="onboarding-step"):
                    yield Static("Let's set up your watch.", classes="step-title")
                    yield Static(
                        "Watch hosts and logs from this terminal. "
                        "Observations stay on your Mac. AI investigations are optional.",
                        classes="step-copy",
                    )
                    yield Static(
                        "Files stay under ~/.socketclaw by default.",
                        classes="step-note",
                    )
                with VerticalScroll(id="onboarding-key", classes="onboarding-step"):
                    yield Static("Connect OpenAI", classes="step-title")
                    yield Static(
                        "Add an API key for investigations, or skip to monitor locally. "
                        "You can connect later with /settings.",
                        classes="step-copy",
                    )
                    yield Input(
                        placeholder=(
                            "Configured key will be kept"
                            if self._pending_key is not None
                            else "sk-proj-..."
                        ),
                        password=True,
                        id="api-key",
                    )
                with VerticalScroll(id="onboarding-target-step", classes="onboarding-step"):
                    yield Static("Choose what this watch can observe", classes="step-title")
                    yield Select(
                        [
                            ("Local development services", "local"),
                            ("Specified server health", "server"),
                            ("Security log investigation", "logs"),
                        ],
                        value=self._pending_config.profile,
                        allow_blank=False,
                        id="onboarding-profile",
                    )
                    yield Static(
                        "Targets use ICMP and TCP only. Blank is allowed for log-only monitoring.",
                        classes="step-copy",
                    )
                    yield Input(
                        value=", ".join(self._pending_config.targets),
                        placeholder="1.1.1.1, gateway.local",
                        id="onboarding-targets",
                    )
                    yield Static("Readable log files / JSON list", classes="field-label")
                    yield Input(json.dumps(self._pending_config.log_paths), id="onboarding-logs")
                    yield Static("Discovered local candidates: select intended sources only.")
                    yield SelectionList[str](id="onboarding-candidates")
                    yield Static(
                        "Discovering readable sources…", id="onboarding-discovery", markup=False
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
                with VerticalScroll(id="onboarding-ready", classes="onboarding-step"):
                    yield Static(
                        "Configuration ready. First observation pending.", classes="step-title"
                    )
                    yield Static(
                        "Use / to browse commands. Pause with Space. "
                        "Switch appearance with Ctrl+T.",
                        classes="step-copy",
                    )
                    yield Static(
                        "",
                        id="onboarding-summary",
                        classes="step-note",
                        markup=False,
                    )
            yield Static("", id="onboarding-error", markup=False)
            with Horizontal(id="onboarding-actions"):
                yield Button("Back", id="onboarding-back", disabled=True)
                yield Button("Skip for now", id="onboarding-skip")
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
            if (
                not self.query_one("#api-key", Input).value.strip()
                and self._pending_key is not None
            ):
                self._show_step(2)
                return
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
        button = self.query_one("#onboarding-next", Button)
        button.disabled = True
        button.label = "Starting…"
        try:
            await app.complete_onboarding(self._pending_config, self._pending_key)
        except Exception as exc:
            self._set_error(f"Setup could not be completed: {exc}")
            button.disabled = False
            button.label = "Start monitoring"

    @on(Input.Submitted)
    def submit_input(self) -> None:
        self.query_one("#onboarding-next", Button).press()

    @on(Button.Pressed, "#onboarding-skip")
    def skip_openai(self) -> None:
        if self.current_step != 1:
            return
        self._pending_key = self._existing_api_key
        self.query_one("#api-key", Input).value = ""
        self._show_step(2)

    async def _validate_key(self) -> None:
        key_input = self.query_one("#api-key", Input)
        key = key_input.value.strip()
        if not key:
            self._set_error("Enter an OpenAI API key.")
            key_input.focus()
            return
        button = self.query_one("#onboarding-next", Button)
        button.disabled = True
        button.label = "Validating…"
        try:
            await self.services.validate_key(key)
        except OpenAIError as exc:
            self._set_error(str(exc))
            key_input.focus()
            return
        except Exception:
            self._set_error("OpenAI validation failed. Check your connection.")
            key_input.focus()
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
                    "profile": cast(
                        Select[str], self.query_one("#onboarding-profile", Select)
                    ).value,
                    "log_paths": self._selected_logs(),
                    "services": self._selected_services(),
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
            self.query_one("#onboarding-targets", Input).focus()
            return False
        return True

    @work(exclusive=True, group="source-discovery")
    async def discover(self) -> None:
        try:
            report = await discover_sources()
            if not self.is_mounted or not self.query("#onboarding-candidates"):
                return
            self.discovery = report
            choices = cast(
                SelectionList[str], self.query_one("#onboarding-candidates", SelectionList)
            )
            for index, source in enumerate(report.sources):
                if source.supported and source.readable:
                    choices.add_option((f"Log file: {source.path}", f"source:{index}"))  # pyright: ignore[reportUnknownMemberType]
            for index, listener in enumerate(report.listeners):
                choices.add_option(  # pyright: ignore[reportUnknownMemberType]
                    (
                        f"Service: {listener.process or 'unknown process'} "
                        f"{listener.host}:{listener.port} / {listener.exposure}",
                        f"listener:{index}",
                    )
                )
            unavailable = [
                f"{source.path}: {source.detail}"
                for source in report.sources
                if not source.readable
            ]
            self.query_one("#onboarding-discovery", Static).update(
                "\n".join((*report.limitations, *unavailable))
            )
        except Exception as exc:
            if self.is_mounted and self.query("#onboarding-discovery"):
                self.query_one("#onboarding-discovery", Static).update(
                    f"Discovery unavailable: {exc}"
                )

    def _selected_logs(self) -> list[str]:
        raw = self.query_one("#onboarding-logs", Input).value.strip()
        paths = TypeAdapter(list[str]).validate_json(raw or "[]", strict=True)
        if self.discovery:
            for value in cast(SelectionList[str], self.query_one(SelectionList)).selected:
                if value.startswith("source:"):
                    paths.append(self.discovery.sources[int(value.split(":")[1])].path)
        return list(dict.fromkeys(paths))

    def _selected_services(self) -> list[ServiceConfig]:
        services = list(self._pending_config.services)
        if self.discovery:
            for value in cast(SelectionList[str], self.query_one(SelectionList)).selected:
                if not value.startswith("listener:"):
                    continue
                listener = self.discovery.listeners[int(value.split(":")[1])]
                host = (
                    "127.0.0.1"
                    if listener.host in {"*", "0.0.0.0"}
                    else "::1"
                    if listener.host == "::"
                    else listener.host
                )
                identifier = f"local-{listener.port}-{value.split(':')[1]}"
                service = ServiceConfig(
                    id=identifier,
                    name=f"{listener.process or 'Local service'}:{listener.port}",
                    host=host,
                    port=listener.port,
                )
                if not any(item.id == service.id for item in services):
                    services.append(service)
        return services

    def _show_step(self, step: int) -> None:
        ids = (
            "onboarding-welcome",
            "onboarding-key",
            "onboarding-target-step",
            "onboarding-ready",
        )
        self.current_step = step
        self.query_one("#onboarding-steps", ContentSwitcher).current = ids[step]
        label = ("Welcome", "Optional connection", "Watch targets", "Ready")[step]
        progress = f"{step + 1} / 4   {label}"
        self.query_one("#onboarding-progress", Static).update(progress)
        self.query_one("#onboarding-back", Button).disabled = step == 0
        self.query_one("#onboarding-skip", Button).display = step == 1
        next_button = self.query_one("#onboarding-next", Button)
        # Moving to a new step is a distinct action, even when the same button is reused.
        next_button.remove_class("-active")
        if step < 3:
            next_button.label = "Continue"
        focus_targets = (
            "#onboarding-next",
            "#api-key",
            "#onboarding-targets",
            "#onboarding-next",
        )
        self.call_after_refresh(self.query_one(focus_targets[step]).focus)

    def _render_summary(self) -> None:
        preset = self._pending_config.preset
        model_summary = preset.label if self._pending_key is not None else "Local monitoring only"
        self.query_one("#onboarding-summary", Static).update(
            f"{len(self._pending_config.targets)} network target(s) / "
            f"{len(self._pending_config.log_paths)} log file(s) / "
            f"{len(self._pending_config.services)} required service(s)\n"
            f"{model_summary} / "
            f"Ping {self._pending_config.ping_interval:g}s / "
            f"Scan {self._pending_config.scan_interval:g}s\n"
            "Collection is not yet verified. Overview will show actual first evidence and gaps."
        )

    def _set_error(self, message: str) -> None:
        self.query_one("#onboarding-error", Static).update(safe_text(message))


def _validation_message(error: Exception) -> str:
    if isinstance(error, ValidationError) and error.errors():
        return str(error.errors()[0].get("msg", "Invalid settings."))
    return "Enter valid targets and intervals."
