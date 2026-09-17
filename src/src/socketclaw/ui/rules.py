"""Numeric detection policy editor with explicit units and preserved drafts."""

from __future__ import annotations

from typing import ClassVar

from pydantic import ValidationError
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Input, Static

from ..config import AppConfig
from ..rules import RuleConfig
from .context import safe_text, socketclaw_app
from .layout import ResponsiveModalScreen as ModalScreen

_THRESHOLDS = (
    ("window_seconds", "Correlation window / seconds (1-86400)"),
    ("ping_degraded_percent", "Degraded ping / loss percent (1-98)"),
    ("ping_high_loss_percent", "High-loss ping / loss percent (2-99, above degraded)"),
    ("ping_sustained_count", "Sustained ping / observations (2-10000)"),
    ("auth_failure_count", "Authentication burst / failures (2-10000)"),
    ("firewall_denial_count", "Firewall burst / denials (2-10000)"),
    ("port_open_count", "Port opening burst / ports (2-1024)"),
)


class RuleSettingsScreen(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back")]
    DEFAULT_CSS = """
    RuleSettingsScreen { background: $surface; layout: vertical; padding: 0 1; }
    RuleSettingsScreen > Static { height: auto; margin-bottom: 1; }
    #rule-fields { height: 1fr; }
    #rule-fields Static { height: auto; }
    #rule-fields Input { height: 3; margin-bottom: 1; }
    #rule-actions { height: 3; align-horizontal: right; }
    #rule-actions Button { margin-left: 1; }
    #rule-feedback { height: 2; margin: 0; }
    """

    def __init__(self, config: RuleConfig) -> None:
        super().__init__()
        self.baseline = config
        self.saving = False

    def compose(self) -> ComposeResult:
        yield Static("DETECTION RULES / balanced preset")
        yield Static(
            "Counts include the current observation. Windows use collection time. "
            "Changes apply to new observations; saved history keeps its original rules.",
            markup=False,
        )
        with VerticalScroll(id="rule-fields"):
            for field, label in _THRESHOLDS:
                yield Static(label)
                yield Input(str(getattr(self.baseline, field)), type="integer", id=f"rule-{field}")
            yield Static("SCORE CONTRIBUTIONS / points (0-100 each, total capped at 100)")
            for field, value in self.baseline.points.model_dump().items():
                yield Static(field.replace("_", " ").capitalize())
                yield Input(str(value), type="integer", id=f"points-{field}")
        yield Static("", id="rule-feedback", markup=False)
        with Horizontal(id="rule-actions"):
            yield Button("Apply rules", id="apply-rules", variant="primary")
            yield Button("Reload saved", id="reload-rules")
            yield Button("Back", id="close-rules")

    def on_mount(self) -> None:
        self.query_one("#rule-window_seconds", Input).focus()

    def action_close(self) -> None:
        if not self.saving:
            self.dismiss(None)

    @on(Button.Pressed, "#close-rules")
    def close_button(self) -> None:
        self.action_close()

    @on(Button.Pressed, "#reload-rules")
    def reload_saved(self) -> None:
        self.baseline = socketclaw_app(self).config.rules
        for field, _ in _THRESHOLDS:
            self.query_one(f"#rule-{field}", Input).value = str(getattr(self.baseline, field))
        for field, value in self.baseline.points.model_dump().items():
            self.query_one(f"#points-{field}", Input).value = str(value)
        self._message("Loaded saved rules. Previous draft discarded.")

    def _message(self, value: str) -> None:
        self.query_one("#rule-feedback", Static).update(safe_text(value))

    @on(Button.Pressed, "#apply-rules")
    def apply_rules(self) -> None:
        self._save()

    @work(exclusive=True, group="rule-settings-save")
    async def _save(self) -> None:
        self.saving = True
        for button in self.query(Button):
            button.disabled = True
        try:
            values = {
                field: int(self.query_one(f"#rule-{field}", Input).value)
                for field, _ in _THRESHOLDS
            }
            points = {
                field: int(self.query_one(f"#points-{field}", Input).value)
                for field in self.baseline.points.model_dump()
            }
            draft = RuleConfig.model_validate({**values, "points": points})
            baseline = self.baseline.model_dump()
            edited = draft.model_dump()

            def merge(current: AppConfig) -> AppConfig:
                latest = current.rules.model_dump()
                for section, before, after in (
                    ("rules", baseline, edited),
                    ("points", baseline["points"], edited["points"]),
                ):
                    destination = latest if section == "rules" else latest["points"]
                    for field, value in after.items():
                        if field == "points" or value == before[field]:
                            continue
                        if destination[field] not in (before[field], value):
                            raise ValueError(
                                f"{field} changed elsewhere. "
                                "Draft kept; reload saved rules to resolve."
                            )
                        destination[field] = value
                policy = RuleConfig.model_validate(latest)
                return current.model_copy(update={"rules": policy})

            updated = await socketclaw_app(self).update_config(merge)
            self.baseline = updated.rules
            # Reflect any unrelated settings merged from another editor.
            self.reload_saved()
            self._message("Rules saved. The next new observation records its applied rule version.")
        except ValidationError as exc:
            self._message(f"Rules were not saved: {exc.errors()[0]['msg']}")
        except Exception as exc:
            self._message(f"Rules were not saved: {exc}")
        finally:
            self.saving = False
            for button in self.query(Button):
                button.disabled = False
