"""Live per-probe health without adding another top-level workspace."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Protocol, cast

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.widgets import Button, DataTable, Static

from ..domain import utc_now
from ..health import ProbeHealth
from ..monitor import MonitorStatus
from .context import escape_markdown, safe_text, socketclaw_app
from .detail import DetailScreen
from .layout import ResponsiveModalScreen as ModalScreen


class HealthSource(Protocol):
    @property
    def status(self) -> MonitorStatus: ...


class HealthScreen(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "close", "Back")]
    DEFAULT_CSS = """
    HealthScreen { background: $surface; layout: vertical; padding: 0 1; }
    HealthScreen > Static { height: auto; margin-bottom: 1; }
    HealthScreen > DataTable { height: 1fr; }
    HealthScreen > Button { height: 3; }
    """

    def __init__(self, monitor: HealthSource) -> None:
        super().__init__()
        self.monitor = monitor
        self._records: dict[str, ProbeHealth] = {}
        self._cells: dict[str, tuple[str, str, str]] = {}

    def compose(self) -> ComposeResult:
        yield Static("HEALTH / Enter inspects a probe / Esc returns", markup=False)
        yield Static("", id="health-summary", markup=False)
        yield DataTable(id="health-table", cursor_type="row", zebra_stripes=True)
        yield Static(
            "Stale: no successful poll within 3 intervals (minimum 10 seconds).\n"
            "Pause holds new scheduled starts; in-flight collection finishes.",
            markup=False,
        )
        yield Button("Back", id="health-close", variant="primary")

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one("#health-table", DataTable))
        table.add_column("PROBE", width=32)
        table.add_column("STATE", width=18)
        table.add_column("LAST SUCCESS", width=12)
        self.refresh_health()
        table.focus()
        self.set_interval(1, self.refresh_health)

    def refresh_health(self) -> None:
        if socketclaw_app(self).screen is not self:
            return
        status = self.monitor.status
        now = utc_now()
        self._records = {item.probe_id: item for item in status.probe_health}
        state = "Paused" if status.paused else "Running" if status.running else "Stopped"
        self.query_one("#health-summary", Static).update(
            f"{state} / pending batches: {status.pending_batches} / "
            f"dropped UI notifications: {status.dropped_notifications}\n"
            + (
                safe_text(status.last_error)[:160]
                if status.last_error
                else "No current collection error."
            )
            + ("\nNo probes have been scheduled." if not self._records else "")
        )
        table = cast(DataTable[str], self.query_one("#health-table", DataTable))
        for name in self._cells.keys() - self._records.keys():
            table.remove_row(name)
            self._cells.pop(name)
        for name, health in self._records.items():
            label = health.state.upper() + (" / STALE" if health.is_stale(now) else "")
            cells = (safe_text(name), label, _time(health.last_success_at, short=True))
            if name not in self._cells:
                table.add_row(*cells, key=name)
            elif self._cells[name] != cells:
                for column, value in zip(table.columns, cells, strict=True):
                    table.update_cell(name, column, value)
            self._cells[name] = cells

    @on(DataTable.RowSelected, "#health-table")
    def inspect_probe(self, event: DataTable.RowSelected) -> None:
        health = self._records.get(str(event.row_key.value))
        if health is not None:
            socketclaw_app(self).push_screen(DetailScreen(health_markdown(health)))

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#health-close")
    def close_button(self) -> None:
        self.action_close()


def health_markdown(health: ProbeHealth) -> str:
    return (
        f"## {escape_markdown(health.probe_id)}\n\n"
        f"**{health.state.upper()}** / {health.activity} / "
        f"{'STALE' if health.is_stale(utc_now()) else 'current'}\n\n"
        "Collection health describes measurement quality, not whether the target is reachable.\n\n"
        f"Last attempt: {_time(health.last_attempt_at)}  \n"
        f"Last success: {_time(health.last_success_at)}  \n"
        f"Last observation: {_time(health.last_observation_at)}  \n"
        f"Next scheduled start: {_time(health.next_due_at)}\n\n"
        f"Target interval: {health.interval_seconds:g} seconds  \n"
        f"Start delay: {health.lag_ms:.1f} ms / last duration: {health.duration_ms:.1f} ms  \n"
        f"Skipped ticks: {health.skipped_ticks} / "
        f"consecutive errors: {health.consecutive_errors}  \n"
        f"Pending observations: {health.pending_observations}\n\n"
        f"{escape_markdown(health.error or 'No current error.')}\n\n"
        f"Updated: {_time(health.updated_at)}"
    )


def _time(value: datetime | None, *, short: bool = False) -> str:
    if value is None:
        return "Never" if short else "Not available"
    return value.astimezone().strftime("%H:%M:%S") if short else value.isoformat(timespec="seconds")
