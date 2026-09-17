"""Read committed log progress without advancing a watched file."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol, cast

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, ContentSwitcher, DataTable, Input, Static, TabbedContent

from ..collection import CheckpointChange, LogCheckpointState
from ..config import AppConfig
from ..probes.logs import preview_log
from .context import escape_markdown, safe_text, socketclaw_app
from .detail import DetailScreen


class CheckpointReader(Protocol):
    async def load_checkpoint(self, probe_id: str) -> CheckpointChange: ...


class LogSourcesView(Vertical):
    DEFAULT_CSS = """
    LogSourcesView { height: 1fr; }
    #logs-table { height: 1fr; min-height: 3; }
    """

    def __init__(self) -> None:
        super().__init__(id="log-sources-view")
        self._cells: dict[str, tuple[str, str, str]] = {}

    def compose(self) -> ComposeResult:
        with Horizontal(classes="filter-row"):
            yield Input(placeholder="Local log file path", id="log-source-path")
            yield Button("Add source", id="add-log-source", variant="primary")
        yield Static(
            "Select a source to inspect or test read.",
            id="logs-feedback",
            classes="inline-state",
            markup=False,
        )
        yield DataTable(id="logs-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="action-row"):
            yield Button("Inspect", id="inspect-log", variant="primary")
            yield Button("Test read", id="test-log")
            yield Button("Remove", id="remove-log", variant="error")
            yield Button("Refresh", id="refresh-logs")

    def on_mount(self) -> None:
        table = cast(DataTable[str], self.query_one("#logs-table", DataTable))
        table.add_column("PATH", width=36)
        table.add_column("STATE", width=18)
        table.add_column("BACKLOG BYTES", width=13)
        self.set_interval(2, self._refresh_visible)

    def _refresh_visible(self) -> None:
        if self._active():
            self.refresh_data()

    def _active(self) -> bool:
        app = socketclaw_app(self)
        return app.screen is self.screen and (
            app.screen.query_one("#workspace", ContentSwitcher).current == "hosts-view"
            and app.screen.query_one("#hosts-tabs", TabbedContent).active == "host-logs"
        )

    @work(exclusive=True, group="log-source-read")
    async def refresh_data(self) -> None:
        app = socketclaw_app(self)
        if app.services.repository is None:
            return
        paths = tuple(app.config.log_paths)
        try:
            states = [(path, await log_state(app.services.repository, path)) for path in paths]
        except Exception as exc:
            self._message(f"Cannot read source status: {exc}")
            return
        if paths != tuple(app.config.log_paths):
            return
        table = cast(DataTable[str], self.query_one("#logs-table", DataTable))
        for path in self._cells.keys() - set(paths):
            table.remove_row(path)
            self._cells.pop(path)
        for path, state in states:
            cells = (safe_text(path), _state_label(state), f"{state.backlog_bytes:,}")
            if path not in self._cells:
                table.add_row(*cells, key=path)
            elif cells != self._cells[path]:
                for column, value in zip(table.columns, cells, strict=True):
                    table.update_cell(path, column, value)
            self._cells[path] = cells
        if not paths:
            self._message("No log sources configured. Add a local file path above.")

    def _selected_path(self) -> str | None:
        table = cast(DataTable[str], self.query_one("#logs-table", DataTable))
        if not table.row_count:
            self._message("Select a log source first.")
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    def _message(self, message: str) -> None:
        self.query_one("#logs-feedback", Static).update(safe_text(message))

    @on(Button.Pressed, "#refresh-logs")
    def refresh_button(self) -> None:
        self.refresh_data()

    @on(Button.Pressed, "#add-log-source")
    @on(Input.Submitted, "#log-source-path")
    def add_source(self) -> None:
        self._add_source()

    @work(exclusive=True, group="log-source-update")
    async def _add_source(self) -> None:
        app = socketclaw_app(self)
        path = self.query_one("#log-source-path", Input).value.strip()
        if not path:
            self._message("Enter a local log file path.")
            return
        try:

            def add(current: AppConfig) -> AppConfig:
                paths = list(dict.fromkeys([*current.log_paths, path]))
                return AppConfig.model_validate({**current.model_dump(), "log_paths": paths})

            await app.update_config(add)
        except Exception as exc:
            self._message(f"Source was not added: {exc}")
            return
        self.query_one("#log-source-path", Input).value = ""
        self._message("Source saved. The monitor will report read errors if it is unavailable.")
        self.refresh_data()

    @on(Button.Pressed, "#remove-log")
    def remove_source(self) -> None:
        path = self._selected_path()
        if path is not None:
            self._remove_source(path)

    @work(exclusive=True, group="log-source-update")
    async def _remove_source(self, path: str) -> None:
        app = socketclaw_app(self)
        try:
            await app.update_config(
                lambda current: current.model_copy(
                    update={
                        "log_paths": [item for item in current.log_paths if item != path],
                    }
                )
            )
        except Exception as exc:
            self._message(f"Source was not removed: {exc}")
            return
        self._message(
            "Source removed from monitoring. Stored observations and cursor are retained."
        )
        self.refresh_data()

    @on(Button.Pressed, "#inspect-log")
    @on(DataTable.RowSelected, "#logs-table")
    def inspect_source(self) -> None:
        path = self._selected_path()
        if path is not None:
            self._inspect_source(path)

    @work(exclusive=True, group="log-source-inspect")
    async def _inspect_source(self, path: str) -> None:
        app = socketclaw_app(self)
        if app.services.repository is None:
            return
        try:
            content = await log_status_markdown(app.services.repository, [path])
        except Exception as exc:
            self._message(f"Cannot inspect source: {exc}")
            return
        if not self._active() or path not in app.config.log_paths:
            return
        app.push_screen(DetailScreen(content))

    @on(Button.Pressed, "#test-log")
    def test_source(self) -> None:
        path = self._selected_path()
        if path is not None:
            self._test_source(path)

    @work(exclusive=True, group="log-source-preview")
    async def _test_source(self, path: str) -> None:
        try:
            preview = await preview_log(Path(path))
        except Exception as exc:
            self._message(f"Cannot test read source: {exc}")
            return
        if not self._active() or path not in socketclaw_app(self).config.log_paths:
            return
        content = (
            f"## Test read: {escape_markdown(path)}\n\n"
            "This preview does not save observations or advance the collector.\n\n"
            f"Read {preview.bytes_read:,} bytes from a {preview.file_size:,}-byte file. "
            f"Inspected up to {preview.complete_lines} complete lines. "
            f"Showing {len(preview.matches)} matches (maximum 20).\n\n"
            f"Sample limited: {'yes' if preview.limited else 'no'} / "
            f"sampled at {preview.sampled_at.isoformat(timespec='seconds')}\n\n"
        )
        for event in preview.matches:
            content += (
                f"### {escape_markdown(event.event_type)}\n\n"
                f"Source IP: {escape_markdown(event.target or 'unknown')} / "
                f"parse: {escape_markdown(str(event.evidence.get('parse_quality', 'unknown')))}\n\n"
                f"{escape_markdown(event.summary)}\n\n"
            )
        socketclaw_app(self).push_screen(DetailScreen(content))


async def log_state(repository: CheckpointReader, configured: str) -> LogCheckpointState:
    path = Path(configured).expanduser().absolute()
    probe_id = "log:" + hashlib.sha256(str(path).encode()).hexdigest()
    checkpoint = await repository.load_checkpoint(probe_id)
    return LogCheckpointState.model_validate(checkpoint.state)


def _state_label(state: LogCheckpointState) -> str:
    if state.missing:
        return "Missing"
    if state.error:
        return "Read error"
    if state.backlog_bytes:
        return "Catching up"
    return "Current" if state.last_read_at else "Not read yet"


async def log_status_markdown(repository: CheckpointReader, paths: list[str]) -> str:
    sections = [
        "## Log sources\n\n"
        "First attachment skips existing content (tail). Restart resumes the committed position. "
        "Progress below reflects the last committed poll. Press Esc, then Enter to refresh."
    ]
    if not paths:
        sections.append("No log sources configured. Add a path in Hosts / Logs.")
    for configured in paths:
        path = Path(configured).expanduser().absolute()
        state = await log_state(repository, configured)
        status = _state_label(state)
        read_at = (
            state.last_read_at.isoformat(timespec="seconds") if state.last_read_at else "Never"
        )
        sections.append(
            f"### {escape_markdown(str(path))}\n\n"
            f"**{status}** / {state.read_policy}\n\n"
            f"Committed bytes: {state.offset:,} / sampled file size: {state.sampled_size:,}  \n"
            f"Remaining bytes: {state.backlog_bytes:,} / last read: {read_at}  \n"
            f"Matches in last poll: {state.last_match_count} / "
            f"truncated lines: {state.truncated_lines}  \n"
            f"Recorded gaps: {state.gap_count}"
            + (" (unrecoverable bytes may be unknown)" if state.gap_count else "")
            + (f"\n\n{escape_markdown(state.error)}" if state.error else "")
        )
    return "\n\n".join(sections)
