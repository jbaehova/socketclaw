"""Installed SocketClaw command line and Textual runtime composition."""

from __future__ import annotations

# pyright: reportUnknownMemberType=false
import asyncio
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from click import ClickException

from . import __version__
from .config import AppConfig, ConfigStore
from .detection import Detector
from .doctor import inspect_environment
from .domain import SecurityEvent
from .export import export_json, export_markdown
from .monitor import MonitorService, ProbeJob
from .probes.logs import LogProbe
from .probes.ping import PingProbe
from .probes.ports import PortProbe
from .storage import EventQuery, Repository
from .ui.app import AppServices, SocketClawApp

app = typer.Typer(
    name="socketclaw",
    help="Local-first terminal security operations cockpit.",
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=False,
)
config_app = typer.Typer(help="Inspect the effective local configuration.")
app.add_typer(config_app, name="config")


@app.callback()
def main(ctx: typer.Context) -> None:
    """Launch the operational TUI when no subcommand is supplied."""
    if ctx.invoked_subcommand is None:
        _launch_tui(ConfigStore())


@app.command("version")
def version_command() -> None:
    """Print the installed SocketClaw version."""
    typer.echo(f"SocketClaw {__version__}")


@config_app.command("path")
def config_path() -> None:
    """Print the effective SocketClaw home directory."""
    typer.echo(str(ConfigStore().home))


@app.command("doctor")
def doctor_command() -> None:
    """Check launch-critical paths and optional system commands."""
    report = asyncio.run(inspect_environment(ConfigStore()))
    typer.echo(report.render())
    if not report.launch_ready:
        raise typer.Exit(1)


@app.command("export")
def export_command(
    format_: Annotated[
        str,
        typer.Option(
            "--format",
            help="Export format: markdown or json.",
        ),
    ] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Destination path. Defaults below ~/.socketclaw/exports.",
        ),
    ] = None,
    event_id: Annotated[
        str | None,
        typer.Option(
            "--event",
            help="Specific event UUID. Defaults to the newest event.",
        ),
    ] = None,
) -> None:
    """Export one durable incident without exposing configured secrets."""
    normalized_format = format_.casefold()
    if normalized_format not in {"markdown", "json"}:
        raise typer.BadParameter(
            "choose markdown or json",
            param_hint="--format",
        )
    selected_id: UUID | None = None
    if event_id is not None:
        try:
            selected_id = UUID(event_id)
        except ValueError as exc:
            raise typer.BadParameter(
                "event must be a UUID",
                param_hint="--event",
            ) from exc

    store = ConfigStore()
    rendered, event_uuid = asyncio.run(_render_export(store, normalized_format, selected_id))
    if rendered is None or event_uuid is None:
        typer.echo("No events are available to export.")
        raise typer.Exit(1)
    suffix = "md" if normalized_format == "markdown" else "json"
    destination = output or store.home / "exports" / f"{event_uuid}.{suffix}"
    _atomic_private_write(destination, rendered)
    typer.echo(f"Exported {event_uuid} to {destination}")


def _launch_tui(store: ConfigStore) -> None:
    """Build all local services, run Textual, and close SQLite on exit."""
    repository = Repository(store.database_path)
    asyncio.run(repository.initialize())
    monitor = _build_monitor(store.load(), repository)
    socketclaw = SocketClawApp(
        AppServices(
            config_store=store,
            monitor=monitor,
            repository=repository,
        )
    )
    try:
        socketclaw.run()
    finally:
        asyncio.run(repository.close())


def _build_monitor(config: AppConfig, repository: Repository) -> MonitorService:
    ping = PingProbe()
    ports = PortProbe()
    jobs: list[ProbeJob] = []
    for target in config.targets:

        async def collect_ping(selected: str = target) -> Sequence[SecurityEvent]:
            return (await ping.collect(selected),)

        async def collect_ports(selected: str = target) -> Sequence[SecurityEvent]:
            return (await ports.collect(selected, config.ports),)

        jobs.extend(
            (
                ProbeJob(f"ping:{target}", config.ping_interval, collect_ping),
                ProbeJob(f"ports:{target}", config.scan_interval, collect_ports),
            )
        )

    if config.log_paths:
        logs = LogProbe([Path(path) for path in config.log_paths])
        jobs.append(ProbeJob("logs", 1.0, logs.poll))

    async def diagnose_ping(target: str) -> SecurityEvent:
        return await ping.collect(target)

    async def diagnose_ports(target: str) -> SecurityEvent:
        return await ports.collect(target, config.ports)

    return MonitorService(
        repository,
        Detector(),
        jobs=jobs,
        diagnostics={
            "ping": diagnose_ping,
            "ports": diagnose_ports,
        },
    )


async def _render_export(
    store: ConfigStore,
    format_: str,
    event_id: UUID | None,
) -> tuple[str | None, UUID | None]:
    repository = Repository(store.database_path)
    await repository.initialize()
    try:
        if event_id is None:
            events = await repository.list_events(EventQuery(limit=1))
            event = events[0] if events else None
        else:
            event = await repository.get_event(event_id)
        if event is None:
            return None, None
        investigations = await repository.list_investigations(
            event_id=event.id,
            limit=1,
        )
        key = store.load_api_key()
        secrets = [key] if key else ()
        investigation = investigations[0] if investigations else None
        rendered = (
            export_json(event, investigation, secrets=secrets)
            if format_ == "json"
            else export_markdown(event, investigation, secrets=secrets)
        )
        return rendered, event.id
    finally:
        await repository.close()


def _atomic_private_write(destination: Path, content: str) -> None:
    destination = destination.expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(0o600)
        os.replace(temporary_path, destination)
        destination.chmod(0o600)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise ClickException(f"Cannot write export: {exc}") from exc
