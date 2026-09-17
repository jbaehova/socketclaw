"""Installed SocketClaw command line and Textual runtime composition."""

from __future__ import annotations

# pyright: reportUnknownMemberType=false
import asyncio
import errno
import os
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from click import ClickException

from . import __version__
from .collection import ProbeBatch
from .config import AppConfig, ConfigStore
from .detection import Detector
from .doctor import inspect_environment
from .domain import SecurityEvent
from .export import (
    export_incident_json,
    export_incident_markdown,
    export_json,
    export_markdown,
    write_managed_export,
)
from .monitor import Diagnostic, MonitorService, ProbeJob
from .openai import redact_secrets
from .probes.logs import LogProbe
from .probes.ping import PingProbe
from .probes.ports import PortProbe
from .rules import RuleConfig
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
db_app = typer.Typer(help="Inspect and migrate local storage.")
app.add_typer(db_app, name="db")


@app.callback()
def main(ctx: typer.Context) -> None:
    """Launch the operational TUI when no subcommand is supplied."""
    if ctx.invoked_subcommand is None:
        try:
            _launch_tui(ConfigStore())
        except Exception as exc:
            raise ClickException(f"Cannot launch SocketClaw: {_error_detail(exc)}") from exc


@app.command("version")
def version_command() -> None:
    """Print the installed SocketClaw version."""
    typer.echo(f"SocketClaw {__version__}")


@config_app.command("path")
def config_path() -> None:
    """Print the effective SocketClaw home directory."""
    try:
        home = ConfigStore().home
    except Exception as exc:
        raise ClickException(f"Cannot resolve SocketClaw home: {_error_detail(exc)}") from exc
    typer.echo(_terminal_text(str(home)))


@app.command("doctor")
def doctor_command() -> None:
    """Check launch-critical paths and optional system commands."""
    try:
        report = asyncio.run(inspect_environment(ConfigStore()))
    except Exception as exc:
        raise ClickException(f"Cannot inspect this environment: {_error_detail(exc)}") from exc
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
    incident_id: Annotated[
        str | None,
        typer.Option("--incident", help="Operational incident UUID, including its full history."),
    ] = None,
) -> None:
    """Export an observation or operational incident without exposing configured secrets."""
    normalized_format = format_.casefold()
    if normalized_format not in {"markdown", "json"}:
        raise typer.BadParameter(
            "choose markdown or json",
            param_hint="--format",
        )
    if event_id is not None and incident_id is not None:
        raise typer.BadParameter("choose either --event or --incident")
    incident_uuid: UUID | None = None
    if incident_id is not None:
        try:
            incident_uuid = UUID(incident_id)
        except ValueError as exc:
            raise typer.BadParameter("incident must be a UUID", param_hint="--incident") from exc
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
    try:
        store.ensure_home()
        rendered, event_uuid = asyncio.run(
            _render_export(store, normalized_format, selected_id, incident_uuid)
        )
    except Exception as exc:
        raise ClickException(f"Cannot export incident: {_error_detail(exc)}") from exc
    if rendered is None or event_uuid is None:
        if incident_uuid is not None:
            typer.echo(f"Incident {incident_uuid} was not found.")
        elif selected_id is None:
            typer.echo("No events are available to export.")
        else:
            typer.echo(f"Event {selected_id} was not found.")
        raise typer.Exit(1)
    suffix = "md" if normalized_format == "markdown" else "json"
    filename = f"{'incident-' if incident_uuid else ''}{event_uuid}.{suffix}"
    if output is None:
        try:
            destination = write_managed_export(store.home, filename, rendered)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ClickException(f"Cannot write export: {_error_detail(exc)}") from exc
        typer.echo(f"Exported {event_uuid} to {_terminal_text(str(destination))}")
        return
    try:
        destination = output.expanduser()
    except (OSError, RuntimeError) as exc:
        raise ClickException(f"Cannot resolve export destination: {_error_detail(exc)}") from exc
    _validate_export_destination(store, destination)
    _atomic_private_write(destination, rendered)
    typer.echo(f"Exported {event_uuid} to {_terminal_text(str(destination))}")


@db_app.command("migrate")
def migrate_database() -> None:
    """Upgrade storage with a verified recovery backup under the home writer lock."""
    store = ConfigStore()
    try:
        store.ensure_home()
        store.load()  # Validate configuration before modifying storage.
        lock = _ApplicationLock(store.home / ".instance.lock")
        lock.acquire()
        try:
            asyncio.run(_migrate_database(store))
        finally:
            lock.release()
    except Exception as exc:
        raise ClickException(f"Cannot migrate storage: {_error_detail(exc)}") from exc


async def _migrate_database(store: ConfigStore) -> None:
    repository = Repository(store.database_path)
    try:
        await repository.initialize()
        info = await repository.database_info()
        typer.echo(
            f"Storage schema {info.schema_version} verified. "
            f"Backups: {_terminal_text(str(store.home / 'backups'))}"
        )
    finally:
        await repository.close()


@db_app.command("status")
def database_status() -> None:
    """Check storage without migrating or recovering work owned by another process."""

    async def inspect_status() -> None:
        store = ConfigStore()
        repository = Repository(store.database_path, read_only=True)
        try:
            info = await repository.database_info()
            typer.echo(f"Schema {info.schema_version} / {info.journal_mode.upper()} / integrity OK")
        finally:
            await repository.close()

    try:
        asyncio.run(inspect_status())
    except Exception as exc:
        raise ClickException(f"Cannot inspect storage: {_error_detail(exc)}") from exc


def _launch_tui(store: ConfigStore) -> None:
    """Build all local services, run Textual, and close SQLite on exit."""
    store.ensure_home()
    lock = _ApplicationLock(store.home / ".instance.lock")
    lock.acquire()
    try:
        asyncio.run(_run_tui(store))
    finally:
        lock.release()


async def _run_tui(store: ConfigStore) -> None:
    """Keep repository and Textual work on one event loop for async portability."""
    store.ensure_home()
    repository = Repository(store.database_path)
    run_id: UUID | None = None
    monitor: MonitorService | None = None
    clean_shutdown = False
    failure: BaseException | None = None
    try:
        active_config = store.load()
        await repository.initialize()
        run_id = (await repository.start_run(__version__)).id
        planner = _ProbePlanner(repository=repository)
        monitor = _build_monitor(active_config, repository, planner=planner)

        async def reconfigure(config: AppConfig) -> None:
            nonlocal active_config
            if _monitoring_settings(config) == _monitoring_settings(active_config):
                active_config = config
                return
            candidate = planner.prepare(config)
            await planner.activate(monitor, candidate)
            active_config = config

        socketclaw = SocketClawApp(
            AppServices(
                config_store=store,
                monitor=monitor,
                repository=repository,
                reconfigure=reconfigure,
            )
        )
        await socketclaw.run_async()
        clean_shutdown = True
    except BaseException as exc:
        failure = exc

    cleanup_error: BaseException | None = None
    if monitor is not None:
        try:
            await monitor.stop()
        except BaseException as exc:
            cleanup_error = exc
            clean_shutdown = False
    if run_id is not None:
        try:
            await repository.stop_run(run_id, clean_shutdown=clean_shutdown)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
    try:
        await repository.close()
    except BaseException as exc:
        if cleanup_error is None:
            cleanup_error = exc

    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    if cleanup_error is not None:
        raise cleanup_error.with_traceback(cleanup_error.__traceback__)


def _build_monitor(
    config: AppConfig,
    repository: Repository,
    *,
    planner: _ProbePlanner | None = None,
) -> MonitorService:
    if planner is None:
        jobs, diagnostics = _build_probe_plan(config, repository=repository)
        return MonitorService(
            repository, Detector(config.rules), jobs=jobs, diagnostics=diagnostics
        )
    plan = planner.prepare(config)
    monitor = MonitorService(
        repository,
        Detector(config.rules),
        jobs=plan.jobs,
        diagnostics=plan.diagnostics,
    )
    planner.commit(plan)
    return monitor


CommandFinder = Callable[[str], str | None]


@dataclass(frozen=True, slots=True)
class _PreparedProbePlan:
    jobs: tuple[ProbeJob, ...]
    diagnostics: dict[str, Diagnostic]
    rules: RuleConfig
    port_numbers: tuple[int, ...]
    targets: tuple[str, ...]
    port_probe: PortProbe
    log_paths: tuple[Path, ...]
    log_probe: LogProbe | None
    ping_executable: str | None
    ping_probe: PingProbe | None


class _ProbePlanner:
    """Stage probe plans while preserving stateful collectors when safe."""

    def __init__(
        self, *, which: CommandFinder = shutil.which, repository: Repository | None = None
    ) -> None:
        self._which = which
        self._repository = repository
        self._committed: _PreparedProbePlan | None = None

    def prepare(self, config: AppConfig) -> _PreparedProbePlan:
        previous = self._committed
        port_numbers = tuple(config.ports)
        targets = tuple(config.targets)
        if previous is not None:
            port_probe = (
                previous.port_probe
                if previous.targets == targets
                else previous.port_probe.retained_for_targets(targets)
            )
        else:
            port_probe = PortProbe()
        log_paths = tuple(dict.fromkeys(_expand_log_paths(config.log_paths)))
        previous_log_paths: set[Path] = set(previous.log_paths) if previous is not None else set()
        retain_log_probe = (
            previous is not None
            and previous.log_probe is not None
            and bool(previous_log_paths.intersection(log_paths))
        )
        log_probe = (
            previous.log_probe
            if retain_log_probe and previous is not None
            else (LogProbe(list(log_paths), repository=self._repository) if log_paths else None)
        )
        ping_executable = _resolve_command("ping", self._which)
        ping_probe = (
            previous.ping_probe
            if ping_executable is not None
            and previous is not None
            and previous.ping_executable == ping_executable
            and previous.ping_probe is not None
            else (PingProbe(executable=ping_executable) if ping_executable is not None else None)
        )
        jobs, diagnostics = _compose_probe_plan(
            config,
            ping=ping_probe,
            ports=port_probe,
            logs=log_probe,
            repository=self._repository,
        )
        return _PreparedProbePlan(
            jobs=jobs,
            diagnostics=diagnostics,
            rules=config.rules,
            port_numbers=port_numbers,
            targets=targets,
            port_probe=port_probe,
            log_paths=log_paths,
            log_probe=log_probe,
            ping_executable=ping_executable,
            ping_probe=ping_probe,
        )

    def commit(self, plan: _PreparedProbePlan) -> None:
        self._committed = plan

    async def activate(
        self,
        monitor: MonitorService,
        plan: _PreparedProbePlan,
    ) -> None:
        """Apply a staged plan and roll back a reused log probe on failure."""
        previous = self._committed
        log_probe = plan.log_probe
        reused_changed_log = (
            previous is not None
            and log_probe is not None
            and log_probe is previous.log_probe
            and plan.log_paths != previous.log_paths
        )
        try:
            if reused_changed_log and log_probe is not None:
                await log_probe.reconfigure(list(plan.log_paths))
            await monitor.reconfigure(
                jobs=plan.jobs,
                diagnostics=plan.diagnostics,
                detector=Detector(plan.rules),
            )
        except BaseException:
            if reused_changed_log and previous is not None and log_probe is not None:
                with suppress(Exception):
                    await log_probe.reconfigure(list(previous.log_paths))
            raise
        self.commit(plan)


def _build_probe_plan(
    config: AppConfig,
    *,
    which: CommandFinder = shutil.which,
    repository: Repository | None = None,
) -> tuple[tuple[ProbeJob, ...], dict[str, Diagnostic]]:
    """Build fresh collectors for startup and in-place runtime reconfiguration."""
    plan = _ProbePlanner(which=which, repository=repository).prepare(config)
    return plan.jobs, plan.diagnostics


def _compose_probe_plan(
    config: AppConfig,
    *,
    ping: PingProbe | None,
    ports: PortProbe,
    logs: LogProbe | None,
    repository: Repository | None = None,
) -> tuple[tuple[ProbeJob, ...], dict[str, Diagnostic]]:
    jobs: list[ProbeJob] = []
    selected_ports = tuple(config.ports)
    for target in config.targets:
        if ping is not None:

            async def collect_ping(
                selected: str = target,
                probe: PingProbe = ping,
            ) -> Sequence[SecurityEvent]:
                return (await probe.collect(selected),)

            jobs.append(ProbeJob(f"ping:{target}", config.ping_interval, collect_ping))

        async def collect_ports(
            selected: str = target,
            scan_ports: tuple[int, ...] = selected_ports,
        ) -> Sequence[SecurityEvent] | ProbeBatch:
            if repository is not None:
                return await ports.collect_batch(
                    selected, scan_ports, repository, baseline_ttl=config.port_baseline_ttl
                )
            return (await ports.collect(selected, scan_ports),)

        jobs.append(ProbeJob(f"ports:{target}", config.scan_interval, collect_ports))

    if logs is not None:
        jobs.append(ProbeJob("logs", 1.0, logs.collect))

    async def diagnose_ports(target: str) -> SecurityEvent | ProbeBatch:
        if repository is not None:
            return await ports.collect_batch(
                target, selected_ports, repository, baseline_ttl=config.port_baseline_ttl
            )
        return await ports.collect(target, selected_ports)

    diagnostics: dict[str, Diagnostic] = {"ports": diagnose_ports}
    if ping is not None:
        available_ping = ping

        async def diagnose_ping(target: str) -> SecurityEvent:
            return await available_ping.collect(target)

        diagnostics["ping"] = diagnose_ping

    return tuple(jobs), diagnostics


def _resolve_command(command: str, which: CommandFinder) -> str | None:
    try:
        selected = which(command)
        if selected is None:
            return None
        return str(Path(selected).expanduser().resolve(strict=False))
    except (OSError, RuntimeError, TypeError):
        return None


def _monitoring_settings(config: AppConfig) -> tuple[object, ...]:
    return (
        tuple(config.targets),
        config.ping_interval,
        config.scan_interval,
        config.port_baseline_ttl,
        tuple(config.ports),
        tuple(config.log_paths),
        config.rules,
    )


def _expand_log_paths(configured_paths: Sequence[str]) -> list[Path]:
    expanded: list[Path] = []
    for configured in configured_paths:
        try:
            expanded.append(Path(configured).expanduser())
        except RuntimeError as exc:
            raise ClickException(f"Cannot expand log path {configured!r}: {exc}") from exc
    return expanded


class _ApplicationLock:
    """Best-effort cross-platform advisory lock for one SocketClaw home."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        if self._fd is not None:
            return
        fd: int | None = None
        try:
            existing: os.stat_result | None = None
            with suppress(FileNotFoundError):
                existing = self.path.lstat()
            if existing is not None:
                if stat.S_ISLNK(existing.st_mode):
                    raise OSError(errno.ELOOP, "lock path must not be a symbolic link")
                if not stat.S_ISREG(existing.st_mode):
                    raise OSError(errno.EINVAL, "lock path must be a regular file")
                if existing.st_nlink != 1:
                    raise OSError(errno.EPERM, "lock path must not be hard linked")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(errno.EINVAL, "lock path must be a regular file")
            if existing is not None and (
                existing.st_dev,
                existing.st_ino,
            ) != (metadata.st_dev, metadata.st_ino):
                raise OSError(errno.EBUSY, "lock path changed while opening")
            if metadata.st_nlink != 1:
                raise OSError(errno.EPERM, "lock path must not be hard linked")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            _acquire_file_lock(fd)
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise RuntimeError(f"SocketClaw is already running for {self.path.parent}") from exc
            raise RuntimeError(f"Cannot lock SocketClaw home {self.path.parent}: {exc}") from exc
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            os.fsync(fd)
        except OSError:
            with suppress(OSError):
                _release_file_lock(fd)
            with suppress(OSError):
                os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        fd = self._fd
        self._fd = None
        if fd is None:
            return
        with suppress(OSError):
            _release_file_lock(fd)
        with suppress(OSError):
            os.close(fd)


def _acquire_file_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_file_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


async def _render_export(
    store: ConfigStore,
    format_: str,
    event_id: UUID | None,
    incident_id: UUID | None = None,
) -> tuple[str | None, UUID | None]:
    if not store.database_path.exists() and not store.database_path.is_symlink():
        return None, None
    repository = Repository(store.database_path, read_only=True)
    try:
        await repository.require_current_schema()
        if incident_id is not None:
            report = await repository.incident_report(incident_id)
            if report is None:
                return None, None
            key = store.load_api_key()
            renderer = export_incident_json if format_ == "json" else export_incident_markdown
            return renderer(report, secrets=[key] if key else ()), incident_id
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
        response_proposal = None
        if investigation is not None:
            proposals = await repository.list_response_proposals(
                event_id=event.id,
                limit=500,
            )
            response_proposal = next(
                (
                    proposal
                    for proposal in proposals
                    if proposal.investigation_id == investigation.id
                ),
                None,
            )
        suppressions = await repository.incidents.suppression_decisions(event.id)
        rendered = (
            export_json(
                event,
                investigation,
                response_proposal=response_proposal,
                suppressions=suppressions,
                secrets=secrets,
            )
            if format_ == "json"
            else export_markdown(
                event,
                investigation,
                response_proposal=response_proposal,
                suppressions=suppressions,
                secrets=secrets,
            )
        )
        return rendered, event.id
    finally:
        await repository.close()


def _atomic_private_write(destination: Path, content: str) -> None:
    destination = destination.expanduser()
    temporary_path: Path | None = None
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            if hasattr(os, "fchmod"):
                os.fchmod(temporary.fileno(), 0o600)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
    except (OSError, UnicodeError) as exc:
        raise ClickException(f"Cannot write export: {_error_detail(exc)}") from exc
    finally:
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink(missing_ok=True)


def _validate_export_destination(store: ConfigStore, destination: Path) -> None:
    managed_paths = (
        store.database_path,
        Path(f"{store.database_path}-wal"),
        Path(f"{store.database_path}-shm"),
        store.config_path,
        store.env_path,
        store.home / ".instance.lock",
    )
    try:
        candidate = destination.absolute().resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ClickException(f"Cannot resolve export destination: {_error_detail(exc)}") from exc
    for managed in managed_paths:
        try:
            same_resolved_path = candidate == managed.absolute().resolve(strict=False)
        except (OSError, RuntimeError):
            same_resolved_path = False
        try:
            same_file = destination.samefile(managed)
        except OSError:
            same_file = False
        if same_resolved_path or same_file:
            raise ClickException(
                f"Refusing to overwrite managed SocketClaw file: {_terminal_text(str(destination))}"
            )


def _error_detail(error: Exception) -> str:
    return _terminal_text(str(error).strip() or type(error).__name__)


def _terminal_text(value: str) -> str:
    """Keep CLI text on one inert terminal line without recognizable credentials."""
    redacted = redact_secrets(value)
    safe: list[str] = []
    for character in redacted:
        codepoint = ord(character)
        if character in {"\r", "\n", "\t"}:
            safe.append(" ")
        elif (
            codepoint >= 0x20
            and not 0x7F <= codepoint <= 0x9F
            and unicodedata.category(character) != "Cf"
        ):
            safe.append(character)
    return redact_secrets("".join(safe))
