"""Read-only local source discovery. A candidate is never automatically monitored."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import platform
import shutil
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Listener:
    host: str
    port: int
    pid: int | None
    process: str | None
    executable: str | None
    exposure: str


@dataclass(frozen=True)
class SourceCandidate:
    path: str
    kind: str
    supported: bool
    readable: bool
    detail: str


@dataclass(frozen=True)
class DiscoveryReport:
    listeners: tuple[Listener, ...]
    sources: tuple[SourceCandidate, ...]
    limitations: tuple[str, ...]


def parse_listeners(output: str) -> tuple[Listener, ...]:
    """Parse lsof machine fields, including IPv6 brackets and wildcard binds."""
    pid = None
    process = None
    found: list[Listener] = []
    for line in output.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else None
            process = None
        elif line.startswith("c"):
            process = line[1:]
        elif line.startswith("n"):
            address, separator, port = line[1:].rpartition(":")
            if not separator or not port.isdigit():
                continue
            host = address.strip("[]")
            try:
                exposure = (
                    "loopback"
                    if ipaddress.ip_address(host).is_loopback
                    else "all_interfaces"
                    if ipaddress.ip_address(host).is_unspecified
                    else "interface"
                )
            except ValueError:
                exposure = "all_interfaces" if host == "*" else "unknown"
            executable = None
            if pid is not None:
                with suppress(OSError):
                    executable = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
            found.append(Listener(host, int(port), pid, process, executable, exposure))
    return tuple(found)


async def discover_sources() -> DiscoveryReport:
    limitations = ["A listening address does not prove Internet reachability."]
    listeners: tuple[Listener, ...] = ()
    executable = shutil.which("lsof")
    if executable:
        process = await asyncio.create_subprocess_exec(
            executable,
            "-nP",
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fpcn",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
            listeners = parse_listeners(stdout.decode(errors="replace"))
            if stderr or process.returncode not in {0, 1}:
                limitations.append(
                    "Listener discovery is partial: lsof reported inaccessible processes."
                )
        except (TimeoutError, asyncio.CancelledError):
            process.kill()
            await process.communicate()
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
            limitations.append("Listener discovery timed out.")
    else:
        limitations.append("lsof is unavailable; process and binding discovery is unsupported.")
    if platform.system() == "Darwin" and listeners:
        # comm contains the executable name/path, never the process arguments.
        pids = sorted({item.pid for item in listeners if item.pid is not None})[:128]
        ps = shutil.which("ps")
        if ps and pids:
            process = await asyncio.create_subprocess_exec(
                ps,
                "-ww",
                "-p",
                ",".join(str(pid) for pid in pids),
                "-o",
                "pid=,comm=",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                output, _ = await asyncio.wait_for(process.communicate(), 3)
                process_paths: dict[int, str] = {}
                for line in output.decode(errors="replace").splitlines():
                    fields = line.strip().split(None, 1)
                    if len(fields) == 2 and fields[0].isdigit() and fields[1].startswith("/"):
                        process_paths[int(fields[0])] = fields[1]
                listeners = tuple(
                    replace(item, executable=process_paths.get(item.pid or -1))
                    for item in listeners
                )
            except (TimeoutError, asyncio.CancelledError):
                process.kill()
                await process.communicate()
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    raise
                limitations.append(
                    "Executable-path discovery timed out; listener facts are retained."
                )
    if platform.system() == "Darwin":
        paths = ("/var/log/system.log", "/var/log/install.log")
        limitations.append(
            "macOS unified logging is separate and is not collected by the file log parser."
        )
        limitations.append("Process executable paths may require additional permissions on macOS.")
    else:
        paths = ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog")
        limitations.append(
            "journald is a separate source and is not collected by the file log parser."
        )
    sources = tuple(
        SourceCandidate(
            path,
            "file",
            True,
            Path(path).is_file() and os.access(path, os.R_OK),
            "Readable file candidate; parser coverage depends on actual records."
            if Path(path).is_file() and os.access(path, os.R_OK)
            else "Missing file or current user lacks read permission.",
        )
        for path in paths
    )
    return DiscoveryReport(listeners, sources, tuple(limitations))
