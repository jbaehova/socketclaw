"""Rotation-aware incremental security log watcher."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ..domain import EventSource, SecurityEvent

_ADDRESS_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]*:[0-9A-Fa-f:.]+|(?:\d{1,3}\.){3}\d{1,3})"
    r"(?![0-9A-Fa-f:.])"
)
_MAX_LINE_BYTES = 64 * 1024
_MAX_EVIDENCE_CHARS = 4000
_MAX_POLL_BYTES = 1024 * 1024
_MAX_POLL_LINES = 1000
_MAX_POLL_PATHS = 256
_TAIL_BYTES = 128
_PATTERNS = (
    (
        "log.malware_indicator",
        re.compile(r"\b(?:malware|ransomware|trojan|rootkit|cryptominer)\b", re.I),
        "Malware indicator in log",
    ),
    (
        "log.auth_failure",
        re.compile(
            r"(?:failed password|authentication failure|invalid user|login failed)",
            re.I,
        ),
        "Authentication failure in log",
    ),
    (
        "log.privilege_escalation",
        re.compile(r"(?:privilege escalation|sudo:)", re.I),
        "Privilege escalation in log",
    ),
    (
        "log.firewall_denial",
        re.compile(r"(?:firewall.*den(?:y|ied)|\bDROP\b|\bREJECT\b)", re.I),
        "Firewall denial in log",
    ),
)


@dataclass(frozen=True, slots=True)
class _Cursor:
    inode: int
    offset: int
    tail: bytes = b""
    rotation_pending: bool = False
    continuing_line: bool = False


class LogProbe:
    def __init__(self, paths: list[Path]) -> None:
        self.paths = list(dict.fromkeys(Path(path) for path in paths))
        self._cursors: dict[Path, _Cursor] = {}
        self._missing_seen: set[Path] = set()
        self._errors: dict[Path, str] = {}
        self._async_poll_lock = asyncio.Lock()
        self._poll_lock = threading.Lock()
        self._pending_events: list[SecurityEvent] = []
        self._next_path_index = 0

    async def poll(self) -> list[SecurityEvent]:
        async with self._async_poll_lock:
            worker = asyncio.create_task(asyncio.to_thread(self._poll_serialized))
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                # Once started, a worker thread cannot be cancelled. Let it finish
                # buffering events so a replacement job can deliver them later.
                await worker
                raise
            with self._poll_lock:
                events = self._pending_events
                self._pending_events = []
            return events

    async def reconfigure(self, paths: list[Path]) -> None:
        """Replace watched paths while retaining cursor state for intersections."""
        normalized = list(dict.fromkeys(Path(path) for path in paths))
        async with self._async_poll_lock:
            await asyncio.to_thread(self._reconfigure_serialized, normalized)

    def _reconfigure_serialized(self, paths: list[Path]) -> None:
        with self._poll_lock:
            retained = set(paths)
            self.paths = paths
            self._cursors = {
                path: cursor for path, cursor in self._cursors.items() if path in retained
            }
            self._missing_seen.intersection_update(retained)
            self._errors = {path: error for path, error in self._errors.items() if path in retained}
            self._next_path_index = self._next_path_index % len(self.paths) if self.paths else 0

    def _poll_serialized(self) -> None:
        with self._poll_lock:
            self._pending_events.extend(self._poll_sync())

    def _poll_sync(self) -> list[SecurityEvent]:
        if not self.paths:
            return []
        events: list[SecurityEvent] = []
        consumed_bytes = 0
        consumed_lines = 0
        path_count = min(len(self.paths), _MAX_POLL_PATHS)
        start_index = self._next_path_index % len(self.paths)
        for step in range(path_count):
            path_index = (start_index + step) % len(self.paths)
            path = self.paths[path_index]
            self._next_path_index = (path_index + 1) % len(self.paths)
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_NONBLOCK", 0)
                descriptor = os.open(path, flags)
                try:
                    stream = os.fdopen(descriptor, "rb")
                except BaseException:
                    os.close(descriptor)
                    raise
                with stream:
                    opened_stat = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened_stat.st_mode):
                        raise OSError("path is not a regular file")
                    path_events, path_bytes, path_lines = self._read_open_file(
                        path,
                        stream,
                        opened_stat,
                        byte_budget=_MAX_POLL_BYTES - consumed_bytes,
                        line_budget=_MAX_POLL_LINES - consumed_lines,
                    )
                    events.extend(path_events)
                    consumed_bytes += path_bytes
                    consumed_lines += path_lines
            except (FileNotFoundError, IsADirectoryError):
                self._missing_seen.add(path)
                self._errors.pop(path, None)
                continue
            except OSError as exc:
                error = _error_text(exc)
                if self._errors.get(path) != error:
                    events.append(_error_event(path, error))
                    self._errors[path] = error
            if consumed_bytes >= _MAX_POLL_BYTES or consumed_lines >= _MAX_POLL_LINES:
                break
        return events

    def _read_open_file(
        self,
        path: Path,
        stream: BinaryIO,
        opened_stat: os.stat_result,
        *,
        byte_budget: int,
        line_budget: int,
    ) -> tuple[list[SecurityEvent], int, int]:
        cursor = self._cursors.get(path)
        was_missing = path in self._missing_seen
        if cursor is None and not was_missing:
            offset = opened_stat.st_size
            self._cursors[path] = _Cursor(
                opened_stat.st_ino,
                offset,
                _tail_at(stream, offset),
            )
            self._errors.pop(path, None)
            return [], 0, 0

        rotated = (
            was_missing
            or cursor is None
            or cursor.inode != opened_stat.st_ino
            or opened_stat.st_size < cursor.offset
        )
        if cursor is not None and not rotated and cursor.tail:
            rotated = _tail_at(stream, cursor.offset) != cursor.tail

        offset = 0 if rotated or cursor is None else cursor.offset
        rotation_pending = rotated or (cursor.rotation_pending if cursor is not None else False)
        continuing_line = False if rotated or cursor is None else cursor.continuing_line
        stream.seek(offset)
        committed_offset = offset
        events: list[SecurityEvent] = []
        processed_complete_line = False
        consumed_bytes = 0
        consumed_lines = 0
        while consumed_bytes < byte_budget and consumed_lines < line_budget:
            remaining_bytes = byte_budget - consumed_bytes
            if continuing_line:
                chunk = stream.readline(remaining_bytes)
                consumed_bytes += len(chunk)
                committed_offset = stream.tell()
                if not chunk or not chunk.endswith(b"\n"):
                    break
                continuing_line = False
                processed_complete_line = True
                continue

            if remaining_bytes < _MAX_LINE_BYTES + 1:
                break
            start = stream.tell()
            chunk = stream.readline(min(_MAX_LINE_BYTES + 1, remaining_bytes))
            if not chunk:
                break
            consumed_bytes += len(chunk)
            complete = chunk.endswith(b"\n")
            at_eof = stream.tell() >= opened_stat.st_size
            if not complete and at_eof and len(chunk) <= _MAX_LINE_BYTES:
                stream.seek(start)
                break
            truncated = not complete or len(chunk) > _MAX_LINE_BYTES
            committed_offset = stream.tell()
            processed_complete_line = complete
            continuing_line = not complete
            consumed_lines += 1
            line_bytes = chunk[:_MAX_LINE_BYTES]
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            matched = _event_for_line(path, line, rotation_pending, truncated)
            if matched is not None:
                events.append(matched)

        self._cursors[path] = _Cursor(
            opened_stat.st_ino,
            committed_offset,
            _tail_at(stream, committed_offset),
            rotation_pending and (continuing_line or not processed_complete_line),
            continuing_line,
        )
        self._missing_seen.discard(path)
        self._errors.pop(path, None)
        return events, consumed_bytes, consumed_lines


def _event_for_line(
    path: Path,
    line: str,
    rotated: bool,
    truncated: bool = False,
) -> SecurityEvent | None:
    for event_type, pattern, title in _PATTERNS:
        if not pattern.search(line):
            continue
        target = _address_from_line(line)
        message = line[:_MAX_EVIDENCE_CHARS]
        return SecurityEvent(
            source=EventSource.LOG,
            event_type=event_type,
            title=title,
            summary=message[:1000],
            target=target,
            evidence={
                "path": str(path),
                "message": message,
                "rotated": rotated,
                "truncated": truncated or len(line) > _MAX_EVIDENCE_CHARS,
            },
        )
    return None


def _tail_at(stream: BinaryIO, offset: int) -> bytes:
    size = min(_TAIL_BYTES, offset)
    stream.seek(offset - size)
    tail = stream.read(size)
    stream.seek(offset)
    return tail


def _address_from_line(line: str) -> str | None:
    for match in _ADDRESS_CANDIDATE.finditer(line):
        try:
            return str(ipaddress.ip_address(match.group(0)))
        except ValueError:
            continue
    return None


def _error_event(path: Path, error: str) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.SYSTEM,
        event_type="system.log_probe_error",
        title=f"Cannot read log {path.name}"[:200],
        summary=error,
        evidence={"path": str(path), "error": error},
    )


def _error_text(exc: OSError) -> str:
    return (str(exc).strip() or type(exc).__name__)[:2000]
