"""Rotation-aware incremental security log watcher."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from ..collection import CheckpointChange, IngestGap, LogCheckpointState, ProbeBatch
from ..domain import EventSource, ObservationOutcome, SecurityEvent, utc_now
from ..health import ProbeHealthSignal
from ..storage import Repository
from .log_parser import PARSER_VERSION, parse_log_line

_MAX_LINE_BYTES = 64 * 1024
_MAX_EVIDENCE_CHARS = 4000
_MAX_CONTEXT_BYTES = 1024
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
            r"(?:failed password|failed publickey|authentication failure|"
            r"invalid user|login failed)",
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
        re.compile(r"(?:firewall.*den(?:y|ied)|\bDROP\b|\bREJECT\b|\[UFW BLOCK\])", re.I),
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
    device: int = 0
    generation: str = field(default_factory=lambda: uuid4().hex)
    head: bytes = b""
    head_size: int = 0


@dataclass(frozen=True, slots=True)
class LogPreview:
    path: Path
    sampled_at: datetime
    file_size: int
    bytes_read: int
    complete_lines: int
    matches: tuple[SecurityEvent, ...]
    limited: bool


async def preview_log(path: Path) -> LogPreview:
    """Read a bounded tail without changing any collector, cursor, or database."""
    return await asyncio.to_thread(_preview_log, path.expanduser().absolute())


def _preview_log(path: Path) -> LogPreview:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError("Log preview requires a regular file, not a link or device")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise OSError("Log source changed while opening its preview")
        start = max(0, opened.st_size - _MAX_LINE_BYTES)
        stream.seek(start)
        data = stream.read(_MAX_LINE_BYTES)
    read_count = len(data)
    limited = start > 0 or (not data.endswith(b"\n") and bool(data))
    if start:
        # The first sampled fragment may begin in the middle of a line.
        _, boundary, data = data.partition(b"\n")
        if not boundary:
            data = b""
    lines = data.split(b"\n")[:-1]
    matches: list[SecurityEvent] = []
    for raw in lines[:1000]:
        event = _event_for_line(path, raw.decode("utf-8", errors="replace").rstrip(), False)
        if event is not None:
            matches.append(event)
            if len(matches) == 20:
                limited = True
                break
    return LogPreview(
        path=path,
        sampled_at=utc_now(),
        file_size=opened.st_size,
        bytes_read=read_count,
        complete_lines=min(len(lines), 1000),
        matches=tuple(matches),
        limited=limited or len(lines) > 1000,
    )


class LogProbe:
    def __init__(self, paths: list[Path], *, repository: Repository | None = None) -> None:
        self.paths = list(dict.fromkeys(Path(path).absolute() for path in paths))
        self.repository = repository
        self._cursors: dict[Path, _Cursor] = {}
        self._missing_seen: set[Path] = set()
        self._errors: dict[Path, str] = {}
        self._async_poll_lock = asyncio.Lock()
        self._poll_lock = threading.Lock()
        self._pending_events: list[SecurityEvent] = []
        self._next_path_index = 0
        self._read_states: dict[Path, LogCheckpointState] = {}
        self._gaps: list[IngestGap] = []

    async def collect(self) -> ProbeBatch | list[SecurityEvent]:
        if self.repository is None:
            return await self.poll()
        async with self._async_poll_lock:
            checkpoints = {
                path: await self.repository.load_checkpoint(_probe_id(path)) for path in self.paths
            }
            worker = asyncio.create_task(asyncio.to_thread(self._prepare_batch, checkpoints))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                await worker
                raise

    def _prepare_batch(self, checkpoints: dict[Path, CheckpointChange]) -> ProbeBatch:
        with self._poll_lock:
            previous = self._cursors, self._missing_seen, self._errors
            previous_states, previous_gaps = self._read_states, self._gaps
            self._cursors, self._missing_seen, self._errors = {}, set(), {}
            self._read_states, self._gaps = {}, []
            try:
                for path, checkpoint in checkpoints.items():
                    state = LogCheckpointState.model_validate(checkpoint.state)
                    self._read_states[path] = state
                    if state.inode is not None:
                        self._cursors[path] = _Cursor(
                            state.inode,
                            state.offset,
                            bytes.fromhex(state.tail_hash),
                            state.rotation_pending,
                            state.continuing_line,
                            state.device,
                            state.generation,
                            bytes.fromhex(state.head_hash),
                            state.head_size,
                        )
                    if state.missing:
                        self._missing_seen.add(path)
                    if state.error is not None:
                        self._errors[path] = state.error
                observations = self._poll_sync()
                candidates: list[CheckpointChange] = []
                for path, checkpoint in checkpoints.items():
                    cursor = self._cursors.get(path)
                    state = self._read_states[path].model_copy(
                        update={
                            "parser_version": PARSER_VERSION,
                            "inode": cursor.inode if cursor else None,
                            "device": cursor.device if cursor else 0,
                            "offset": cursor.offset if cursor else 0,
                            "generation": cursor.generation if cursor else "",
                            "head_hash": cursor.head.hex() if cursor else "",
                            "head_size": cursor.head_size if cursor else 0,
                            "tail_hash": cursor.tail.hex() if cursor else "",
                            "rotation_pending": cursor.rotation_pending if cursor else False,
                            "continuing_line": cursor.continuing_line if cursor else False,
                            "missing": path in self._missing_seen,
                            "error": self._errors.get(path),
                        }
                    )
                    if state.model_dump(mode="json") != checkpoint.state:
                        candidates.append(
                            checkpoint.model_copy(update={"state": state.model_dump(mode="json")})
                        )
                return ProbeBatch(
                    observations=tuple(observations),
                    checkpoints=tuple(candidates),
                    gaps=tuple(self._gaps),
                    health=tuple(self._health_signal(path) for path in checkpoints),
                )
            finally:
                # A candidate never advances the collector's committed in-memory state.
                self._cursors, self._missing_seen, self._errors = previous
                self._read_states, self._gaps = previous_states, previous_gaps

    def _health_signal(self, path: Path) -> ProbeHealthSignal:
        state = self._read_states[path]
        if path in self._missing_seen:
            error, detail = "missing_source", f"Missing log: {path}"
        elif path in self._errors:
            error, detail = "read_error", self._errors[path]
        elif state.last_read_at is None:
            error, detail = "not_read", f"Waiting to read log: {path}"
        elif state.last_lines_read and state.last_unparsed_count == state.last_lines_read:
            error, detail = (
                "unsupported_format",
                (
                    f"Read {state.last_lines_read} lines, but none used a supported format. "
                    "Keyword matches and bounded surrounding context may be retained."
                ),
            )
        elif state.last_partial_count or state.last_unparsed_count:
            error, detail = (
                "partial_format",
                (
                    f"Read {state.last_lines_read} lines: {state.last_partial_count} partial, "
                    f"{state.last_unparsed_count} unsupported. Missing fields remain unknown."
                ),
            )
        else:
            error, detail = None, None
        return ProbeHealthSignal(
            probe_id=_probe_id(path),
            state="degraded" if error else "healthy",
            error_kind=error,
            detail=detail[:2000] if detail else None,
        )

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
        normalized = list(dict.fromkeys(Path(path).absolute() for path in paths))
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
                        line_budget=min(
                            _MAX_POLL_LINES - consumed_lines, _MAX_POLL_LINES - len(events)
                        ),
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
            if (
                consumed_bytes >= _MAX_POLL_BYTES
                or consumed_lines >= _MAX_POLL_LINES
                or len(events) >= _MAX_POLL_LINES
            ):
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
        recover_rotation: bool = True,
    ) -> tuple[list[SecurityEvent], int, int]:
        cursor = self._cursors.get(path)
        was_missing = path in self._missing_seen
        if cursor is None and not was_missing:
            offset = opened_stat.st_size
            self._cursors[path] = _Cursor(
                opened_stat.st_ino,
                offset,
                _tail_at(stream, offset),
                device=opened_stat.st_dev,
                head=_head_at(stream, min(_TAIL_BYTES, opened_stat.st_size)),
                head_size=min(_TAIL_BYTES, opened_stat.st_size),
            )
            self._errors.pop(path, None)
            self._record_progress(path, opened_stat.st_size, offset, "tail", [], 0)
            return [], 0, 0

        rotated = (
            cursor is None
            or cursor.inode != opened_stat.st_ino
            or cursor.device != opened_stat.st_dev
            or opened_stat.st_size < cursor.offset
        )
        if cursor is not None and not rotated and cursor.tail:
            rotated = _tail_at(stream, cursor.offset) != cursor.tail

        if cursor is not None and not rotated and cursor.head:
            rotated = _head_at(stream, cursor.head_size) != cursor.head
        recovered_events: list[SecurityEvent] = []
        recovered_bytes = recovered_lines = 0
        if rotated and cursor is not None and recover_rotation:
            recovered = self._recover_rotated_file(path, cursor, byte_budget, line_budget)
            if recovered is None:
                self._record_gap(path, cursor, "rotated_source_unavailable")
            else:
                recovered_events, recovered_bytes, recovered_lines, complete = recovered
                if not complete:
                    self._read_states[path] = self._read_states[path].model_copy(
                        update={"read_policy": "rotation"}
                    )
                    return recovered_events, recovered_bytes, recovered_lines
                byte_budget -= recovered_bytes
                line_budget -= max(recovered_lines, len(recovered_events))
        generation = uuid4().hex if rotated or cursor is None else cursor.generation
        head = (
            _head_at(stream, min(_TAIL_BYTES, opened_stat.st_size))
            if rotated or cursor is None
            else cursor.head
        )
        offset = 0 if rotated or cursor is None else cursor.offset
        rotation_pending = rotated or (cursor.rotation_pending if cursor is not None else False)
        continuing_line = False if rotated or cursor is None else cursor.continuing_line
        stream.seek(offset)
        committed_offset = offset
        events: list[SecurityEvent] = []
        processed_complete_line = False
        consumed_bytes = 0
        consumed_lines = 0
        truncated_lines = 0
        unparsed_count = partial_count = 0
        context_state = self._read_states.get(path, LogCheckpointState())
        context_before = [
            SecurityEvent.model_validate(item) for item in context_state.context_before
        ]
        context_after = context_state.context_after_remaining
        context_anchor = context_state.context_anchor
        context_limit = min(3, max(0, _MAX_POLL_LINES - 1))
        context_before = context_before[-context_limit:] if context_limit else []
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
            truncated_lines += int(truncated)
            committed_offset = stream.tell()
            processed_complete_line = complete
            continuing_line = not complete
            consumed_lines += 1
            line_bytes = chunk[:_MAX_LINE_BYTES]
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            matched = _event_for_line(path, line, rotation_pending, truncated)
            if len(events) + (len(context_before) if matched is not None else 0) + 1 > line_budget:
                stream.seek(start)
                committed_offset = start
                continuing_line = False
                consumed_lines -= 1
                truncated_lines -= int(truncated)
                break
            raw = matched or _event_for_line(path, line, rotation_pending, truncated, context=True)
            assert raw is not None
            quality = raw.evidence.get("parse_quality")
            unparsed_count += int(quality == "unparsed")
            partial_count += int(quality == "partial")
            identity = (
                f"{_probe_id(path)}:{opened_stat.st_dev}:{opened_stat.st_ino}:"
                f"{generation}:{hashlib.sha256(head).hexdigest()}:{start}:{committed_offset}:{PARSER_VERSION}"
            )
            raw = raw.model_copy(
                update={
                    "source_key": hashlib.sha256(identity.encode()).hexdigest(),
                    "outcome": ObservationOutcome.OK
                    if quality == "structured"
                    else ObservationOutcome.PARTIAL,
                    "evidence": {
                        **raw.evidence,
                        "byte_start": start,
                        "byte_end": committed_offset,
                        "parser_version": PARSER_VERSION,
                    },
                }
            )
            if matched is not None:
                context_anchor = str(raw.id)
                events.extend(
                    item.model_copy(
                        update={
                            "evidence": {
                                **item.evidence,
                                "context_for": context_anchor,
                                "context_position": "before",
                            }
                        }
                    )
                    for item in context_before
                )
                context_before = []
                events.append(raw)
                context_after = 3
            elif context_after > 0:
                events.append(
                    raw.model_copy(
                        update={
                            "evidence": {
                                **raw.evidence,
                                "context_for": context_anchor,
                                "context_position": "after",
                            }
                        }
                    )
                )
                context_after -= 1
            else:
                context_before = [*context_before, raw][-context_limit:] if context_limit else []

        self._read_states[path] = context_state.model_copy(
            update={
                "context_before": [item.model_dump(mode="json") for item in context_before],
                "context_after_remaining": context_after,
                "context_anchor": context_anchor,
                "last_lines_read": consumed_lines or context_state.last_lines_read,
                "last_unparsed_count": unparsed_count
                if consumed_lines
                else context_state.last_unparsed_count,
                "last_partial_count": partial_count
                if consumed_lines
                else context_state.last_partial_count,
            }
        )

        self._cursors[path] = _Cursor(
            opened_stat.st_ino,
            committed_offset,
            _tail_at(stream, committed_offset),
            rotation_pending and (continuing_line or not processed_complete_line),
            continuing_line,
            opened_stat.st_dev,
            generation,
            head,
            min(_TAIL_BYTES, opened_stat.st_size)
            if rotated or cursor is None
            else cursor.head_size,
        )
        self._missing_seen.discard(path)
        self._errors.pop(path, None)
        self._record_progress(
            path,
            opened_stat.st_size,
            committed_offset,
            "rotation" if rotated else "resume",
            recovered_events + events,
            truncated_lines,
        )
        return (
            recovered_events + events,
            recovered_bytes + consumed_bytes,
            recovered_lines + consumed_lines,
        )

    def _record_progress(
        self,
        path: Path,
        size: int,
        offset: int,
        policy: str,
        events: list[SecurityEvent],
        truncated: int,
    ) -> None:
        previous = self._read_states.get(path, LogCheckpointState())
        self._read_states[path] = previous.model_copy(
            update={
                "sampled_size": size,
                "backlog_bytes": max(0, size - offset),
                "read_policy": policy,
                "last_read_at": utc_now(),
                "last_match_count": len(events),
                "truncated_lines": previous.truncated_lines + truncated,
            }
        )

    def _record_gap(self, path: Path, cursor: _Cursor, reason: str) -> None:
        gap = IngestGap.model_validate(
            {
                "probe_id": _probe_id(path),
                "generation": cursor.generation,
                "from_offset": cursor.offset,
                "reason": reason,
            }
        )
        self._gaps.append(gap)
        state = self._read_states.get(path, LogCheckpointState())
        self._read_states[path] = state.model_copy(update={"gap_count": state.gap_count + 1})

    def _recover_rotated_file(
        self,
        path: Path,
        cursor: _Cursor,
        byte_budget: int,
        line_budget: int,
    ) -> tuple[list[SecurityEvent], int, int, bool] | None:
        """Follow a renamed sibling only after checking its file identity and hashes."""
        try:
            with os.scandir(path.parent) as entries:
                for index, entry in enumerate(entries):
                    if index >= 256:
                        break
                    if entry.name == path.name or not entry.name.startswith(path.name + "."):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (
                        cursor.device,
                        cursor.inode,
                    ):
                        continue
                    flags = (
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                    )
                    with os.fdopen(os.open(entry.path, flags), "rb") as previous:
                        info = os.fstat(previous.fileno())
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or (info.st_dev, info.st_ino) != (cursor.device, cursor.inode)
                            or info.st_size < cursor.offset
                        ):
                            continue
                        if _tail_at(previous, cursor.offset) != cursor.tail or (
                            _head_at(previous, cursor.head_size) != cursor.head
                        ):
                            continue
                        self._missing_seen.discard(path)
                        events, consumed, lines = self._read_open_file(
                            path,
                            previous,
                            info,
                            byte_budget=byte_budget,
                            line_budget=line_budget,
                            recover_rotation=False,
                        )
                        resumed = self._cursors[path]
                        complete = resumed.offset >= info.st_size
                        if (
                            not complete
                            and resumed.offset == cursor.offset
                            and info.st_size - resumed.offset <= _MAX_LINE_BYTES
                            and byte_budget >= _MAX_LINE_BYTES + 1
                            and line_budget > 0
                        ):
                            # A retired file cannot complete a trailing partial line.
                            self._record_gap(path, resumed, "incomplete_rotated_line")
                            complete = True
                        return events, consumed, lines, complete
        except OSError:
            return None
        return None


def _event_for_line(
    path: Path,
    line: str,
    rotated: bool,
    truncated: bool = False,
    *,
    context: bool = False,
) -> SecurityEvent | None:
    parsed = parse_log_line(line)
    actions = {
        "authentication_failure": ("log.auth_failure", "Authentication failure"),
        "authentication_success": ("log.auth_success", "Authentication succeeded"),
        "session_opened": ("log.session_opened", "Session opened"),
        "session_closed": ("log.session_closed", "Session closed"),
        "sudo_execution": ("log.sudo_execution", "Approved sudo execution"),
        "account_change": ("log.account_change", "Account changed"),
        "malware_detected": ("log.malware_indicator", "Security tool reported a detection"),
        "scan_clean": ("log.scan_clean", "Security tool reported a clean scan"),
        "deny": ("log.firewall_denial", "Firewall denial"),
    }
    selected = actions.get(parsed.action or "")
    if selected is None:
        selected = next(
            ((kind, title) for kind, pattern, title in _PATTERNS if pattern.search(line)), None
        )
        if selected is None:
            if not context:
                return None
            selected = ("log.context", "Surrounding log context")
        if selected[0] == "log.malware_indicator":
            selected = ("log.unverified_indicator", "Unverified security keyword")
        elif selected[0] == "log.privilege_escalation":
            selected = ("log.unverified_indicator", "Unverified privileged activity")
    if truncated and parsed.parse_quality == "structured":
        parsed = parsed.model_copy(update={"parse_quality": "partial"})
    message = line[:_MAX_EVIDENCE_CHARS]
    raw_bytes = line.encode("utf-8")
    is_context = selected[0] == "log.context"
    context_truncated = is_context and len(raw_bytes) > _MAX_CONTEXT_BYTES
    if is_context:
        # Keep complete Unicode code points, and bound durable surrounding text
        # independently of the full evidence retained for supported source facts.
        message = raw_bytes[:_MAX_CONTEXT_BYTES].decode("utf-8", errors="ignore")
    # Source-file identity is an explicit fallback, never an inferred victim IP.
    asset = parsed.asset or "log:" + hashlib.sha256(str(path.absolute()).encode()).hexdigest()
    return SecurityEvent(
        source=EventSource.LOG,
        event_type=selected[0],
        title=selected[1],
        summary=message[:1000] or "Empty log line",
        target=asset[:253],
        source_at=parsed.source_at,
        evidence={
            **parsed.model_dump(mode="json", exclude={"source_at"}),
            "asset": asset,
            "actor_ip": parsed.source_ip,
            "path": str(path),
            "message": message,
            "rotated": rotated,
            "truncated": truncated or len(line) > _MAX_EVIDENCE_CHARS or context_truncated,
            **(
                {"original_byte_length": len(raw_bytes), "context_truncated": context_truncated}
                if is_context
                else {}
            ),
        },
    )


def _probe_id(path: Path) -> str:
    return "log:" + hashlib.sha256(str(path.absolute()).encode()).hexdigest()


def _head_at(stream: BinaryIO, size: int) -> bytes:
    position = stream.tell()
    stream.seek(0)
    head = stream.read(size)
    stream.seek(position)
    return hashlib.sha256(head).digest()


def _tail_at(stream: BinaryIO, offset: int) -> bytes:
    size = min(_TAIL_BYTES, offset)
    stream.seek(offset - size)
    tail = stream.read(size)
    stream.seek(offset)
    return hashlib.sha256(tail).digest()


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
