"""Rotation-aware incremental security log watcher."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..domain import SecurityEvent

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
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


class LogProbe:
    def __init__(self, paths: list[Path]) -> None:
        self.paths = [Path(path) for path in paths]
        self._cursors: dict[Path, _Cursor] = {}
        self._missing_seen: set[Path] = set()

    async def poll(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for path in self.paths:
            if not path.exists() or not path.is_file():
                self._missing_seen.add(path)
                continue
            stat = path.stat()
            cursor = self._cursors.get(path)
            if cursor is None:
                if path not in self._missing_seen:
                    self._cursors[path] = _Cursor(stat.st_ino, stat.st_size)
                    continue
                offset = 0
                rotated = True
            else:
                rotated = cursor.inode != stat.st_ino or stat.st_size < cursor.offset
                offset = 0 if rotated else cursor.offset

            with path.open(encoding="utf-8", errors="replace") as stream:
                stream.seek(offset)
                for line in stream:
                    matched = _event_for_line(path, line.rstrip(), rotated)
                    if matched is not None:
                        events.append(matched)
                new_offset = stream.tell()
            self._cursors[path] = _Cursor(stat.st_ino, new_offset)
            self._missing_seen.discard(path)
        return events


def _event_for_line(
    path: Path,
    line: str,
    rotated: bool,
) -> SecurityEvent | None:
    for event_type, pattern, title in _PATTERNS:
        if not pattern.search(line):
            continue
        target_match = _IPV4.search(line)
        target = target_match.group(0) if target_match else None
        return SecurityEvent(
            source="log",
            event_type=event_type,
            title=title,
            summary=line[:1000],
            target=target,
            evidence={
                "path": str(path),
                "message": line,
                "rotated": rotated,
            },
        )
    return None
