"""LogWatcherProbe — log file tail & pattern detection.

Tails a log file using async polling and extracts lines matching regex patterns as events.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .base import BaseProbe

logger = logging.getLogger(__name__)


@dataclass
class LogPattern:
    """Log matching pattern definition."""

    name: str
    pattern: str  # regex
    severity: str = "warning"  # normal | warning | critical
    _compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern)

    def match(self, line: str) -> re.Match[str] | None:
        return self._compiled.search(line)


DEFAULT_PATTERNS = [
    LogPattern("failed_login", r"(?i)failed\s+(password|login|auth)", severity="warning"),
    LogPattern("brute_force", r"(?i)(too many|repeated|multiple)\s+(failed|attempts)", severity="critical"),
    LogPattern("port_scan_detected", r"(?i)port\s*scan\s*(detected|attempt)", severity="critical"),
    LogPattern("connection_refused", r"(?i)connection\s+refused", severity="warning"),
    LogPattern("permission_denied", r"(?i)permission\s+denied", severity="warning"),
    LogPattern("segfault", r"(?i)segfault|segmentation\s+fault", severity="critical"),
]


class LogWatcherProbe(BaseProbe):
    """Log file monitoring probe.

    Args:
        log_path: Path to the log file to watch.
        queue: Event delivery queue.
        patterns: List of matching patterns (uses defaults if None).
        interval: Polling interval (seconds).
    """

    def __init__(
        self,
        log_path: str,
        queue: asyncio.Queue[dict[str, Any]],
        patterns: list[LogPattern] | None = None,
        interval: float = 1.0,
    ) -> None:
        super().__init__(name="log_watcher", queue=queue, interval=interval)
        self.log_path = log_path
        self.patterns = patterns or DEFAULT_PATTERNS
        self._offset: int = 0
        self._inode: int | None = None

    async def start(self) -> None:
        """Initialize offset to end of file before starting."""
        if os.path.exists(self.log_path):
            stat = os.stat(self.log_path)
            self._offset = stat.st_size
            self._inode = stat.st_ino
        await super().start()

    async def _collect(self) -> dict[str, Any] | None:
        if not os.path.exists(self.log_path):
            return None

        stat = os.stat(self.log_path)

        # Detect file rotation (inode change or size shrink)
        if self._inode is not None and (stat.st_ino != self._inode or stat.st_size < self._offset):
            logger.info("Log file rotated: %s", self.log_path)
            self._offset = 0
            self._inode = stat.st_ino

        if stat.st_size <= self._offset:
            return None

        # Read newly appended content
        loop = asyncio.get_event_loop()
        new_lines = await loop.run_in_executor(None, self._read_new_lines)

        matched_events: list[dict[str, Any]] = []
        for line in new_lines:
            for pattern in self.patterns:
                m = pattern.match(line)
                if m:
                    matched_events.append({
                        "pattern_name": pattern.name,
                        "severity": pattern.severity,
                        "matched_text": m.group(0),
                        "full_line": line.strip(),
                    })

        if not matched_events:
            return None

        return {
            "type": "log_match",
            "log_path": self.log_path,
            "matches": matched_events,
            "timestamp": time.time(),
        }

    def _read_new_lines(self) -> list[str]:
        """Read newly added lines from the file."""
        try:
            with open(self.log_path, "r", errors="replace") as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()
            return lines
        except OSError as exc:
            logger.debug("Failed to read log %s: %s", self.log_path, exc)
            return []
