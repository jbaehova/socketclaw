"""BaseProbe — abstract base class for all probes."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseProbe(ABC):
    """Network monitoring probe ABC.

    Subclasses implement `_collect` to provide the actual collection logic.
    `start()` runs the `_collect → produce_event` loop at `interval` intervals.
    """

    def __init__(
        self,
        name: str,
        queue: asyncio.Queue[dict[str, Any]],
        interval: float = 5.0,
    ) -> None:
        self.name = name
        self.queue = queue
        self.interval = interval
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def start(self) -> None:
        """Start the probe collection loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name=f"probe-{self.name}")
        logger.info("Probe [%s] started (interval=%.1fs)", self.name, self.interval)

    async def stop(self) -> None:
        """Stop the probe."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Probe [%s] stopped", self.name)

    async def produce_event(self, event: dict[str, Any]) -> None:
        """Put an event onto the queue."""
        event.setdefault("source", self.name)
        await self.queue.put(event)

    @abstractmethod
    async def _collect(self) -> dict[str, Any] | None:
        """One collection cycle. Returns an event dict, or None to skip."""
        ...

    async def _loop(self) -> None:
        """Internal loop that calls _collect at interval intervals."""
        while self._running:
            try:
                event = await self._collect()
                if event is not None:
                    await self.produce_event(event)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Probe [%s] collect error", self.name)
            await asyncio.sleep(self.interval)
