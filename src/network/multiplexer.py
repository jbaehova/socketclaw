"""Multiplexer — channel-based multiplexing over a single WebSocket connection.

Routes messages by channel over a single WebSocket connection.
Clients can subscribe/unsubscribe to channels of interest.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from websockets.asyncio.server import ServerConnection

from ..protocol.constants import ALL_CHANNELS
from ..protocol.frame import Frame

logger = logging.getLogger(__name__)


class Multiplexer:
    """Channel-based message routing multiplexer.

    Each WebSocket connection (client) can subscribe to one or more channels,
    and messages are delivered only to clients subscribed to that channel.
    """

    def __init__(self) -> None:
        # channel → set of websocket connections
        self._subscriptions: dict[str, set[ServerConnection]] = {
            ch: set() for ch in ALL_CHANNELS
        }
        self._lock = asyncio.Lock()

    async def subscribe(self, ws: ServerConnection, channel: str) -> bool:
        """Register a client subscription to a channel."""
        if channel not in ALL_CHANNELS:
            logger.warning("Unknown channel: %s", channel)
            return False
        async with self._lock:
            self._subscriptions[channel].add(ws)
        logger.debug("Client subscribed to channel: %s", channel)
        return True

    async def unsubscribe(self, ws: ServerConnection, channel: str) -> bool:
        """Remove a client subscription from a channel."""
        if channel not in ALL_CHANNELS:
            return False
        async with self._lock:
            self._subscriptions[channel].discard(ws)
        logger.debug("Client unsubscribed from channel: %s", channel)
        return True

    async def unsubscribe_all(self, ws: ServerConnection) -> None:
        """Remove a client from all channels (called on connection close)."""
        async with self._lock:
            for subs in self._subscriptions.values():
                subs.discard(ws)

    async def publish(self, frame: Frame) -> int:
        """Send a frame to all subscribers of the given channel.

        Returns:
            Number of clients successfully delivered to.
        """
        channel = frame.channel
        if channel not in self._subscriptions:
            return 0

        encoded = frame.encode()
        sent = 0

        async with self._lock:
            subscribers = list(self._subscriptions[channel])

        tasks = [self._send_to(ws, encoded) for ws in subscribers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for ws, result in zip(subscribers, results):
            if result is True:
                sent += 1
            elif isinstance(result, Exception):
                logger.debug("Failed to send to client: %s", result)
                await self.unsubscribe_all(ws)

        return sent

    @staticmethod
    async def _send_to(ws: ServerConnection, data: bytes) -> bool:
        """Send a message to a single client."""
        try:
            await ws.send(data)
            return True
        except Exception as exc:
            raise exc

    def get_subscriber_count(self, channel: str) -> int:
        """Return the number of subscribers for a channel."""
        return len(self._subscriptions.get(channel, set()))

    @property
    def total_connections(self) -> int:
        """Total number of unique connections."""
        all_ws: set[ServerConnection] = set()
        for subs in self._subscriptions.values():
            all_ws.update(subs)
        return len(all_ws)
