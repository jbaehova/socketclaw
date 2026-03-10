"""WebSocket client — for Gradio UI.

Connects to the server, subscribes to channels, and invokes a callback on message receipt.
Supports automatic reconnection.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Awaitable

import websockets
from websockets.asyncio.client import ClientConnection

from ..protocol.constants import CH_CONTROL, CH_MONITORING, MSG_CONTROL, MSG_HEARTBEAT
from ..protocol.frame import Frame, FrameError

logger = logging.getLogger(__name__)

MessageCallback = Callable[[Frame], Awaitable[None]]


class NetAgentClient:
    """WebSocket client.

    Args:
        uri: WebSocket server URI (e.g. ws://localhost:8765).
        on_message: Callback invoked on message receipt.
        channels: List of channels to subscribe to.
        reconnect_interval: Reconnection attempt interval (seconds).
        max_reconnect_attempts: Maximum reconnection attempts (0=unlimited).
    """

    def __init__(
        self,
        uri: str = "ws://localhost:8765",
        on_message: MessageCallback | None = None,
        channels: list[str] | None = None,
        reconnect_interval: float = 3.0,
        max_reconnect_attempts: int = 0,
    ) -> None:
        self.uri = uri
        self.on_message = on_message
        self.channels = channels or [CH_MONITORING]
        self.reconnect_interval = reconnect_interval
        self.max_reconnect_attempts = max_reconnect_attempts
        self._ws: ClientConnection | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        """Connect to the server and start the message receive loop."""
        self._running = True
        self._task = asyncio.create_task(self._connection_loop())

    async def disconnect(self) -> None:
        """Close the connection."""
        self._running = False
        if self._ws:
            await self._ws.close()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def send_control(self, action: str, **kwargs: Any) -> None:
        """Send a control message to the server."""
        if not self._ws:
            logger.warning("Not connected")
            return
        payload = {"action": action, **kwargs}
        frame = Frame.create(MSG_CONTROL, CH_CONTROL, payload)
        await self._ws.send(frame.encode())

    async def subscribe(self, channel: str) -> None:
        """Request channel subscription."""
        await self.send_control("subscribe", channel=channel)

    async def unsubscribe(self, channel: str) -> None:
        """Request channel unsubscription."""
        await self.send_control("unsubscribe", channel=channel)

    async def _connection_loop(self) -> None:
        """Connection/reconnection loop."""
        attempts = 0

        while self._running:
            try:
                async with websockets.connect(self.uri) as ws:
                    self._ws = ws
                    attempts = 0
                    logger.info("Connected to %s", self.uri)

                    # Request subscription to additional channels
                    for ch in self.channels:
                        if ch != CH_MONITORING:  # monitoring is auto-subscribed by server
                            await self.subscribe(ch)

                    await self._receive_loop(ws)

            except websockets.ConnectionClosed:
                logger.info("Connection closed")
            except (ConnectionRefusedError, OSError) as exc:
                logger.warning("Connection failed: %s", exc)
            finally:
                self._ws = None

            if not self._running:
                break

            attempts += 1
            if self.max_reconnect_attempts and attempts >= self.max_reconnect_attempts:
                logger.error("Max reconnect attempts reached")
                break

            logger.info("Reconnecting in %.1fs (attempt %d)...", self.reconnect_interval, attempts)
            await asyncio.sleep(self.reconnect_interval)

    async def _receive_loop(self, ws: ClientConnection) -> None:
        """Message receive loop."""
        async for raw in ws:
            try:
                frame = Frame.decode(raw)
            except FrameError as exc:
                logger.warning("Invalid frame received: %s", exc)
                continue

            # Auto-respond to heartbeat
            if frame.type == MSG_HEARTBEAT and frame.payload.get("ping"):
                pong = Frame.create(MSG_HEARTBEAT, frame.channel, {"pong": True})
                await ws.send(pong.encode())
                continue

            if self.on_message:
                try:
                    await self.on_message(frame)
                except Exception:
                    logger.exception("Message callback error")

    @property
    def is_connected(self) -> bool:
        return self._ws is not None and self._ws.state.name == "OPEN"
