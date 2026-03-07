"""asyncio WebSocket server.

Consumes events produced by probes, forwards them to the agent,
and pushes results to clients via the Multiplexer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import time
from typing import Any, Callable, Awaitable

import websockets
from websockets.asyncio.server import ServerConnection, Server

from ..protocol.constants import (
    CH_CONTROL,
    CH_MONITORING,
    MSG_ACK,
    MSG_CONTROL,
    MSG_EVENT,
    MSG_HEARTBEAT,
    PROTOCOL_VERSION,
)
from ..protocol.frame import Frame, FrameError
from .multiplexer import Multiplexer

logger = logging.getLogger(__name__)

# Agent callback type: event dict → agent result dict
AgentCallback = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]]


class NetAgentServer:
    """WebSocket-based network monitoring server.

    Args:
        host: Bind address.
        port: Bind port.
        event_queue: Queue for receiving events from probes.
        agent_callback: Callback to forward events to the agent (connected in Phase 2).
        heartbeat_interval: Heartbeat transmission interval (seconds).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8765,
        event_queue: asyncio.Queue[dict[str, Any]] | None = None,
        agent_callback: AgentCallback | None = None,
        heartbeat_interval: float = 30.0,
        max_queue_size: int = 1000,
        agent_timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.event_queue = event_queue or asyncio.Queue()
        self.agent_callback = agent_callback
        self.heartbeat_interval = heartbeat_interval
        self.max_queue_size = max_queue_size
        self.agent_timeout = agent_timeout
        self.multiplexer = Multiplexer()
        self._server: Server | None = None
        self._running = False
        self._tasks: list[asyncio.Task[Any]] = []

    async def start(self) -> None:
        """Start the server."""
        self._running = True
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
        )
        # Start event consumer task
        self._tasks.append(
            asyncio.create_task(self._consume_events(), name="event-consumer")
        )
        logger.info("NetAgent server started on ws://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Gracefully stop the server."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("NetAgent server stopped")

    async def _handle_connection(self, ws: ServerConnection) -> None:
        """Client connection handler."""
        remote = ws.remote_address
        logger.info("Client connected: %s", remote)

        # Subscribe to monitoring channel by default
        await self.multiplexer.subscribe(ws, CH_MONITORING)

        # Heartbeat task
        hb_task = asyncio.create_task(self._heartbeat_loop(ws))

        try:
            async for message in ws:
                await self._handle_message(ws, message)
        except websockets.ConnectionClosed:
            logger.info("Client disconnected: %s", remote)
        finally:
            hb_task.cancel()
            await self.multiplexer.unsubscribe_all(ws)

    async def _handle_message(self, ws: ServerConnection, raw: str | bytes) -> None:
        """Handle incoming messages."""
        try:
            frame = Frame.decode(raw)
        except FrameError as exc:
            logger.warning("Invalid frame: %s", exc)
            return

        if frame.type == MSG_HEARTBEAT:
            # Pong response
            pong = Frame.create(MSG_HEARTBEAT, frame.channel, {"pong": True})
            await ws.send(pong.encode())

        elif frame.type == MSG_CONTROL:
            await self._handle_control(ws, frame)

        # Send ACK
        ack = Frame.create(MSG_ACK, frame.channel, {"ack_seq": frame.seq})
        await ws.send(ack.encode())

    async def _handle_control(self, ws: ServerConnection, frame: Frame) -> None:
        """Handle control messages (subscribe/unsubscribe, etc.)."""
        action = frame.payload.get("action")

        if action == "subscribe":
            channel = frame.payload.get("channel", "")
            await self.multiplexer.subscribe(ws, channel)

        elif action == "unsubscribe":
            channel = frame.payload.get("channel", "")
            await self.multiplexer.unsubscribe(ws, channel)

    async def _consume_events(self) -> None:
        """Consume events from the event queue and broadcast to clients.

        Backpressure: if queue size exceeds max_queue_size, drop stale events.
        """
        while self._running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
            except (asyncio.TimeoutError, TimeoutError):
                continue

            # Backpressure — drop stale events when queue is overloaded
            if self.event_queue.qsize() > self.max_queue_size:
                dropped = 0
                while self.event_queue.qsize() > self.max_queue_size // 2:
                    try:
                        self.event_queue.get_nowait()
                        dropped += 1
                    except asyncio.QueueEmpty:
                        break
                if dropped:
                    logger.warning("Backpressure: dropped %d stale events", dropped)

            # Broadcast event to monitoring channel
            event_frame = Frame.create(MSG_EVENT, CH_MONITORING, event)
            await self.multiplexer.publish(event_frame)

            # Invoke agent callback if set
            if self.agent_callback:
                try:
                    asyncio.create_task(self._invoke_agent(event))
                except Exception:
                    logger.exception("Agent callback scheduling failed")

    async def _invoke_agent(self, event: dict[str, Any]) -> None:
        """Invoke the agent callback and broadcast the result.

        Sends a fallback result if timeout is exceeded.
        """
        if not self.agent_callback:
            return
        try:
            result = await asyncio.wait_for(
                self.agent_callback(event),
                timeout=self.agent_timeout,
            )
            if result:
                from ..protocol.constants import CH_AGENT, MSG_AGENT_RESULT
                result_frame = Frame.create(MSG_AGENT_RESULT, CH_AGENT, result)
                await self.multiplexer.publish(result_frame)
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Agent timeout (%.0fs) for event: %s", self.agent_timeout, event.get("type"))
            # Fallback: send default result on timeout
            from ..protocol.constants import CH_AGENT, MSG_AGENT_RESULT
            fallback = {
                "classification": "unknown",
                "action": "log",
                "analysis": "Agent timeout — event logged without analysis.",
                "timestamp": time.time(),
            }
            fallback_frame = Frame.create(MSG_AGENT_RESULT, CH_AGENT, fallback)
            await self.multiplexer.publish(fallback_frame)
        except Exception:
            logger.exception("Agent callback error")

    async def _heartbeat_loop(self, ws: ServerConnection) -> None:
        """Periodically send heartbeat frames."""
        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                hb = Frame.create(MSG_HEARTBEAT, CH_MONITORING, {"ping": True})
                await ws.send(hb.encode())
            except asyncio.CancelledError:
                break
            except Exception:
                break


async def run_server(
    host: str = "0.0.0.0",
    port: int = 8765,
    event_queue: asyncio.Queue[dict[str, Any]] | None = None,
    agent_callback: AgentCallback | None = None,
) -> None:
    """Run the server and handle SIGINT/SIGTERM."""
    server = NetAgentServer(
        host=host,
        port=port,
        event_queue=event_queue,
        agent_callback=agent_callback,
    )

    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    await server.start()
    await stop_event.wait()
    await server.stop()
