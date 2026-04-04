"""NetAgent server run entrypoint.

Starts probes, connects the event queue, and runs the WebSocket server.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.graph import AgentRunner
from src.network.server import NetAgentServer
from src.probes.ping import PingProbe
from src.probes.port_scan import PortScanProbe
from src.probes.log_watcher import LogWatcherProbe
from src.storage.repository import Repository

logging.basicConfig(
    level=os.getenv("NETAGENT_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netagent")


async def main() -> None:
    host = os.getenv("NETAGENT_HOST", "0.0.0.0")
    port = int(os.getenv("NETAGENT_PORT", "8765"))
    targets_str = os.getenv("NETAGENT_PROBE_TARGETS", "8.8.8.8")
    targets = [t.strip() for t in targets_str.split(",") if t.strip()]
    ping_interval = float(os.getenv("NETAGENT_PING_INTERVAL", "5"))
    scan_interval = float(os.getenv("NETAGENT_SCAN_INTERVAL", "60"))
    db_path = os.getenv("NETAGENT_DB_PATH", "./netagent.db")

    # Initialize repository
    repo = Repository(f"sqlite+aiosqlite:///{db_path}")
    await repo.init_db()

    # Event queue
    event_queue: asyncio.Queue = asyncio.Queue()

    # Create probes
    probes = [
        PingProbe(targets=targets, queue=event_queue, interval=ping_interval),
        PortScanProbe(targets=targets, queue=event_queue, interval=scan_interval),
    ]

    # Watch syslog if available
    log_path = os.getenv("NETAGENT_LOG_PATH", "/var/log/system.log")
    if os.path.exists(log_path):
        probes.append(LogWatcherProbe(log_path=log_path, queue=event_queue))

    # Create agent
    window_size = int(os.getenv("NETAGENT_WINDOW_SIZE", "50"))
    agent = AgentRunner(window_size=window_size)

    async def agent_callback(event: dict) -> dict | None:
        """Forward event to agent and save result to DB."""
        try:
            result = await agent.process_event(event)
            # Save event + decision to DB
            saved_event = await repo.save_event(event)
            await repo.save_decision(
                event_id=saved_event.id,
                classification=result.get("classification", "normal"),
                analysis=result.get("analysis", ""),
                action=result.get("action", "log"),
                tool_results=result.get("tool_results"),
            )
            return result
        except Exception:
            logger.exception("Agent processing failed")
            # Save event even on agent failure
            await repo.save_event(event)
            return None

    # Create server
    server = NetAgentServer(
        host=host,
        port=port,
        event_queue=event_queue,
        agent_callback=agent_callback,
    )

    # Start probes
    for probe in probes:
        await probe.start()

    # Start server
    await server.start()

    logger.info("NetAgent running — press Ctrl+C to stop")
    logger.info("Monitoring targets: %s", targets)

    # Wait for shutdown signal
    stop = asyncio.Event()
    loop = asyncio.get_event_loop()

    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    await stop.wait()

    # Cleanup
    logger.info("Shutting down...")
    for probe in probes:
        await probe.stop()
    await server.stop()
    await repo.close()


if __name__ == "__main__":
    asyncio.run(main())
