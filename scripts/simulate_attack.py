"""Virtual attack scenario simulator.

Connects directly to the WebSocket server event queue or runs standalone
to inject simulated events into the server's event queue.

Scenarios:
  1. port_flood — many ports opened simultaneously in a short time
  2. suspicious_ip — access from known malicious IP ranges
  3. brute_force — repeated failed login pattern
  4. gradual_probe — slow reconnaissance activity
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import sys
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.protocol.constants import CH_MONITORING, MSG_EVENT
from src.protocol.frame import Frame

logging.basicConfig(
    level=os.getenv("NETAGENT_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("simulator")


# ── Scenario definitions ──────────────────────────────────────────────────


async def scenario_port_flood(queue: asyncio.Queue[dict[str, Any]], target: str = "192.168.1.100") -> None:
    """Simulate an event where many ports open in a short time.

    Starts with a small number of normal ports open, then suddenly many ports open at once.
    """
    logger.info("[port_flood] Starting scenario for %s", target)

    # Phase 1: Normal state
    normal_event = {
        "type": "port_scan_result",
        "source": "port_scan",
        "timestamp": time.time(),
        "results": [{
            "host": target,
            "open_ports": [22, 80, 443],
            "newly_opened": [],
            "newly_closed": [],
            "total_scanned": 20,
            "severity": "normal",
        }],
    }
    await queue.put(normal_event)
    logger.info("[port_flood] Normal state sent")
    await asyncio.sleep(2)

    # Phase 2: Many ports suddenly opened
    flood_ports = [21, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 8080, 27017]
    flood_event = {
        "type": "port_scan_result",
        "source": "port_scan",
        "timestamp": time.time(),
        "results": [{
            "host": target,
            "open_ports": [22, 80, 443] + flood_ports,
            "newly_opened": flood_ports,
            "newly_closed": [],
            "total_scanned": 20,
            "severity": "critical",
        }],
    }
    await queue.put(flood_event)
    logger.info("[port_flood] FLOOD! %d new ports opened", len(flood_ports))


async def scenario_suspicious_ip(queue: asyncio.Queue[dict[str, Any]]) -> None:
    """Simulate access from known malicious IP ranges.

    Consecutive access attempts from suspicious IPs from outside.
    """
    logger.info("[suspicious_ip] Starting scenario")

    suspicious_ips = [
        "185.220.101.42",   # Tor exit node range
        "45.155.205.233",   # Known malicious
        "194.26.192.77",    # Botnet C2
    ]

    for ip in suspicious_ips:
        event = {
            "type": "port_scan_result",
            "source": "port_scan",
            "timestamp": time.time(),
            "results": [{
                "host": ip,
                "open_ports": [22, 80, 443, 4444, 8888],
                "newly_opened": [4444, 8888],
                "newly_closed": [],
                "total_scanned": 20,
                "severity": "warning",
            }],
        }
        await queue.put(event)
        logger.info("[suspicious_ip] Suspicious activity from %s", ip)
        await asyncio.sleep(1)


async def scenario_brute_force(queue: asyncio.Queue[dict[str, Any]], target_log: str = "/tmp/netagent_sim.log") -> None:
    """Simulate a repeated failed login pattern in logs.

    Writes patterns to an actual log file so LogWatcherProbe can detect them.
    """
    logger.info("[brute_force] Starting scenario → %s", target_log)

    # Inject events directly into the queue
    attacker_ip = "10.0.0.99"

    # Gradual login failures
    for i in range(1, 8):
        event = {
            "type": "log_match",
            "source": "log_watcher",
            "log_path": target_log,
            "timestamp": time.time(),
            "matches": [{
                "pattern_name": "failed_login" if i < 5 else "brute_force",
                "severity": "warning" if i < 5 else "critical",
                "matched_text": f"Failed password for root from {attacker_ip}",
                "full_line": f"sshd[{12345 + i}]: Failed password for root from {attacker_ip} port {50000 + i} ssh2",
            }],
        }

        # Escalate to multiple failures after 5 attempts
        if i >= 5:
            event["matches"].append({
                "pattern_name": "brute_force",
                "severity": "critical",
                "matched_text": f"too many failed attempts from {attacker_ip}",
                "full_line": f"sshd: too many failed attempts from {attacker_ip}, blocking",
            })

        await queue.put(event)
        logger.info("[brute_force] Attempt %d from %s", i, attacker_ip)
        await asyncio.sleep(0.5)


async def scenario_gradual_probe(queue: asyncio.Queue[dict[str, Any]], target: str = "192.168.1.1") -> None:
    """Simulate slow reconnaissance activity.

    Scans only a few ports intermittently; individual events look normal
    but the pattern becomes apparent when accumulated.
    """
    logger.info("[gradual_probe] Starting scenario for %s", target)

    probe_groups = [
        [21, 22],
        [80, 443],
        [3306, 5432],
        [8080, 8443],
        [6379, 27017],
        [445, 3389],
    ]

    cumulative_open: list[int] = []

    for i, ports in enumerate(probe_groups):
        # Add only 1-2 newly discovered ports at a time
        new_ports = random.sample(ports, min(len(ports), random.randint(0, 2)))
        cumulative_open.extend(new_ports)

        severity = "normal"
        if len(cumulative_open) >= 4:
            severity = "warning"
        if len(cumulative_open) >= 8:
            severity = "critical"

        event = {
            "type": "port_scan_result",
            "source": "port_scan",
            "timestamp": time.time(),
            "results": [{
                "host": target,
                "open_ports": cumulative_open[:],
                "newly_opened": new_ports,
                "newly_closed": [],
                "total_scanned": len(ports),
                "severity": severity,
            }],
        }
        await queue.put(event)
        logger.info(
            "[gradual_probe] Probe %d/%d: found %d new ports (total open: %d)",
            i + 1, len(probe_groups), len(new_ports), len(cumulative_open),
        )
        await asyncio.sleep(3)


# ── Scenario map ──────────────────────────────────────────────────────────

SCENARIOS = {
    "port_flood": scenario_port_flood,
    "suspicious_ip": scenario_suspicious_ip,
    "brute_force": scenario_brute_force,
    "gradual_probe": scenario_gradual_probe,
}


async def run_all_scenarios(queue: asyncio.Queue[dict[str, Any]]) -> None:
    """Run all scenarios sequentially."""
    for name, fn in SCENARIOS.items():
        logger.info("=" * 50)
        logger.info("Running scenario: %s", name)
        logger.info("=" * 50)
        await fn(queue)
        await asyncio.sleep(3)
    logger.info("All scenarios completed!")


# ── WebSocket client mode ─────────────────────────────────────────────────


async def run_via_websocket(uri: str, scenario_name: str | None = None) -> None:
    """Connect to the server via WebSocket and send simulated events."""
    import websockets

    async with websockets.connect(uri) as ws:
        logger.info("Connected to %s", uri)

        async def send_event(event: dict[str, Any]) -> None:
            frame = Frame.create(MSG_EVENT, CH_MONITORING, event)
            await ws.send(frame.encode())

        # Wrapper that sends directly instead of using a queue
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        # Queue consumer → WebSocket sender
        async def consumer() -> None:
            while True:
                event = await queue.get()
                await send_event(event)

        consumer_task = asyncio.create_task(consumer())

        try:
            if scenario_name and scenario_name in SCENARIOS:
                await SCENARIOS[scenario_name](queue)
            else:
                await run_all_scenarios(queue)
        finally:
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass


# ── CLI ───────────────────────────────────────────────────────────────────


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="NetAgent Attack Simulator")
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["local", "ws"],
        default="local",
        help="local: inject directly into queue (same process as server), ws: send via WebSocket",
    )
    parser.add_argument(
        "--uri", "-u",
        default="ws://localhost:8765",
        help="WebSocket server URI (for ws mode)",
    )
    args = parser.parse_args()

    if args.mode == "ws":
        scenario = args.scenario if args.scenario != "all" else None
        await run_via_websocket(args.uri, scenario)
    else:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        if args.scenario == "all":
            await run_all_scenarios(queue)
        else:
            await SCENARIOS[args.scenario](queue)

        # Print events accumulated in the queue
        count = 0
        while not queue.empty():
            event = queue.get_nowait()
            count += 1
            severity = event.get("results", [{}])[0].get("severity", "?") if event.get("results") else "?"
            logger.info(
                "Event %d: type=%s severity=%s",
                count, event.get("type", "?"), severity,
            )

        logger.info("Total events generated: %d", count)


if __name__ == "__main__":
    asyncio.run(main())
