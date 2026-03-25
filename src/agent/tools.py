"""LangChain tool wrappers — network diagnostic tools used by the agent.

Each tool is called by the agent when analyzing suspicious/critical events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import re
import socket
import struct
import time
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# ── Simulation state (block_ip, etc.) ────────────────────────────────────
_blocked_ips: set[str] = set()


@tool
async def ping_host(host: str, count: int = 3, timeout: float = 2.0) -> str:
    """Perform an ICMP ping to the target host to measure RTT and packet loss.

    Args:
        host: Target host to ping (IP or domain).
        count: Number of packets to send.
        timeout: Response wait timeout (seconds).

    Returns:
        JSON string containing RTT statistics and packet loss rate.
    """
    flag = "-c" if platform.system() != "Windows" else "-n"
    timeout_flag = "-W" if platform.system() != "Windows" else "-w"
    cmd = ["ping", flag, str(count), timeout_flag, str(int(timeout * 1000)), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout * count + 5)
        output = stdout.decode(errors="replace")

        rtt_list = [float(m.group(1)) for m in re.finditer(r"time[=<]([\d.]+)\s*ms", output)]
        loss_match = re.search(r"([\d.]+)%\s*packet\s*loss", output)
        loss_pct = float(loss_match.group(1)) if loss_match else (
            (count - len(rtt_list)) / count * 100
        )

        result = {
            "host": host,
            "sent": count,
            "received": len(rtt_list),
            "loss_pct": round(loss_pct, 1),
            "rtt_min": round(min(rtt_list), 2) if rtt_list else None,
            "rtt_avg": round(sum(rtt_list) / len(rtt_list), 2) if rtt_list else None,
            "rtt_max": round(max(rtt_list), 2) if rtt_list else None,
        }
    except Exception as exc:
        result = {"host": host, "error": str(exc)}

    return json.dumps(result, ensure_ascii=False)


@tool
async def port_scan(host: str, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080") -> str:
    """Async scan the specified TCP ports of the target host.

    Args:
        host: Target host to scan.
        ports: Comma-separated port numbers (e.g. "22,80,443").

    Returns:
        JSON string containing open/closed state for each port.
    """
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    results = []

    async def check(port: int) -> dict:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return {"port": port, "state": "open"}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed"}

    tasks = [check(p) for p in port_list]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r["state"] == "open"]
    return json.dumps({
        "host": host,
        "total_scanned": len(port_list),
        "open_ports": open_ports,
        "open_count": len(open_ports),
    }, ensure_ascii=False)


@tool
async def whois_lookup(target: str) -> str:
    """Look up WHOIS information for an IP address or domain.

    Args:
        target: IP address or domain to look up.

    Returns:
        JSON string containing WHOIS information.
    """
    try:
        import whois
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, target)

        result = {
            "target": target,
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
            "name_servers": getattr(w, "name_servers", None),
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
            "emails": getattr(w, "emails", None),
        }
    except Exception as exc:
        result = {"target": target, "error": str(exc)}

    return json.dumps(result, ensure_ascii=False, default=str)


@tool
async def traceroute(host: str, max_hops: int = 20, timeout: float = 2.0) -> str:
    """Trace the network path to the target host.

    Args:
        host: Target host to trace.
        max_hops: Maximum hop count.
        timeout: Per-hop timeout (seconds).

    Returns:
        JSON string containing IP and RTT for each hop.
    """
    # subprocess-based traceroute
    if platform.system() == "Windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max_hops * timeout + 10)
        output = stdout.decode(errors="replace")

        hops = []
        for line in output.splitlines():
            # "  1  router (192.168.1.1)  1.234 ms  ..."
            hop_match = re.match(r"\s*(\d+)\s+", line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            ip_match = re.search(r"\(([\d.]+)\)", line)
            ip_alt = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            rtt_matches = re.findall(r"([\d.]+)\s*ms", line)

            hop_ip = ip_match.group(1) if ip_match else (ip_alt.group(1) if ip_alt else "*")
            rtts = [float(r) for r in rtt_matches]

            hops.append({
                "hop": hop_num,
                "ip": hop_ip,
                "rtt_ms": rtts if rtts else None,
            })

        result = {"host": host, "hops": hops, "total_hops": len(hops)}
    except Exception as exc:
        result = {"host": host, "error": str(exc)}

    return json.dumps(result, ensure_ascii=False)


@tool
async def block_ip(ip: str, reason: str = "") -> str:
    """Block an IP address (simulation — not actual iptables).

    In a real environment this would add a firewall rule;
    here it records the block state in memory and logs it.

    Args:
        ip: IP address to block.
        reason: Reason for blocking.

    Returns:
        JSON string with block result.
    """
    _blocked_ips.add(ip)
    logger.warning("[SIMULATED] IP blocked: %s (reason: %s)", ip, reason)

    return json.dumps({
        "ip": ip,
        "action": "blocked",
        "simulated": True,
        "reason": reason,
        "blocked_at": time.time(),
        "total_blocked": len(_blocked_ips),
    }, ensure_ascii=False)


@tool
async def generate_report(
    event_summary: str,
    analysis: str,
    classification: str,
    action_taken: str,
) -> str:
    """Generate an event analysis report in Markdown format.

    Args:
        event_summary: Summary of the event.
        analysis: Analysis result.
        classification: Classification (normal/suspicious/critical).
        action_taken: Response action taken.

    Returns:
        Markdown-formatted report string.
    """
    severity_emoji = {"normal": "🟢", "suspicious": "🟡", "critical": "🔴"}.get(
        classification, "⚪"
    )

    report = f"""# Network Event Analysis Report

## Classification: {severity_emoji} {classification.upper()}

### Event Summary
{event_summary}

### Detailed Analysis
{analysis}

### Actions Taken
{action_taken}

---
*Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}*
"""
    return report


def get_all_tools() -> list:
    """Return the list of all agent tools."""
    return [ping_host, port_scan, whois_lookup, traceroute, block_ip, generate_report]


def get_blocked_ips() -> set[str]:
    """Return the current set of blocked IPs (simulation)."""
    return _blocked_ips.copy()
