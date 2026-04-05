"""Probe unit tests — mock out network dependencies."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time

import pytest

from src.probes.base import BaseProbe
from src.probes.ping import PingProbe, _build_icmp_packet, _internet_checksum
from src.probes.port_scan import PortScanProbe
from src.probes.log_watcher import LogPattern, LogWatcherProbe


# ── BaseProbe tests ───────────────────────────────────────────────────────


class DummyProbe(BaseProbe):
    """Dummy probe for testing."""

    def __init__(self, queue, interval=0.1, events=None):
        super().__init__("dummy", queue, interval)
        self._events = events or []
        self._call_count = 0

    async def _collect(self):
        if self._call_count < len(self._events):
            ev = self._events[self._call_count]
            self._call_count += 1
            return ev
        return None


class TestBaseProbe:
    @pytest.mark.asyncio
    async def test_start_stop(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = DummyProbe(q)
        await probe.start()
        assert probe._running
        await probe.stop()
        assert not probe._running

    @pytest.mark.asyncio
    async def test_produce_event(self):
        q: asyncio.Queue = asyncio.Queue()
        events = [{"data": "test1"}, {"data": "test2"}]
        probe = DummyProbe(q, interval=0.05, events=events)
        await probe.start()
        await asyncio.sleep(0.2)
        await probe.stop()

        collected = []
        while not q.empty():
            collected.append(q.get_nowait())

        assert len(collected) >= 2
        assert collected[0]["data"] == "test1"
        assert collected[0]["source"] == "dummy"

    @pytest.mark.asyncio
    async def test_double_start(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = DummyProbe(q)
        await probe.start()
        await probe.start()  # no-op
        await probe.stop()


# ── ICMP utility tests ────────────────────────────────────────────────────


class TestICMPUtils:
    def test_internet_checksum(self):
        data = b"\x08\x00\x00\x00\x00\x01\x00\x01"
        cs = _internet_checksum(data)
        assert isinstance(cs, int)
        assert 0 <= cs <= 0xFFFF

    def test_build_icmp_packet(self):
        pkt = _build_icmp_packet(seq=1, ident=1234)
        assert len(pkt) == 8 + 56  # header + payload
        assert pkt[0] == 8  # ICMP echo request type


# ── PingProbe tests ───────────────────────────────────────────────────────


class TestPingProbe:
    @pytest.mark.asyncio
    async def test_subprocess_ping_localhost(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PingProbe(
            targets=["127.0.0.1"],
            queue=q,
            interval=60,
            count=1,
            timeout=2.0,
        )
        probe._use_raw = False
        result = await probe._ping_host("127.0.0.1")
        assert result["host"] == "127.0.0.1"
        assert result["sent"] == 1
        assert "rtt_avg" in result

    def test_build_result_all_lost(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PingProbe(["x"], q, count=3)
        r = probe._build_result("host", [], 3)
        assert r["severity"] == "critical"
        assert r["loss_pct"] == 100.0

    def test_build_result_partial_loss(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PingProbe(["x"], q, count=4, loss_threshold=0.5)
        r = probe._build_result("host", [10.0, 20.0], 2)
        assert r["severity"] == "warning"
        assert r["loss_pct"] == 50.0

    def test_build_result_normal(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PingProbe(["x"], q, count=3)
        r = probe._build_result("host", [10.0, 15.0, 12.0], 0)
        assert r["severity"] == "normal"
        assert r["rtt_avg"] == pytest.approx(12.33, abs=0.01)


# ── PortScanProbe tests ───────────────────────────────────────────────────


class TestPortScanProbe:
    @pytest.mark.asyncio
    async def test_scan_detects_diff(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PortScanProbe(
            targets=["127.0.0.1"],
            queue=q,
            ports=[1, 2, 3],  # closed ports
            connect_timeout=0.1,
        )

        # First scan
        result = await probe._scan_host("127.0.0.1")
        assert "open_ports" in result
        assert result["newly_opened"] == []  # first scan has empty diff

    @pytest.mark.asyncio
    async def test_check_port_closed(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = PortScanProbe(["x"], q, connect_timeout=0.1)
        port, is_open = await probe._check_port("127.0.0.1", 1)
        assert port == 1
        assert is_open is False


# ── LogWatcherProbe tests ─────────────────────────────────────────────────


class TestLogWatcherProbe:
    @pytest.mark.asyncio
    async def test_detect_pattern(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("normal log line\n")
            f.flush()
            log_path = f.name

        q: asyncio.Queue = asyncio.Queue()
        probe = LogWatcherProbe(log_path=log_path, queue=q, interval=0.1)
        await probe.start()

        # Append new pattern-matching lines
        with open(log_path, "a") as f:
            f.write("ERROR: failed password for user root\n")
            f.write("WARNING: too many failed attempts from 10.0.0.1\n")

        await asyncio.sleep(0.3)
        await probe.stop()

        collected = []
        while not q.empty():
            collected.append(q.get_nowait())

        os.unlink(log_path)

        assert len(collected) >= 1
        ev = collected[0]
        assert ev["type"] == "log_match"
        assert len(ev["matches"]) >= 1

    @pytest.mark.asyncio
    async def test_no_match_returns_none(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("init line\n")
            log_path = f.name

        q: asyncio.Queue = asyncio.Queue()
        probe = LogWatcherProbe(log_path=log_path, queue=q, interval=0.1)
        await probe.start()

        with open(log_path, "a") as f:
            f.write("just a normal line with nothing special\n")

        await asyncio.sleep(0.3)
        await probe.stop()
        os.unlink(log_path)

        assert q.empty()

    def test_log_pattern_matching(self):
        p = LogPattern("test", r"error\s+(\d+)")
        assert p.match("error 404 not found") is not None
        assert p.match("all good") is None

    @pytest.mark.asyncio
    async def test_missing_file(self):
        q: asyncio.Queue = asyncio.Queue()
        probe = LogWatcherProbe(
            log_path="/nonexistent/path.log", queue=q, interval=0.1
        )
        result = await probe._collect()
        assert result is None
