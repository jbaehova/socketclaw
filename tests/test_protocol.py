"""Tests for frame encoding/decoding/checksum verification."""

from __future__ import annotations

import json

import pytest

from src.protocol.constants import (
    CH_MONITORING,
    MSG_ACK,
    MSG_EVENT,
    MSG_HEARTBEAT,
    PROTOCOL_VERSION,
)
from src.protocol.frame import ChecksumError, Frame, FrameError, reset_sequence


@pytest.fixture(autouse=True)
def _reset_seq():
    """Reset sequence counter before each test."""
    reset_sequence()
    yield
    reset_sequence()


class TestFrameCreate:
    def test_create_basic(self):
        frame = Frame.create(MSG_EVENT, CH_MONITORING, {"host": "8.8.8.8"})
        assert frame.version == PROTOCOL_VERSION
        assert frame.seq == 0
        assert frame.type == MSG_EVENT
        assert frame.channel == CH_MONITORING
        assert frame.payload == {"host": "8.8.8.8"}
        assert frame.timestamp > 0
        assert len(frame.checksum) == 8  # CRC32 hex

    def test_seq_auto_increment(self):
        f1 = Frame.create(MSG_EVENT, CH_MONITORING, {})
        f2 = Frame.create(MSG_EVENT, CH_MONITORING, {})
        f3 = Frame.create(MSG_EVENT, CH_MONITORING, {})
        assert f1.seq == 0
        assert f2.seq == 1
        assert f3.seq == 2

    def test_type_name(self):
        frame = Frame.create(MSG_HEARTBEAT, CH_MONITORING, {})
        assert frame.type_name == "HEARTBEAT"

    def test_type_name_unknown(self):
        frame = Frame.create(0xFF, CH_MONITORING, {})
        assert "UNKNOWN" in frame.type_name

    def test_repr(self):
        frame = Frame.create(MSG_EVENT, CH_MONITORING, {"a": 1})
        r = repr(frame)
        assert "EVENT" in r
        assert "monitoring" in r


class TestFrameEncodeDecode:
    def test_roundtrip(self):
        original = Frame.create(MSG_EVENT, CH_MONITORING, {"host": "1.2.3.4", "rtt": 12.5})
        encoded = original.encode()
        decoded = Frame.decode(encoded)

        assert decoded.version == original.version
        assert decoded.seq == original.seq
        assert decoded.type == original.type
        assert decoded.channel == original.channel
        assert decoded.timestamp == original.timestamp
        assert decoded.checksum == original.checksum
        assert decoded.payload == original.payload

    def test_roundtrip_str_input(self):
        original = Frame.create(MSG_ACK, CH_MONITORING, {"ack_seq": 42})
        encoded_str = original.encode().decode()
        decoded = Frame.decode(encoded_str)
        assert decoded.payload == {"ack_seq": 42}

    def test_empty_payload(self):
        frame = Frame.create(MSG_HEARTBEAT, CH_MONITORING, {})
        decoded = Frame.decode(frame.encode())
        assert decoded.payload == {}

    def test_nested_payload(self):
        payload = {"results": [{"host": "a", "rtt": 1.0}, {"host": "b", "rtt": 2.0}]}
        frame = Frame.create(MSG_EVENT, CH_MONITORING, payload)
        decoded = Frame.decode(frame.encode())
        assert decoded.payload == payload


class TestFrameErrors:
    def test_invalid_json(self):
        with pytest.raises(FrameError, match="JSON"):
            Frame.decode(b"not json")

    def test_missing_fields(self):
        data = json.dumps({"version": 1, "seq": 0}).encode()
        with pytest.raises(FrameError, match="Missing required fields"):
            Frame.decode(data)

    def test_invalid_payload_type(self):
        data = json.dumps({
            "version": 1, "seq": 0, "type": 1, "channel": "test",
            "timestamp": 0.0, "checksum": "00000000", "payload": "not a dict",
        }).encode()
        with pytest.raises(FrameError, match="payload.*dict"):
            Frame.decode(data)

    def test_checksum_mismatch(self):
        frame = Frame.create(MSG_EVENT, CH_MONITORING, {"data": "test"})
        raw = json.loads(frame.encode())
        raw["checksum"] = "deadbeef"
        with pytest.raises(ChecksumError, match="Checksum mismatch"):
            Frame.decode(json.dumps(raw).encode())

    def test_skip_checksum_verify(self):
        frame = Frame.create(MSG_EVENT, CH_MONITORING, {"data": "test"})
        raw = json.loads(frame.encode())
        raw["checksum"] = "deadbeef"
        decoded = Frame.decode(json.dumps(raw).encode(), verify_checksum=False)
        assert decoded.checksum == "deadbeef"


class TestFrameChecksum:
    def test_same_payload_same_checksum(self):
        f1 = Frame.create(MSG_EVENT, CH_MONITORING, {"key": "value"})
        f2 = Frame.create(MSG_EVENT, CH_MONITORING, {"key": "value"})
        assert f1.checksum == f2.checksum

    def test_different_payload_different_checksum(self):
        f1 = Frame.create(MSG_EVENT, CH_MONITORING, {"key": "value1"})
        f2 = Frame.create(MSG_EVENT, CH_MONITORING, {"key": "value2"})
        assert f1.checksum != f2.checksum
