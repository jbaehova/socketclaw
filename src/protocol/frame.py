"""Custom protocol frame definition and parsing.

Frame Format:
    version, seq, type, channel, timestamp, checksum(CRC32), payload
"""

from __future__ import annotations

import json
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Any

from .constants import MSG_TYPE_NAMES, PROTOCOL_VERSION


class FrameError(Exception):
    """Error related to frame encoding/decoding."""


class ChecksumError(FrameError):
    """CRC32 checksum mismatch."""


class _SeqCounter:
    """Thread-safe sequence number counter."""

    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            seq = self._value
            self._value += 1
            return seq

    def reset(self) -> None:
        with self._lock:
            self._value = 0


_global_seq = _SeqCounter()


def reset_sequence() -> None:
    """Reset the sequence counter (for testing)."""
    _global_seq.reset()


def _compute_checksum(payload_bytes: bytes) -> str:
    """Return CRC32 hex string for the given payload bytes."""
    return format(zlib.crc32(payload_bytes) & 0xFFFFFFFF, "08x")


@dataclass(frozen=True)
class Frame:
    """Custom protocol frame.

    Attributes:
        version: Protocol version.
        seq: Sequence number.
        type: Message type code.
        channel: Multiplexing channel ID.
        timestamp: Unix timestamp (ms).
        checksum: CRC32 hex string of the payload.
        payload: Actual data dictionary.
    """

    type: int
    channel: str
    payload: dict[str, Any]
    version: int = PROTOCOL_VERSION
    seq: int = field(default=-1)
    timestamp: float = field(default=0.0)
    checksum: str = field(default="")

    @staticmethod
    def create(
        msg_type: int,
        channel: str,
        payload: dict[str, Any],
    ) -> Frame:
        """Create a new Frame. seq / timestamp / checksum are assigned automatically."""
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        return Frame(
            version=PROTOCOL_VERSION,
            seq=_global_seq.next(),
            type=msg_type,
            channel=channel,
            timestamp=time.time() * 1000,
            checksum=_compute_checksum(payload_bytes),
            payload=payload,
        )

    # ── Serialization ─────────────────────────────────────────────

    def encode(self) -> bytes:
        """Serialize Frame → JSON bytes."""
        data = {
            "version": self.version,
            "seq": self.seq,
            "type": self.type,
            "channel": self.channel,
            "timestamp": self.timestamp,
            "checksum": self.checksum,
            "payload": self.payload,
        }
        return json.dumps(data, separators=(",", ":")).encode()

    @staticmethod
    def decode(raw: bytes | str, *, verify_checksum: bool = True) -> Frame:
        """Deserialize JSON bytes/str → Frame.

        Args:
            raw: Encoded frame data.
            verify_checksum: If True, verify the checksum.

        Raises:
            FrameError: On parsing failure.
            ChecksumError: On checksum mismatch.
        """
        if isinstance(raw, (bytes, bytearray)):
            text = raw.decode()
        else:
            text = raw

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise FrameError(f"JSON parse failed: {exc}") from exc

        required = {"version", "seq", "type", "channel", "timestamp", "checksum", "payload"}
        missing = required - set(data.keys())
        if missing:
            raise FrameError(f"Missing required fields: {missing}")

        if not isinstance(data["payload"], dict):
            raise FrameError("payload must be a dict type")

        if verify_checksum:
            payload_bytes = json.dumps(data["payload"], separators=(",", ":")).encode()
            expected = _compute_checksum(payload_bytes)
            if data["checksum"] != expected:
                raise ChecksumError(
                    f"Checksum mismatch: expected={expected}, got={data['checksum']}"
                )

        return Frame(
            version=data["version"],
            seq=data["seq"],
            type=data["type"],
            channel=data["channel"],
            timestamp=data["timestamp"],
            checksum=data["checksum"],
            payload=data["payload"],
        )

    # ── Utilities ─────────────────────────────────────────────────

    @property
    def type_name(self) -> str:
        return MSG_TYPE_NAMES.get(self.type, f"UNKNOWN(0x{self.type:02x})")

    def __repr__(self) -> str:
        return (
            f"Frame(seq={self.seq}, type={self.type_name}, "
            f"channel={self.channel!r}, payload_keys={list(self.payload.keys())})"
        )
