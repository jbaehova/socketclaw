"""Protocol constants — message type codes, channel IDs, version."""

# Protocol version
PROTOCOL_VERSION = 1

# ── Message type codes ────────────────────────────────────────────────────
MSG_EVENT = 0x01           # Probe → Server: network event
MSG_COMMAND = 0x02         # Agent → Probe: command
MSG_ACK = 0x03             # Server → Client: acknowledgment
MSG_AGENT_RESULT = 0x04    # Agent → Client: analysis/decision result
MSG_HEARTBEAT = 0x05       # Bidirectional: keep-alive
MSG_CONTROL = 0x06         # Client → Server: control command

MSG_TYPE_NAMES: dict[int, str] = {
    MSG_EVENT: "EVENT",
    MSG_COMMAND: "COMMAND",
    MSG_ACK: "ACK",
    MSG_AGENT_RESULT: "AGENT_RESULT",
    MSG_HEARTBEAT: "HEARTBEAT",
    MSG_CONTROL: "CONTROL",
}

# ── Channel IDs ──────────────────────────────────────────────────────────
CH_MONITORING = "monitoring"   # Real-time event stream
CH_AGENT = "agent"             # Agent analysis results
CH_CONTROL = "control"         # User control commands

ALL_CHANNELS = {CH_MONITORING, CH_AGENT, CH_CONTROL}
