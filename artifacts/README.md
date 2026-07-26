# Verification artifacts

This directory contains generated, reviewable evidence for the SocketClaw
completion gate.

- `tui/` contains deterministic Textual SVG captures at wide and compact
  terminal sizes.
- `live-openrouter/` contains one redacted JSON metadata record per curated
  paid model call.

Artifacts must never contain API keys, authorization headers, raw provider
payloads, or unredacted environment values. The live tests store only the
requested/provider model IDs, reasoning effort, classification, latency,
token counts, cost, and provider request ID.
