# Verification artifacts

This directory contains generated, reviewable evidence for the SocketClaw
verification gate.

- `tui/` contains tracked Textual SVG captures of every documented screen at
  120x36 and 80x24 terminal sizes.
- `live-openai/` is a Git-ignored local directory. The paid Luna test writes a
  redacted JSON metadata record there.

Regenerate the TUI captures and README screenshot from the repository root:

```bash
uv run python scripts/capture_tui.py
```

The capture tool renders every file in a staging directory, normalizes Rich's
generated terminal identifiers, checks the full set for secrets, and only then
replaces the tracked outputs. Review all SVG changes before committing them.

Artifacts must never contain API keys, authorization headers, raw provider
payloads, or unredacted environment values. The live test stores only:

- requested and returned model IDs plus reasoning effort;
- classification, latency, and token counts;
- estimated cost and the provider request ID.
