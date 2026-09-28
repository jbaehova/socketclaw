# SocketClaw

SocketClaw is a local-first terminal security operations cockpit built with
Textual. It monitors explicitly configured hosts, services and file logs, stores evidence
in SQLite, and supports
optional investigations through the OpenAI Platform.

Source installations require Python 3.11 or newer. macOS releases include the
runtime. Run `socketclaw` to launch the inline terminal workspace or
`socketclaw doctor` to check local readiness.

For installation, configuration, and development instructions, see the
[project documentation](https://github.com/jbaehova/SocketClaw#readme).

For persistent collection, run `socketclaw monitor`. Use
`socketclaw attach --tui --control` to process incidents without stopping it.
Closing the viewer leaves collection running. `/storage` manages online cleanup.
This is a configured-target monitor, not a whole-machine protection agent.
Native journald and macOS unified-log collection are not supported.
