"""Load the application only when a command needs it."""

import sys

from . import __version__


def main() -> None:
    if sys.argv[1:] == ["version"]:
        print(f"SocketClaw {__version__}")
        return

    from .cli import app

    app()
