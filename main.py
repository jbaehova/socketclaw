"""NetAgent — real-time network monitoring & autonomous response agent.

Usage:
    python main.py server     # Run WebSocket server + probes + agent
    python main.py dashboard  # Run Gradio dashboard
    python main.py simulate   # Run attack scenario simulation
"""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "server":
        import asyncio
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from scripts.run_server import main as server_main
        asyncio.run(server_main())

    elif command == "dashboard":
        from scripts.run_dashboard import build_dashboard
        demo = build_dashboard()
        demo.launch(server_name="0.0.0.0", server_port=7860)

    elif command == "simulate":
        import asyncio
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from scripts.simulate_attack import main as sim_main
        asyncio.run(sim_main())

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
