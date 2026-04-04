"""Gradio dashboard run script."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ui.dashboard import build_dashboard

if __name__ == "__main__":
    demo = build_dashboard()
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.getenv("NETAGENT_DASHBOARD_PORT", "7860")),
        share=False,
    )
