from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from socketclaw.collection import CheckpointChange, LogCheckpointState
from socketclaw.config import AppConfig
from socketclaw.health import ProbeHealth

from .conftest import event_fixture, investigation_fixture


@pytest.fixture(autouse=True)
def stable_visual_environment(monkeypatch: pytest.MonkeyPatch):
    # Layout baselines use the original fixture version and timezone. Version
    # correctness is covered independently by the CLI test.
    with monkeypatch.context() as scoped:
        scoped.setattr("socketclaw.ui.dashboard.__version__", "0.5.0")
        scoped.setenv("TZ", "Asia/Seoul")
        if hasattr(time, "tzset"):
            time.tzset()
        yield
    if hasattr(time, "tzset"):
        time.tzset()


@dataclass(frozen=True, slots=True)
class VisualCase:
    name: str
    size: tuple[int, int]
    configured: bool
    keys: tuple[str, ...] = ()


VISUAL_CASES = tuple(
    VisualCase(
        name=f"{state}-{width}x{height}",
        size=(width, height),
        configured=state != "onboarding",
        keys=(
            ()
            if state in {"onboarding", "overview"}
            else ((key,) if state == "settings" else (key, "_"))
        ),
    )
    for width, height in ((80, 24), (120, 36))
    for state, key in (
        ("onboarding", ""),
        ("overview", ""),
        ("events", "2"),
        ("hosts", "3"),
        ("investigations", "4"),
        ("settings", "5"),
    )
) + tuple(
    VisualCase(
        name=f"{state}-detail-{width}x{height}",
        size=(width, height),
        configured=True,
        keys=(key, "enter"),
    )
    for width, height in ((80, 24), (100, 30), (120, 36), (160, 48))
    for state, key in (("events", "2"), ("investigations", "4"))
)

VISUAL_CASES += tuple(
    VisualCase(name=f"health-{width}x{height}", size=(width, height), configured=True, keys=("h",))
    for width, height in ((80, 24), (100, 30), (120, 36), (160, 48))
)

VISUAL_CASES += tuple(
    VisualCase(
        name=f"logs{'-detail' if detail else ''}-{width}x{height}",
        size=(width, height),
        configured=True,
        keys=("l", "enter") if detail else ("l",),
    )
    for width, height in ((80, 24), (100, 30), (120, 36), (160, 48))
    for detail in (False, True)
)


VISUAL_CASES += tuple(
    VisualCase(name=f"rules-{width}x{height}", size=(width, height), configured=True, keys=("5",))
    for width, height in ((80, 24), (100, 30), (120, 36), (160, 48))
)


@pytest.mark.parametrize("case", VISUAL_CASES, ids=lambda case: case.name)
def test_visual_states(
    snap_compare: Callable[..., bool],
    app_factory: Callable[..., Any],
    case: VisualCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLORTERM", "truecolor")
    event = event_fixture().model_copy(update={"id": UUID("b7c5570e-a93e-45cc-9fd9-fb48d6c4df17")})
    fixture = app_factory(
        configured=case.configured,
        events=[event],
        investigations=[investigation_fixture(event.id)],
        config=AppConfig(log_paths=["/var/log/socketclaw-demo.log"])
        if case.name.startswith("logs")
        else None,
    )
    fixture.app.theme = "socketclaw-dark"
    if case.name.startswith("logs"):

        async def checkpoint(probe_id: str) -> CheckpointChange:
            state = LogCheckpointState(
                read_policy="resume",
                offset=500,
                sampled_size=2500,
                backlog_bytes=2000,
                last_read_at=datetime(2026, 9, 17, tzinfo=UTC),
                last_match_count=4,
                truncated_lines=2,
                gap_count=1,
            )
            return CheckpointChange(
                probe_id=probe_id, expected_revision=1, state=state.model_dump(mode="json")
            )

        monkeypatch.setattr(fixture.repository, "load_checkpoint", checkpoint)
    if case.name.startswith("health-"):
        fixture.monitor.health_records = (
            ProbeHealth(
                probe_id="logs",
                interval_seconds=1,
                state="degraded",
                error="Read permission denied",
            ),
            ProbeHealth(probe_id="ports:gateway.local", interval_seconds=60),
        )

    async def prepare(_pilot: Any) -> None:
        if case.name.startswith("rules-"):
            fixture.app.action_rules()
            await _pilot.pause()

    assert snap_compare(
        fixture.app,
        terminal_size=case.size,
        press=case.keys,
        run_before=prepare,
    )
