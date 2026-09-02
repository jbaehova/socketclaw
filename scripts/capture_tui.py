"""Generate deterministic, secret-free SocketClaw SVG verification captures."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from socketclaw.config import AppConfig, ConfigStore
from socketclaw.detection import Detector
from socketclaw.domain import (
    Assessment,
    DetectionResult,
    DetectionSignal,
    EventSource,
    InvestigationResult,
    ModelUsage,
    ResponseProposal,
    SecurityEvent,
    Severity,
)
from socketclaw.monitor import MonitorService
from socketclaw.storage import Repository
from socketclaw.ui.app import AppServices, SocketClawApp

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "tui"
DOC_SCREENSHOTS = ROOT / "docs" / "screenshots"


@dataclass(frozen=True, slots=True)
class Capture:
    name: str
    size: tuple[int, int]
    configured: bool
    key: str | None = None


CAPTURES = (
    Capture("onboarding-120x36", (120, 36), False),
    Capture("overview-120x36", (120, 36), True),
    Capture("events-120x36", (120, 36), True, "2"),
    Capture("investigations-120x36", (120, 36), True, "4"),
    Capture("settings-120x36", (120, 36), True, "5"),
    Capture("onboarding-80x24", (80, 24), False),
    Capture("overview-80x24", (80, 24), True),
)


async def main() -> None:
    os.environ.pop("NO_COLOR", None)
    os.environ["TERM"] = "xterm-256color"
    os.environ["COLORTERM"] = "truecolor"
    ARTIFACTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="socketclaw-captures-") as temporary:
        for index, capture in enumerate(CAPTURES):
            await _capture(capture, Path(temporary) / str(index))
    DOC_SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        ARTIFACTS / "overview-120x36.svg",
        DOC_SCREENSHOTS / "overview.svg",
    )
    print(f"Wrote {len(CAPTURES)} secret-free SVG captures to {ARTIFACTS}")


async def _capture(capture: Capture, home: Path) -> None:
    store = ConfigStore(home)
    repository = Repository(store.database_path)
    await repository.initialize()
    if capture.configured:
        store.save(
            AppConfig(
                targets=["1.1.1.1", "gateway.local"],
                ping_interval=10,
                scan_interval=120,
            )
        )
        store.save_api_key("capture-key-never-rendered")
        await _seed(repository)
    monitor = MonitorService(repository, Detector())
    app = SocketClawApp(
        AppServices(
            config_store=store,
            monitor=monitor,
            repository=repository,
        )
    )
    try:
        async with app.run_test(size=capture.size) as pilot:
            await pilot.pause(0.25)
            if capture.key is not None:
                await pilot.press(capture.key)
                await pilot.pause(0.25)
            app.save_screenshot(
                filename=f"{capture.name}.svg",
                path=str(ARTIFACTS),
            )
    finally:
        await repository.close()


async def _seed(repository: Repository) -> None:
    observed = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
    event = SecurityEvent(
        observed_at=observed,
        created_at=observed,
        source=EventSource.LOG,
        event_type="log.auth_failure",
        title="Repeated SSH authentication failures",
        summary="Twelve failed root logins were observed in sixty seconds.",
        target="8.8.4.4",
        evidence={"attempts": 12, "account": "root"},
        score=95,
        severity=Severity.CRITICAL,
    )
    detection = DetectionResult(
        score=95,
        severity=Severity.CRITICAL,
        signals=(
            DetectionSignal(
                code="auth.burst",
                label="Authentication burst",
                points=95,
                detail="Twelve failures exceeded the configured threshold.",
            ),
        ),
    )
    stored = await repository.save_event(event, detection)
    await repository.save_investigation(
        stored.id,
        InvestigationResult(
            assessment=Assessment(
                classification="critical",
                confidence=0.97,
                summary="The source is likely attacking SSH.",
                rationale=["Repeated root authentication failures exceeded the local threshold."],
                recommended_actions=["Confirm the source and review the proposed block."],
                response_proposal=ResponseProposal(
                    action="block",
                    target_ip="8.8.4.4",
                    reason="Repeated SSH authentication failures",
                ),
            ),
            usage=ModelUsage(
                prompt_tokens=120,
                completion_tokens=40,
                reasoning_tokens=20,
                cost_usd=0.0042,
                latency_ms=810,
                provider_request_id="capture-request",
            ),
            model_id="gpt-5.6-luna",
            requested_effort="high",
        ),
    )


if __name__ == "__main__":
    asyncio.run(main())
