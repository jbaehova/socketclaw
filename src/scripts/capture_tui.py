"""Generate deterministic, secret-free SocketClaw SVG verification captures."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import defusedxml.ElementTree as ET

from socketclaw.config import OPENAI_MODEL, AppConfig, ConfigStore
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
from socketclaw.openai import redact_secrets
from socketclaw.storage import Repository
from socketclaw.ui.app import AppServices, SocketClawApp

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "tui"
DOC_SCREENSHOTS = ROOT / "docs" / "screenshots"
CAPTURE_API_KEY = "capture-key-never-rendered"
_RICH_TERMINAL_ID = re.compile(r"\bterminal-\d+")


@dataclass(frozen=True, slots=True)
class Capture:
    name: str
    size: tuple[int, int]
    configured: bool
    key: str | None = None


CAPTURES = tuple(
    Capture(
        name=f"{view}-{width}x{height}",
        size=(width, height),
        configured=view != "onboarding",
        key=key or None,
    )
    for width, height in ((120, 36), (80, 24))
    for view, key in (
        ("onboarding", ""),
        ("overview", ""),
        ("events", "2"),
        ("hosts", "3"),
        ("investigations", "4"),
        ("settings", "5"),
    )
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic, secret-free SocketClaw SVG captures.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ARTIFACTS,
        help="capture destination (default: artifacts/tui)",
    )
    parser.add_argument(
        "--readme-screenshot",
        type=Path,
        default=DOC_SCREENSHOTS / "overview.svg",
        help="overview copy destination (default: docs/screenshots/overview.svg)",
    )
    parser.add_argument(
        "--skip-readme-screenshot",
        action="store_true",
        help="do not update the README overview copy",
    )
    return parser.parse_args()


async def main(
    output_directory: Path,
    readme_screenshot: Path | None,
) -> None:
    os.environ.pop("NO_COLOR", None)
    os.environ["TERM"] = "xterm-256color"
    os.environ["COLORTERM"] = "truecolor"
    os.environ["TZ"] = "UTC"
    if hasattr(time, "tzset"):
        time.tzset()

    with tempfile.TemporaryDirectory(prefix="socketclaw-captures-") as temporary:
        temporary_root = Path(temporary)
        staging = temporary_root / "svg"
        staging.mkdir()
        for index, capture in enumerate(CAPTURES):
            await _capture(capture, temporary_root / "homes" / str(index), staging)
        _normalize_and_verify(staging, temporary_root)
        _publish(staging, output_directory, readme_screenshot)
    print(f"Wrote {len(CAPTURES)} secret-free SVG captures to {output_directory}")


async def _capture(capture: Capture, home: Path, destination: Path) -> None:
    store = ConfigStore(home)
    repository = Repository(store.database_path)
    try:
        await repository.initialize()
        if capture.configured:
            store.save(
                AppConfig(
                    targets=["1.1.1.1", "gateway.local"],
                    ping_interval=10,
                    scan_interval=120,
                )
            )
            store.save_api_key(CAPTURE_API_KEY)
            await _seed(repository)
        monitor = MonitorService(repository, Detector())
        app = SocketClawApp(
            AppServices(
                config_store=store,
                monitor=monitor,
                repository=repository,
            )
        )
        async with app.run_test(size=capture.size) as pilot:
            await pilot.pause(0.25)
            if capture.key is not None:
                await pilot.press(capture.key)
                await pilot.pause(0.25)
            app.save_screenshot(
                filename=f"{capture.name}.svg",
                path=str(destination),
            )
    finally:
        await repository.close()


async def _seed(repository: Repository) -> None:
    observed = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
    event = SecurityEvent(
        id=UUID("b7c5570e-a93e-45cc-9fd9-fb48d6c4df17"),
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
    with patch("socketclaw.storage.utc_now", return_value=observed):
        queued = await repository.queue_investigation(
            stored.id,
            model_id=OPENAI_MODEL.model_id,
            requested_effort="high",
        )
        await repository.start_investigation(queued.id)
        await repository.complete_investigation(
            queued.id,
            InvestigationResult(
                assessment=Assessment(
                    classification="critical",
                    confidence=0.97,
                    summary="The source is likely attacking SSH.",
                    rationale=(
                        "Repeated root authentication failures exceeded the local threshold.",
                    ),
                    recommended_actions=("Confirm the source and review the proposed block.",),
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
                model_id=OPENAI_MODEL.model_id,
                requested_effort="high",
            ),
        )


def _normalize_and_verify(directory: Path, temporary_root: Path) -> None:
    expected = {f"{capture.name}.svg" for capture in CAPTURES}
    actual = {path.name for path in directory.glob("*.svg")}
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected)) or "none"
        raise RuntimeError(f"capture set mismatch; missing: {missing}; unexpected: {unexpected}")

    for capture in CAPTURES:
        path = directory / f"{capture.name}.svg"
        content = path.read_text(encoding="utf-8")
        stable_id = f"terminal-socketclaw-{capture.name}"
        content = _RICH_TERMINAL_ID.sub(stable_id, content)
        path.write_text(content, encoding="utf-8")
        ET.parse(path)

        forbidden = (
            CAPTURE_API_KEY,
            str(temporary_root),
            "OPENAI_API_KEY=",
            "Authorization:",
            "Bearer ",
        )
        if any(marker in content for marker in forbidden):
            raise RuntimeError(f"secret or local path found in {path.name}")
        if redact_secrets(content) != content:
            raise RuntimeError(f"OpenAI credential pattern found in {path.name}")


def _publish(
    staging: Path,
    output_directory: Path,
    readme_screenshot: Path | None,
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    for capture in CAPTURES:
        source = staging / f"{capture.name}.svg"
        _atomic_copy(source, output_directory / source.name)
    if readme_screenshot is not None:
        _atomic_copy(staging / "overview-120x36.svg", readme_screenshot)


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o644)
        os.replace(temporary_path, destination)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    arguments = _arguments()
    screenshot = None if arguments.skip_readme_screenshot else arguments.readme_screenshot
    asyncio.run(main(arguments.output_dir, screenshot))
