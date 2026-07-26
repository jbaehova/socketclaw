from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest

from socketclaw.config import AppConfig, ConfigStore
from socketclaw.monitor import MonitorStatus
from socketclaw.openrouter import KeyStatus
from socketclaw.ui.app import AppServices, SocketClawApp


class TestMonitor:
    __test__ = False

    def __init__(self) -> None:
        self.running = False
        self.paused = False
        self.started = 0
        self.stopped = 0

    @property
    def status(self) -> MonitorStatus:
        return MonitorStatus(
            running=self.running,
            paused=self.paused,
            started_at=datetime.now().astimezone() if self.running else None,
            active_jobs=2 if self.running else 0,
            last_error=None,
        )

    async def start(self) -> None:
        self.running = True
        self.started += 1

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    async def stop(self) -> None:
        self.running = False
        self.stopped += 1


KeyValidator = Callable[[str], Awaitable[KeyStatus]]


async def valid_key(_key: str) -> KeyStatus:
    return KeyStatus(
        label="socketclaw-test",
        is_free_tier=False,
        limit=10,
        limit_remaining=9,
        usage=1,
    )


@dataclass
class AppFixture:
    app: SocketClawApp
    store: ConfigStore
    monitor: TestMonitor


@pytest.fixture
def app_factory(
    tmp_path: Path,
) -> Callable[..., AppFixture]:
    counter = 0

    def make(
        *,
        configured: bool,
        validator: KeyValidator = valid_key,
    ) -> AppFixture:
        nonlocal counter
        counter += 1
        store = ConfigStore(tmp_path / f"home-{counter}")
        if configured:
            store.save(AppConfig())
            store.save_api_key("sk-or-v1-configured")
        monitor = TestMonitor()
        services = AppServices(
            config_store=store,
            monitor=monitor,
            validate_key=validator,
        )
        return AppFixture(
            app=SocketClawApp(services),
            store=store,
            monitor=monitor,
        )

    return make
