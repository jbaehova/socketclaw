"""Exercise the installed owner boundary from a distinct OS process and full TUI."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
from pathlib import Path

import pytest
from textual.widgets import TextArea

from socketclaw.config import AppConfig, ConfigStore, ServiceConfig
from socketclaw.control import ControlClient
from socketclaw.gateway import RemoteApplication, RemoteMonitor, RemoteRepository
from socketclaw.ui.app import AppServices, SocketClawApp
from socketclaw.ui.incidents import IncidentComment, IncidentReader
from socketclaw.ui.operations import OperationsScreen, StopCollectorScreen


@pytest.fixture
async def process_owner():
    with tempfile.TemporaryDirectory(prefix="scp-", dir="/tmp") as root:
        status = [500]

        async def respond(reader, writer):
            await reader.read(4096)
            writer.write(
                (
                    f"HTTP/1.1 {status[0]} Fixture\r\nContent-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        service = await asyncio.start_server(respond, "127.0.0.1", 0)
        port = service.sockets[0].getsockname()[1]
        store = ConfigStore(Path(root))
        store.save(
            AppConfig(
                targets=[],
                services=[
                    ServiceConfig(
                        id="fixture",
                        name="HTTP recovery fixture",
                        host="127.0.0.1",
                        port=port,
                        protocol="http",
                        interval=1,
                        timeout=0.2,
                        failure_threshold=1,
                    )
                ],
            )
        )
        env = {**os.environ, "SOCKETCLAW_HOME": root}
        env.pop("OPENAI_API_KEY", None)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "from socketclaw.entrypoint import main; main()",
            "monitor",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        client = ControlClient(store.home)
        try:
            for _ in range(100):
                if process.returncode is not None:
                    out, err = await process.communicate()
                    pytest.fail(f"Owner exited: {out!r} {err!r}")
                if (store.home / "control.sock").exists():
                    await client.connect()
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("Owner did not expose its control socket")
            yield store, client, process, status
        finally:
            service.close()
            await service.wait_closed()
            if process.returncode is None:
                process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(process.communicate(), 10)
            except TimeoutError:
                process.kill()
                await process.communicate()


@pytest.mark.parametrize("size", [(80, 24), (120, 36)])
async def test_full_attached_tui_close_preserves_owner(process_owner, size):
    store, client, process, status = process_owner
    repository = RemoteRepository(client)
    application = RemoteApplication(client, repository)
    monitor = RemoteMonitor(client)
    viewer = SocketClawApp(
        AppServices(
            config_store=store,
            monitor=monitor,
            repository=repository,
            investigate=application.investigate,
            application=application,
            attached=True,
        )
    )
    async with viewer.run_test(size=size) as pilot:
        await pilot.pause(1)
        viewer.action_storage()
        await pilot.pause(0.3)
        assert isinstance(viewer.screen, OperationsScreen)
        await pilot.click("#operations-preview")
        await pilot.pause(0.3)
        await pilot.press("escape")
        viewer.action_stop_collector()
        await pilot.pause()
        assert isinstance(viewer.screen, StopCollectorScreen)
        await pilot.press("escape")
        viewer.action_incidents()
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert isinstance(viewer.screen, IncidentReader)
        incident = (await repository.incidents.list())[0]
        status[0] = 200
        for button, reason in [
            ("#case-ack", "Investigating fixture"),
            ("#case-note", "Attached note survives viewer close"),
            ("#case-resolve", "Fixture acknowledged and documented"),
        ]:
            await pilot.click(button)
            await pilot.pause()
            assert isinstance(viewer.screen, IncidentComment)
            viewer.screen.query_one(TextArea).load_text(reason)
            await pilot.pause()
            await pilot.click("#case-comment-save")
            await pilot.pause(0.3)
        assert (await repository.incidents.get(incident.id)).status == "resolved"
        assert len(await repository.incidents.notes(incident.id)) == 1
        queued = await application.execute("export.request", {"identifier": str(incident.id)})
        report = await application.wait_operation(queued)
        assert Path(report).is_file()
        await viewer.action_quit()
    assert process.returncode is None
    health = await client.call("health.get")
    assert health["monitor"]["running"] is True
    before = await repository.latest_service_observations(["fixture"])
    await asyncio.sleep(1.2)
    after = await repository.latest_service_observations(["fixture"])
    assert after["fixture"].id != before["fixture"].id
    await client.call("owner.stop")
    await asyncio.wait_for(process.wait(), 10)
    assert process.returncode == 0
