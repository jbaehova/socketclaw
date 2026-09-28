"""Same-user Unix socket control. No TCP listener or arbitrary method dispatch."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import struct
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .application import ApplicationService, json_value
from .openai import redact_secrets

PROTOCOL = 1
MAX_FRAME = 1024 * 1024


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: int
    request_id: UUID
    owner_session: str = ""
    database_generation: str = ""
    method: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)


async def read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await asyncio.wait_for(reader.readexactly(4), 10)
    size = struct.unpack("!I", header)[0]
    if not 0 < size <= MAX_FRAME:
        raise ControlError("validation", "Frame exceeds the control protocol limit")
    raw = await asyncio.wait_for(reader.readexactly(size), 10)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ControlError("validation", "A control message must be an object")
    return cast(dict[str, Any], value)


async def write_frame(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    raw = json.dumps(json_value(value), ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > MAX_FRAME:
        raise ControlError(
            "validation", "Result exceeds 1 MiB; narrow the query or export the evidence"
        )
    writer.write(struct.pack("!I", len(raw)) + raw)
    await asyncio.wait_for(writer.drain(), 10)


def peer_uid(sock: Any) -> int:
    if sys.platform.startswith("linux"):
        return int(
            struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), 12)
            )[1]
        )
    if sys.platform == "darwin":
        raw = sock.getsockopt(0, 1, 128)  # SOL_LOCAL / LOCAL_PEERCRED, struct xucred
        version, uid = struct.unpack_from("=II", raw)
        if version != 0:
            raise OSError("Unsupported local peer credentials")
        return int(uid)
    raise OSError("Local control is supported on macOS and Linux only")


class ControlServer:
    def __init__(self, application: ApplicationService) -> None:
        self.application = application
        self.path = application.store.home / "control.sock"
        self.session = uuid4().hex
        self.server: asyncio.AbstractServer | None = None
        self._connections = 0
        self._operations: set[asyncio.Task[Any]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._identity: dict[str, str] = {}

    async def start(self) -> None:
        if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
            raise OSError("Owner control requires macOS or Linux")
        if len(os.fsencode(self.path)) > 100:
            raise OSError(
                "Application home is too long for a control socket; use a shorter SOCKETCLAW_HOME"
            )
        metadata = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or self.path.parent.is_symlink()
            or metadata.st_uid != os.getuid()
        ):
            raise OSError("Control home must be a directory owned by the current account")
        self.path.parent.chmod(0o700)
        if self.path.exists() or self.path.is_symlink():
            existing = self.path.lstat()
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise OSError("Refusing to replace an unsafe control socket path")
            self.path.unlink()  # caller already owns the application lock
        self._identity = await self.application.identity()
        self.server = await asyncio.start_unix_server(self._handle, path=self.path)
        self.path.chmod(0o600)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._connections += 1
        self._writers.add(writer)
        request_id: str | None = None
        try:
            if self._connections > 8:
                raise ControlError("busy", "Too many connected requests")
            if peer_uid(writer.get_extra_info("socket")) != os.getuid():
                raise ControlError(
                    "read_only", "Control requires the same operating-system account"
                )
            request = Request.model_validate(await read_frame(reader))
            request_id = str(request.request_id)
            if request.protocol != PROTOCOL:
                raise ControlError("version_mismatch", "Client and owner protocol versions differ")
            if request.method == "hello":
                result: Any = {
                    "protocol": PROTOCOL,
                    "owner_session": self.session,
                    "database_generation": self._identity["restore_generation"],
                    "methods": sorted(self.application.methods()),
                }
            else:
                if request.database_generation != self._identity["restore_generation"]:
                    raise ControlError(
                        "recovery_required",
                        "Database was restored. Reopen the viewer and review current evidence.",
                    )
                if request.owner_session != self.session:
                    raise ControlError(
                        "owner_unavailable", "Owner restarted; reconnect before retrying"
                    )
                operation = asyncio.create_task(
                    self.application.execute(request.method, request.params, request.request_id)
                )
                self._operations.add(operation)
                operation.add_done_callback(self._finished)
                result = await asyncio.shield(operation)
            await write_frame(
                writer, {"request_id": request_id, "status": "complete", "result": result}
            )
        except (Exception, asyncio.CancelledError) as exc:
            key = self.application.store.load_api_key()
            if isinstance(exc, ControlError):
                code = exc.code
            elif isinstance(exc, KeyError):
                code = "not_found"
            elif isinstance(exc, ValueError):
                code = "conflict" if "changed" in str(exc).lower() else "validation"
            else:
                code = "owner_unavailable"
            message = (
                "Request validation failed; check parameter names and types"
                if isinstance(exc, ValidationError)
                else redact_secrets(str(exc) or type(exc).__name__, [key] if key else ())
            )
            with suppress(Exception):
                await write_frame(
                    writer,
                    {
                        "request_id": request_id,
                        "status": "error",
                        "error": {"code": code, "message": message[:2000]},
                    },
                )
        finally:
            self._connections -= 1
            self._writers.discard(writer)
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    def _finished(self, task: asyncio.Task[Any]) -> None:
        self._operations.discard(task)
        if not task.cancelled():
            task.exception()

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        # Complete accepted commands before the owner releases the single-writer lock.
        if self._operations:
            await asyncio.gather(*tuple(self._operations), return_exceptions=True)
        for writer in tuple(self._writers):
            writer.close()
        if self.path.exists() and stat.S_ISSOCK(self.path.lstat().st_mode):
            self.path.unlink()


class ControlClient:
    def __init__(self, home: Path) -> None:
        self.path = home / "control.sock"
        self.session = ""
        self.generation = ""
        self._slots = asyncio.Semaphore(6)
        self.connected = False
        self.last_error: str | None = None

    async def _exchange(self, request: dict[str, Any]) -> Any:
        writer: asyncio.StreamWriter | None = None
        try:
            metadata = self.path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise OSError("Unsafe owner socket")
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(self.path), 3)
            if peer_uid(writer.get_extra_info("socket")) != os.getuid():
                raise OSError("Owner account mismatch")
            await write_frame(writer, request)
            response = await read_frame(reader)
            if response.get("status") == "error":
                error = response["error"]
                raise ControlError(error["code"], error["message"])
            if response.get("request_id") != request["request_id"]:
                raise ControlError("validation", "Owner response ID mismatch")
            self.connected = True
            self.last_error = None
            return response["result"]
        except (OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
            self.connected = False
            self.last_error = "Owner unavailable. Collection status is unknown; reconnecting."
            raise ControlError("owner_unavailable", self.last_error) from exc
        finally:
            if writer is not None:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

    async def connect(self) -> None:
        result = await self._exchange(
            {"protocol": PROTOCOL, "request_id": str(uuid4()), "method": "hello"}
        )
        if self.generation and self.generation != result["database_generation"]:
            self.connected = False
            raise ControlError(
                "recovery_required",
                "Database was restored. Reopen this viewer before making changes.",
            )
        self.generation = result["database_generation"]
        self.session = result["owner_session"]

    async def call(
        self, method: str, params: dict[str, Any] | None = None, *, request_id: UUID | None = None
    ) -> Any:
        async with self._slots:
            if not self.session or not self.connected:
                await self.connect()
            request = {
                "protocol": PROTOCOL,
                "request_id": str(request_id or uuid4()),
                "owner_session": self.session,
                "database_generation": self.generation,
                "method": method,
                "params": json_value(params or {}),
            }
            for attempt in range(2):
                try:
                    return await self._exchange(request)
                except ControlError as exc:
                    if exc.code != "owner_unavailable" or attempt:
                        raise
                    await self.connect()
                    request["owner_session"] = self.session
            raise RuntimeError("Owner unavailable")
