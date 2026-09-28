"""Task-scoped transaction sharing for atomic owner command receipts."""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import TextClause

command_context: ContextVar[tuple[object, AsyncSession] | None] = ContextVar(
    "owner_transaction", default=None
)


def current_session() -> AsyncSession | None:
    current = command_context.get()
    return current[1] if current and current[0] is asyncio.current_task() else None


class CommandSession(AsyncSession):
    _borrowed = False

    async def __aenter__(self) -> AsyncSession:
        current = current_session()
        if current is not None and current.bind is self.bind:
            self._borrowed = True
            return current
        return await super().__aenter__()

    async def __aexit__(self, *args: Any) -> None:
        if not self._borrowed:
            await super().__aexit__(*args)

    async def execute(self, statement: Any, params: Any = None, **kwargs: Any) -> Any:
        if (
            current_session() is self
            and isinstance(statement, TextClause)
            and statement.text.strip().upper().startswith("BEGIN")
        ):
            return await super().execute(text("SELECT 1"))
        return await super().execute(statement, params=params, **kwargs)

    async def commit(self) -> None:
        if current_session() is self:
            await self.flush()
        else:
            await super().commit()

    async def rollback(self) -> None:
        if current_session() is self:
            raise RuntimeError("Command transaction was rejected; no changes were committed")
        await super().rollback()
