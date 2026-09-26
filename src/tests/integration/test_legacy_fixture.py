"""Freeze representative v1 facts before introducing sequential migrations."""

import sqlite3
from pathlib import Path

from socketclaw.migrations import SCHEMA_VERSION
from socketclaw.storage import Repository


async def test_v1_fixture_preserves_legacy_histories_and_unknown_facts(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    fixture = Path(__file__).parents[1] / "fixtures" / "schema-v1.sql"
    with sqlite3.connect(database) as connection:
        connection.executescript(fixture.read_text())
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository = Repository(database)
    try:
        await repository.initialize()
        info = await repository.database_info()
        assert info.schema_version == SCHEMA_VERSION
        events = await repository.list_events()
        assert len(events) == 1
        assert events[0].evidence == {"attempts": 12, "account": "root"}
        investigations = await repository.list_investigations(event_id=events[0].id)
        assert {item.status for item in investigations} == {"complete", "failed"}
        complete = next(item for item in investigations if item.status == "complete")
        assert complete.usage is not None
        assert complete.usage.cost_usd == 0.0042
        proposals = await repository.list_response_proposals()
        assert len(proposals) == 1
        assert proposals[0].status == "approved"
        assert proposals[0].investigation_id == complete.id
        runs = await repository.list_runs()
        assert len(runs) == 2
        assert {run.clean_shutdown for run in runs} == {False, True}
    finally:
        await repository.close()
