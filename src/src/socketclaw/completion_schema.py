"""Shared schema for owner commands, maintenance and transactional notification delivery."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncConnection

OUTBOX_DDL = (
    "CREATE TABLE IF NOT EXISTS notification_config (channel TEXT PRIMARY KEY, "
    "enabled INTEGER NOT NULL, destination TEXT NOT NULL, revision TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS notification_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, transition_id TEXT NOT NULL, "
    "channel TEXT NOT NULL, destination TEXT NOT NULL, revision "
    "TEXT NOT NULL, payload TEXT NOT NULL, "
    "attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0, delivered_at REAL, "
    "error TEXT, lease_until REAL NOT NULL DEFAULT 0, held INTEGER NOT NULL DEFAULT 0, "
    "UNIQUE(transition_id, channel, revision))",
    "CREATE INDEX IF NOT EXISTS ix_deliveries_pending ON deliveries(delivered_at, next_attempt)",
)

# The trigger participates in the caller's transaction, including operator reopen operations.
# It does not depend on ROWID or on a second database's high-water mark.
OUTBOX_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS enqueue_incident_notification
AFTER INSERT ON incident_transitions
WHEN json_extract(NEW.data_json, '$.action') IN
    ('opened','reopened','recurred','observed_recovery','worsened')
BEGIN
    INSERT OR IGNORE INTO deliveries
        (id, transition_id, channel, destination, revision, payload)
    SELECT NEW.id || ':' || channel || ':' || revision, NEW.id, channel, destination, revision,
        json_object('incident_id', json_extract(NEW.data_json,'$.incident_id'),
                    'transition_id', NEW.id, 'action', json_extract(NEW.data_json,'$.action'),
                    'at', json_extract(NEW.data_json,'$.at'),
                    'delayed_evidence', json(CASE WHEN
                        coalesce((julianday('now') - julianday(json_extract(NEW.data_json,'$.at')))
                                 * 86400 > 300, 1) THEN 'true' ELSE 'false' END))
    FROM notification_config WHERE enabled=1;
END
"""

OWNER_DDL = (
    "CREATE TABLE IF NOT EXISTS owner_jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, "
    "result_json TEXT, error TEXT)",
    "CREATE TABLE IF NOT EXISTS command_receipts (id TEXT PRIMARY KEY, method TEXT NOT NULL, "
    "input_hash TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS maintenance_jobs (id TEXT PRIMARY KEY, data_json TEXT NOT NULL)",
)


async def install_completion_schema(connection: AsyncConnection) -> None:
    for statement in (*OUTBOX_DDL, OUTBOX_TRIGGER, *OWNER_DDL):
        await connection.exec_driver_sql(statement)
    for key in ("database_identity", "restore_generation"):
        await connection.exec_driver_sql(
            "INSERT OR IGNORE INTO schema_meta(key,value) VALUES(?, lower(hex(randomblob(16))))",
            (key,),
        )
