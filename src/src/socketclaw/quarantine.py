"""Durable evidence for deterministic validation failures, without advancing checkpoints."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .collection import ProbeBatch
from .domain import utc_now


def quarantine_batch(home: Path, job: str, batch: ProbeBatch, error: str) -> Path:
    directory = home / "quarantine"
    if directory.is_symlink():
        raise OSError("quarantine directory must not be a symbolic link")
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"{batch.batch_id}.json"
    payload = {
        "job": job,
        "error": error[:2000],
        "quarantined_at": utc_now().isoformat(),
        "batch": batch.model_dump(mode="json"),
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, delete=False
        ) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
