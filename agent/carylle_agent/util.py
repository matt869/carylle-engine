"""Small helpers shared across the agent."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from pathlib import Path
from typing import Any


def make_event(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"event_id": uuid.uuid4().hex, "type": event_type, "ts": time.time(), "data": data}


def sha256_file(path: str | Path, max_bytes: int | None = None) -> str | None:
    """Hash a file. Returns None if it can't be read, or is larger than max_bytes."""
    try:
        if max_bytes is not None and os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
