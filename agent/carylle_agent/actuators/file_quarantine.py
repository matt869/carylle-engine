"""Move a file to quarantine, reversibly. Nothing here deletes a file.

The file is moved first and verified afterwards. Hashing and then moving would leave a
window in which an attacker could swap in a different file, including a symlink to
something important. Once moved, the bytes can no longer change under us.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from ..safelist import AgentSafelist, normalize_path
from ..util import sha256_file
from .process_terminator import ActionResult

log = logging.getLogger(__name__)


def _move(source: str, destination: str) -> None:
    try:
        os.replace(source, destination)
    except OSError:
        # Across filesystems os.replace fails, and copy2 then remove is the only option.
        shutil.copy2(source, destination, follow_symlinks=False)
        os.unlink(source)


class FileQuarantine:
    def __init__(self, directory: str | Path, safelist: AgentSafelist):
        self.directory = Path(directory)
        self.safelist = safelist

    def _prepare_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, stat.S_IRWXU)

    def quarantine(self, target: dict[str, Any]) -> ActionResult:
        path = target.get("path")
        expected = str(target.get("sha256") or "").lower()
        if not isinstance(path, str) or not os.path.isabs(path) or not expected:
            return ActionResult("refused", "target lacks an absolute path and sha256")
        path = os.path.normpath(path)

        if (problem := self.safelist.check_file(path, expected)) is not None:
            return ActionResult("refused", problem)
        # A symlinked parent directory could point a safe-looking path at a protected file.
        real = os.path.realpath(path)
        if normalize_path(real) != normalize_path(path):
            if (problem := self.safelist.check_file(real, expected)) is not None:
                return ActionResult("refused", f"resolves into protected location: {problem}")
            return ActionResult("refused", "path passes through a symlink")

        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return ActionResult("failed", "file no longer exists")
        except OSError as exc:
            return ActionResult("failed", f"could not stat file: {type(exc).__name__}")
        if not stat.S_ISREG(info.st_mode):
            return ActionResult("refused", "target is not a regular file")

        try:
            self._prepare_directory()
        except OSError as exc:
            return ActionResult("failed", f"quarantine directory unavailable: {type(exc).__name__}")

        quarantine_id = uuid.uuid4().hex
        stored = self.directory / f"{quarantine_id}.bin"
        try:
            _move(path, str(stored))
        except OSError as exc:
            return ActionResult("failed", f"could not move file: {type(exc).__name__}")

        actual = sha256_file(stored)
        if actual != expected:
            try:
                _move(str(stored), path)
            except OSError as exc:
                log.error("Could not put back %s after hash mismatch, kept as %s", path, stored)
                return ActionResult("failed", f"hash mismatch and restore failed: {type(exc).__name__}")
            return ActionResult("refused", "file content differs from the evidence; left in place")

        os.chmod(stored, stat.S_IRUSR)
        metadata = {
            "id": quarantine_id,
            "original_path": path,
            "sha256": actual,
            "quarantined_at": time.time(),
            "mode": stat.S_IMODE(info.st_mode),
            "uid": getattr(info, "st_uid", None),
            "gid": getattr(info, "st_gid", None),
            "size": info.st_size,
        }
        (self.directory / f"{quarantine_id}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        log.warning("Actuator: quarantined %s as %s", path, quarantine_id)
        return ActionResult("succeeded", f"quarantined as {quarantine_id}")

    def list_items(self) -> list[dict[str, Any]]:
        if not self.directory.exists():
            return []
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.directory.glob("*.json"))]

    def restore(self, quarantine_id: str) -> ActionResult:
        """Undo a false positive. Refuses to overwrite anything now at the original path."""
        if not quarantine_id.isalnum():
            return ActionResult("refused", "invalid quarantine id")
        meta_path = self.directory / f"{quarantine_id}.json"
        stored = self.directory / f"{quarantine_id}.bin"
        if not meta_path.exists() or not stored.exists():
            return ActionResult("failed", "no such quarantine item")
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        original = metadata["original_path"]
        if os.path.lexists(original):
            return ActionResult("refused", "a file now exists at the original path")
        try:
            os.chmod(stored, stat.S_IRUSR | stat.S_IWUSR)
            _move(str(stored), original)
            os.chmod(original, metadata["mode"])
            if metadata.get("uid") is not None and hasattr(os, "chown"):
                try:
                    os.chown(original, metadata["uid"], metadata["gid"])
                except PermissionError:
                    log.warning("Restored %s without its original owner", original)
        except OSError as exc:
            return ActionResult("failed", f"restore failed: {type(exc).__name__}")
        meta_path.unlink()
        return ActionResult("succeeded", f"restored {original}")
