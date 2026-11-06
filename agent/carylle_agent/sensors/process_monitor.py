"""Detect new processes by polling.

Polling can miss very short-lived processes, so this gives good coverage of anything that
lingers (shells, miners, implants) and is not a complete execution log. Replacing it with
eBPF or ETW would need no change elsewhere, as the event format stays the same.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from typing import Any

import psutil

from ..util import make_event, sha256_file

log = logging.getLogger(__name__)
_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
_MAX_HASH_CACHE = 4096


class ProcessMonitor(threading.Thread):
    def __init__(
        self,
        emit: Callable[[dict[str, Any]], None],
        stop: threading.Event,
        poll_seconds: float = 1.0,
        max_hash_bytes: int = 64 * 1024 * 1024,
    ):
        super().__init__(name="process-monitor", daemon=True)
        self._emit = emit
        self._stop_event = stop
        self._poll = poll_seconds
        self._max_hash_bytes = max_hash_bytes
        self._hash_cache: dict[tuple[str, int, int], str | None] = {}

    def _hash(self, exe: str) -> str | None:
        """Cache by path, size and mtime: most new processes are the same few binaries."""
        try:
            stat = os.stat(exe)
        except OSError:
            return None
        key = (exe, stat.st_size, stat.st_mtime_ns)
        if key not in self._hash_cache:
            if len(self._hash_cache) >= _MAX_HASH_CACHE:
                self._hash_cache.clear()
            self._hash_cache[key] = sha256_file(exe, self._max_hash_bytes)
        return self._hash_cache[key]

    def snapshot(self) -> dict[tuple[int, float], dict[str, Any]]:
        out: dict[tuple[int, float], dict[str, Any]] = {}
        for proc in psutil.process_iter(_ATTRS, ad_value=None):
            info = proc.info
            create_time = info.get("create_time")
            if info.get("pid") is None or create_time is None:
                continue
            # The pair identifies a process: PIDs alone get reused.
            out[(info["pid"], create_time)] = info
        return out

    def _describe(self, info: dict[str, Any]) -> dict[str, Any]:
        parent_name, parent_exe = "", ""
        if info.get("ppid"):
            try:
                parent = psutil.Process(info["ppid"])
                parent_name = parent.name()
                parent_exe = parent.exe()
            except psutil.Error:
                pass
        exe = info.get("exe") or ""
        return {
            "pid": info["pid"],
            "ppid": info.get("ppid"),
            "name": info.get("name") or "",
            "exe": exe,
            "cmdline": " ".join(info.get("cmdline") or []),
            "user": info.get("username") or "",
            "create_time": info["create_time"],
            "sha256": self._hash(exe) if exe else None,
            "parent_name": parent_name,
            "parent_exe": parent_exe,
        }

    def poll_once(self, known: set[tuple[int, float]]) -> set[tuple[int, float]]:
        current = self.snapshot()
        for key, info in current.items():
            if key not in known:
                self._emit(make_event("process_start", self._describe(info)))
        return set(current)

    def run(self) -> None:
        try:
            known = set(self.snapshot())  # Baseline: what was already running isn't "new".
        except psutil.Error:
            log.exception("process baseline failed")
            known = set()
        while not self._stop_event.wait(self._poll):
            try:
                known = self.poll_once(known)
            except Exception:
                log.exception("process poll failed")
