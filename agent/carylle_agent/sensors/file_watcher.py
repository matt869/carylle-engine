"""Watch configured paths for changes, hash what changed and run YARA over it."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..scanners.yara_scanner import YaraScanner
from ..util import make_event, sha256_file

log = logging.getLogger(__name__)


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: FileWatcher):
        self._watcher = watcher

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        action = {"created": "created", "modified": "modified", "moved": "moved", "deleted": "deleted"}.get(
            event.event_type
        )
        if action:
            dest = os.fsdecode(event.dest_path) if getattr(event, "dest_path", "") else ""
            self._watcher.record(os.fsdecode(event.src_path), action, dest)


class FileWatcher(threading.Thread):
    def __init__(
        self,
        emit: Callable[[dict[str, Any]], None],
        stop: threading.Event,
        paths: list[str],
        scanner: YaraScanner | None = None,
        exclude: list[str] | None = None,
        max_hash_bytes: int = 64 * 1024 * 1024,
        debounce_seconds: float = 0.5,
        max_delay_seconds: float = 5.0,
    ):
        super().__init__(name="file-watcher", daemon=True)
        self._emit = emit
        self._stop_event = stop
        self._paths = paths
        self._scanner = scanner
        # The agent's own working directories would otherwise feed back into themselves.
        self._exclude = tuple(os.path.abspath(p) + os.sep for p in exclude or [])
        self._max_hash_bytes = max_hash_bytes
        self._debounce = debounce_seconds
        # Debounce waits for a quiet moment. A file written to without pause never has
        # one, so it is reported after this long regardless. Otherwise a slow encryptor,
        # or an attacker touching a dropped file every few hundred ms, would stay unseen.
        self._max_delay = max_delay_seconds
        # path -> (first action, dest, last event time, first event time)
        self._pending: dict[str, tuple[str, str, float, float]] = {}
        self._lock = threading.Lock()
        self.watching: list[str] = []
        self.ready = threading.Event()

    def record(self, path: str, action: str, dest: str = "") -> None:
        final = dest or path
        if os.path.abspath(final).startswith(self._exclude):
            return
        with self._lock:
            # One save produces a flurry of events, so keep the earliest action:
            # "created then modified" should still be reported as created.
            now = time.monotonic()
            previous = self._pending.get(path)
            first_action = previous[0] if previous and action == "modified" else action
            first_seen = previous[3] if previous else now
            self._pending[path] = (first_action, dest, now, first_seen)

    def _flush(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            ready = {
                path: item
                for path, item in self._pending.items()
                if force or now - item[2] >= self._debounce or now - item[3] >= self._max_delay
            }
            for path in ready:
                del self._pending[path]
        for path, (action, dest, _, _) in ready.items():
            try:
                self._process(path, action, dest)
            except Exception:
                log.exception("failed to process file event for %s", path)

    def _process(self, path: str, action: str, dest: str) -> None:
        final = dest or path
        sha256, size = None, None
        if action != "deleted":
            try:
                size = os.path.getsize(final)
            except OSError:
                return  # Gone already, and the delete event will report it.
            sha256 = sha256_file(final, self._max_hash_bytes)
        self._emit(
            make_event(
                "file_event", {"path": path, "action": action, "dest_path": dest, "sha256": sha256, "size": size}
            )
        )
        if action != "deleted" and self._scanner is not None and self._scanner.available:
            for match in self._scanner.scan(final):
                self._emit(make_event("yara_match", {**match, "path": final, "sha256": sha256, "size": size}))

    def run(self) -> None:
        observer = Observer()
        handler = _Handler(self)
        for raw in self._paths:
            path = Path(raw)
            if not path.is_dir():
                log.info("Not watching %s: no such directory", raw)
                continue
            try:
                observer.schedule(handler, str(path), recursive=True)
                self.watching.append(str(path))
            except OSError as exc:
                log.warning("Cannot watch %s: %s", raw, exc)
        try:
            observer.start()
        except OSError as exc:
            # Usually the inotify watch limit. Say so loudly, as this is a blind spot.
            log.error("File watcher failed to start: %s", exc)
            self.ready.set()
            return
        self.ready.set()
        try:
            while not self._stop_event.wait(0.2):
                self._flush()
            self._flush(force=True)
        finally:
            observer.stop()
            observer.join(timeout=5)
