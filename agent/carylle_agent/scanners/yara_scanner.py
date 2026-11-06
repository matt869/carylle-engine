"""YARA scanning. yara-python is optional: without it the scanner reports itself unavailable."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # pragma: no cover - depends on the install profile
    yara = None  # type: ignore[assignment]


class YaraScanner:
    def __init__(self, rules_dir: str | Path, timeout_seconds: int = 30, max_scan_bytes: int = 64 * 1024 * 1024):
        self.timeout = int(timeout_seconds)
        self.max_scan_bytes = int(max_scan_bytes)
        self._rules = None
        if yara is None:
            log.warning("yara-python is not installed: file content scanning is off")
            return
        rule_files = {
            path.stem: str(path)
            for path in sorted(Path(rules_dir).glob("*"))
            if path.suffix.lower() in {".yar", ".yara"}
        }
        if not rule_files:
            log.warning("No YARA rules found in %s: file content scanning is off", rules_dir)
            return
        try:
            self._rules = yara.compile(filepaths=rule_files)
            log.info("Compiled %d YARA rule file(s)", len(rule_files))
        except yara.Error as exc:
            log.error("YARA rules failed to compile, content scanning is off: %s", exc)

    @property
    def available(self) -> bool:
        return self._rules is not None

    def scan(self, path: str | Path) -> list[dict[str, Any]]:
        """Scan one file. A file that can't be read or is too big yields no matches."""
        if self._rules is None:
            return []
        try:
            if os.path.getsize(path) > self.max_scan_bytes:
                return []
            matches = self._rules.match(str(path), timeout=self.timeout)
        except (OSError, yara.Error) as exc:
            log.debug("YARA scan skipped for %s: %s", path, exc)
            return []
        return [
            {
                "rule": match.rule,
                "tags": list(match.tags),
                "severity": str(match.meta.get("severity", "medium")),
                "attack": str(match.meta.get("attack", "")),
                "description": str(match.meta.get("description", "")),
            }
            for match in matches
        ]
