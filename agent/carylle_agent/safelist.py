"""The agent's own copy of the safelist, enforced against live state right before acting.

This deliberately does not trust the server. A compromised server, or a stale command,
still has to get past these checks on the endpoint itself. A missing or unreadable
safelist refuses every action.
"""

from __future__ import annotations

import ntpath
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def _is_windows_path(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", path)) or path.startswith("\\\\")


def normalize_path(path: str) -> str:
    if _is_windows_path(path):
        return ntpath.normcase(ntpath.normpath(path))
    return posixpath.normpath(path)


@dataclass
class AgentSafelist:
    loaded: bool = False
    exe_paths: set[str] = field(default_factory=set)
    min_pid: int = 3
    protected_prefixes: list[str] = field(default_factory=list)
    protected_paths: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path) -> AgentSafelist:
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return cls(loaded=False)
        processes = raw.get("processes") or {}
        files = raw.get("files") or {}

        def prefix(p: str) -> str:
            sep = "\\" if _is_windows_path(p) else "/"
            return normalize_path(p).rstrip(sep) + sep

        return cls(
            loaded=True,
            exe_paths={normalize_path(p) for p in processes.get("exe_paths") or []},
            min_pid=int(processes.get("min_pid", 3)),
            protected_prefixes=[prefix(p) for p in files.get("protected_prefixes") or []],
            protected_paths={normalize_path(p) for p in files.get("protected_paths") or []},
            sha256={s.lower() for s in files.get("sha256") or []},
        )

    def check_process(self, pid: int, exe: str) -> str | None:
        if not self.loaded:
            return "safelist unavailable"
        if pid < self.min_pid:
            return f"pid below protected minimum {self.min_pid}"
        if exe and normalize_path(exe) in self.exe_paths:
            return f"protected executable: {exe}"
        return None

    def check_file(self, path: str, sha256: str | None = None) -> str | None:
        if not self.loaded:
            return "safelist unavailable"
        normalized = normalize_path(path)
        if normalized in self.protected_paths:
            return f"protected file: {normalized}"
        for item in self.protected_prefixes:
            if normalized.startswith(item):
                return f"protected directory: {item}"
        if sha256 and sha256.lower() in self.sha256:
            return "file hash is safelisted"
        return None
