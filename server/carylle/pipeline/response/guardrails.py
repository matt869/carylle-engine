"""The policy layer between a verdict and an endpoint action. No model input can change it.

Checks fail closed: anything unproven or unparseable becomes a denial or a request for a
human, never an automatic action.

  DENY              never run, an operator cannot override (safelist, malformed target)
  SIMULATE          observe mode: record what would have happened
  REQUIRE_APPROVAL  hold for an operator
  ALLOW             run unattended (autonomous mode only, every check passed)
"""

from __future__ import annotations

import ntpath
import posixpath
import re
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from ...config import ResponseSettings
from ...models import ENDPOINT_ACTIONS, ActionType, Severity, Verdict
from ...store import Store

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
VALID_MODES = {"observe", "approve", "autonomous"}


class Outcome(StrEnum):
    DENY = "deny"
    SIMULATE = "simulate"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW = "allow"


@dataclass
class Decision:
    outcome: Outcome
    reasons: list[str] = field(default_factory=list)


def _is_windows_path(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", path)) or path.startswith("\\\\")


def normalize_path(path: str) -> str:
    """Collapse ".." and case-fold Windows paths, so traversal can't dodge a prefix check."""
    if _is_windows_path(path):
        return ntpath.normcase(ntpath.normpath(path))
    return posixpath.normpath(path)


def _is_absolute(path: str) -> bool:
    return path.startswith("/") or _is_windows_path(path)


@dataclass
class Safelist:
    hosts: set[str] = field(default_factory=set)
    exe_paths: set[str] = field(default_factory=set)
    min_pid: int = 3
    protected_prefixes: list[str] = field(default_factory=list)
    protected_paths: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path) -> Safelist:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        processes = raw.get("processes") or {}
        files = raw.get("files") or {}

        def prefix(p: str) -> str:
            # normpath strips the trailing separator that stops /lib matching /library.
            sep = "\\" if _is_windows_path(p) else "/"
            return normalize_path(p).rstrip(sep) + sep

        return cls(
            hosts=set(raw.get("hosts") or []),
            exe_paths={normalize_path(p) for p in processes.get("exe_paths") or []},
            min_pid=int(processes.get("min_pid", 3)),
            protected_prefixes=[prefix(p) for p in files.get("protected_prefixes") or []],
            protected_paths={normalize_path(p) for p in files.get("protected_paths") or []},
            sha256={s.lower() for s in files.get("sha256") or []},
        )

    def check_process(self, target: dict[str, Any]) -> str | None:
        if int(target.get("pid", 0)) < self.min_pid:
            return f"pid below protected minimum {self.min_pid}"
        exe = target.get("exe") or ""
        if exe and normalize_path(exe) in self.exe_paths:
            return f"protected executable: {exe}"
        return None

    def check_file(self, target: dict[str, Any]) -> str | None:
        path = normalize_path(target.get("path") or "")
        if path in self.protected_paths:
            return f"protected file: {path}"
        for prefix in self.protected_prefixes:
            if path.startswith(prefix):
                return f"protected directory: {prefix}"
        if (target.get("sha256") or "").lower() in self.sha256:
            return "file hash is safelisted"
        return None


def validate_target(action: ActionType, target: dict[str, Any]) -> str | None:
    """A target must identify one specific thing. PID or path alone can be reused or swapped."""
    if action is ActionType.TERMINATE_PROCESS:
        pid = target.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return "terminate_process target has no valid pid"
        if not isinstance(target.get("create_time"), (int, float)):
            return "terminate_process target has no create_time, so PID reuse can't be ruled out"
        return None
    if action is ActionType.QUARANTINE_FILE:
        path = target.get("path")
        if not isinstance(path, str) or not path or not _is_absolute(path):
            return "quarantine_file target has no absolute path"
        if not _SHA256.match(str(target.get("sha256") or "")):
            return "quarantine_file target has no sha256, so a swapped file can't be ruled out"
        return None
    return f"{action} is not an endpoint action"


class Guardrails:
    def __init__(self, settings: ResponseSettings, safelist: Safelist, store: Store):
        self.settings = settings
        self.safelist = safelist
        self._store = store
        store.set_meta_if_absent("response_mode", settings.mode)

    @property
    def mode(self) -> str:
        mode = self._store.get_meta("response_mode") or "approve"
        # Fail closed on a corrupted setting: observe can't change anything.
        return mode if mode in VALID_MODES else "observe"

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"unknown mode: {mode}")
        self._store.set_meta("response_mode", mode)

    def hard_blocks(self, action: ActionType, target: dict[str, Any], host: str) -> list[str]:
        """Reasons an action must never run. Approval re-runs these, so no operator can bypass them."""
        if action not in ENDPOINT_ACTIONS:
            return [f"{action} is not an endpoint action"]
        reasons: list[str] = []
        if (problem := validate_target(action, target)) is not None:
            reasons.append(problem)
            return reasons
        if host in self.safelist.hosts:
            reasons.append(f"host is safelisted: {host}")
        problem = (
            self.safelist.check_process(target)
            if action is ActionType.TERMINATE_PROCESS
            else self.safelist.check_file(target)
        )
        if problem:
            reasons.append(problem)
        return reasons

    def _rate_limit_reasons(self, host: str, now: float) -> list[str]:
        s = self.settings
        reasons = []
        host_count = self._store.count_executed_actions(now - 3600, host)
        if host_count >= s.max_actions_per_host_per_hour:
            reasons.append(f"host action limit reached ({host_count}/{s.max_actions_per_host_per_hour} per hour)")
        total = self._store.count_executed_actions(now - 3600)
        if total >= s.max_actions_per_hour:
            reasons.append(f"fleet action limit reached ({total}/{s.max_actions_per_hour} per hour)")
        hosts = self._store.count_hosts_with_actions(now - 600)
        if hosts >= s.max_hosts_per_10min:
            reasons.append(f"blast radius limit reached ({hosts}/{s.max_hosts_per_10min} hosts in 10 minutes)")
        return reasons

    def evaluate(
        self,
        action: ActionType,
        target: dict[str, Any],
        verdict: Verdict,
        *,
        host: str,
        evidence_event_id: str,
        playbook_requires_approval: bool = False,
        now: float | None = None,
    ) -> Decision:
        now = time.time() if now is None else now

        blocks = self.hard_blocks(action, target, host)
        if blocks:
            return Decision(Outcome.DENY, blocks)

        mode = self.mode
        if mode == "observe":
            return Decision(Outcome.SIMULATE, ["observe mode"])

        s = self.settings
        holds: list[str] = []
        if mode == "approve":
            holds.append("approve mode")
        if playbook_requires_approval:
            holds.append("playbook requires approval")
        if verdict.requires_human:
            holds.append("model disagreed with deterministic rules")

        # Autonomy needs independent evidence about this exact target. Model output alone
        # never qualifies, because the model reads attacker-controlled text.
        if evidence_event_id not in verdict.deterministic_event_ids:
            holds.append("target was not flagged by deterministic rules")
        if verdict.deterministic_score < s.min_deterministic_score:
            holds.append(
                f"deterministic score {verdict.deterministic_score:.2f} below {s.min_deterministic_score:.2f}"
            )
        # Rules alone are enough once corroborated, so a model nudged into low confidence
        # cannot hold up containment that would run with the model switched off.
        confidence = max(verdict.confidence, verdict.deterministic_score)
        if confidence < s.min_autonomous_confidence:
            holds.append(f"confidence {confidence:.2f} below {s.min_autonomous_confidence:.2f}")
        minimum = Severity(s.min_autonomous_severity)
        if verdict.severity.rank < minimum.rank:
            holds.append(f"severity {verdict.severity} below {minimum}")
        holds.extend(self._rate_limit_reasons(host, now))

        if holds:
            return Decision(Outcome.REQUIRE_APPROVAL, holds)
        return Decision(Outcome.ALLOW, ["all autonomous checks passed"])
