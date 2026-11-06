"""Verify signed commands from the server, and run the ones that pass.

Being reachable from the server is not authority. A command must carry a valid Ed25519
signature, name this agent, be in date, and not have been seen before. The actuators then
apply their own checks against live state.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .actuators.file_quarantine import FileQuarantine
from .actuators.process_terminator import ActionResult, terminate_process
from .safelist import AgentSafelist

log = logging.getLogger(__name__)
MAX_FUTURE_SKEW_SECONDS = 300


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def verify_signature(public_key_b64: str, envelope: dict[str, Any]) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64))
        key.verify(_b64d(envelope["signature"]), canonical_json(envelope["command"]))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


class ReplayGuard:
    """Remembers command IDs on disk, so a restart can't reopen the replay window."""

    def __init__(self, state_dir: str | Path):
        self._path = Path(state_dir) / "seen_commands.json"
        self._seen: dict[str, float] = {}
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("replay state is not an object")
            self._seen = {str(k): float(v) for k, v in loaded.items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError):
            log.warning("Replay state unreadable: starting fresh; expiry still bounds replay")

    def first_time(self, command_id: str, expires_at: float) -> bool:
        now = time.time()
        self._seen = {k: v for k, v in self._seen.items() if v > now}
        if command_id in self._seen:
            return False
        self._seen[command_id] = expires_at
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._seen), encoding="utf-8")
        os.replace(tmp, self._path)
        return True


@dataclass
class CommandOutcome:
    command_id: str
    result: ActionResult


class CommandExecutor:
    def __init__(
        self,
        agent_id: str,
        public_key: str,
        safelist: AgentSafelist,
        quarantine: FileQuarantine,
        replay: ReplayGuard,
        actuators_enabled: bool = False,
        terminate_grace_seconds: float = 3.0,
    ):
        self.agent_id = agent_id
        self.public_key = public_key
        self.safelist = safelist
        self.quarantine = quarantine
        self.replay = replay
        self.actuators_enabled = actuators_enabled
        self.grace = terminate_grace_seconds
        self.rejected_signatures = 0

    def handle(self, envelope: dict[str, Any]) -> CommandOutcome | None:
        """Returns None for anything unauthenticated, which gets no reply at all."""
        if not verify_signature(self.public_key, envelope):
            self.rejected_signatures += 1
            log.error("Rejected a command with an invalid signature")
            return None
        command = envelope["command"]
        command_id = str(command.get("command_id", ""))
        if command.get("agent_id") != self.agent_id:
            log.error("Rejected command %s addressed to another agent", command_id)
            return None

        now = time.time()
        expires_at = command.get("expires_at")
        issued_at = command.get("issued_at")
        if not isinstance(expires_at, (int, float)) or not isinstance(issued_at, (int, float)):
            return CommandOutcome(command_id, ActionResult("refused", "malformed timestamps"))
        if expires_at < now:
            return CommandOutcome(command_id, ActionResult("refused", "command expired"))
        if issued_at > now + MAX_FUTURE_SKEW_SECONDS:
            return CommandOutcome(command_id, ActionResult("refused", "command issued in the future"))
        if not self.replay.first_time(command_id, expires_at):
            log.error("Rejected replayed command %s", command_id)
            return None

        if not self.actuators_enabled:
            return CommandOutcome(command_id, ActionResult("refused", "actuators are disabled on this agent"))

        action = command.get("action")
        target = command.get("target")
        if not isinstance(target, dict):
            return CommandOutcome(command_id, ActionResult("refused", "malformed target"))
        try:
            if action == "terminate_process":
                result = terminate_process(target, self.safelist, self.grace)
            elif action == "quarantine_file":
                result = self.quarantine.quarantine(target)
            else:
                result = ActionResult("refused", f"unsupported action: {str(action)[:64]}")
        except Exception as exc:
            log.exception("Actuator crashed on command %s", command_id)
            result = ActionResult("failed", f"actuator error: {type(exc).__name__}")
        return CommandOutcome(command_id, result)
