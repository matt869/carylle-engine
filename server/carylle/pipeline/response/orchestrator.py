"""Turn verdicts into actions and take each action through its lifecycle.

Targets are built here from stored evidence, and never from model text. Every state
change goes to the ledger, and transitions are compare-and-set so two callers cannot
both approve, or both dispatch, the same action.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ...config import ResponseSettings
from ...models import ActionState, ActionType, Classification, EventType, NormalizedEvent, Severity, Verdict
from ...security import CommandSigner, canonical_json
from ...store import Store
from .action_ledger import ActionLedger
from .guardrails import Guardrails, Outcome

log = logging.getLogger(__name__)


@dataclass
class PlaybookAction:
    type: ActionType
    requires_approval: bool = False


@dataclass
class Playbook:
    id: str
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.INFO
    actions: list[PlaybookAction] = field(default_factory=list)

    def matches(self, verdict: Verdict) -> bool:
        if verdict.severity.rank < self.min_severity.rank:
            return False
        if not self.techniques and not self.rules:
            return True
        if any(rule in verdict.matched_rules for rule in self.rules):
            return True
        # Exact or parent match: T1059 covers T1059.004, but T10 does not cover T1059.
        return any(
            t == prefix or t.startswith(f"{prefix}.")
            for t in verdict.techniques
            for prefix in self.techniques
        )

    def action(self, action_type: ActionType) -> PlaybookAction | None:
        return next((a for a in self.actions if a.type is action_type), None)


def load_playbooks(path: str | Path) -> list[Playbook]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    playbooks = []
    for item in raw.get("playbooks") or []:
        match = item.get("match") or {}
        playbooks.append(
            Playbook(
                id=item["id"],
                description=item.get("description", ""),
                techniques=match.get("techniques") or [],
                rules=match.get("rules") or [],
                min_severity=Severity(match.get("min_severity", "info")),
                actions=[
                    PlaybookAction(ActionType(a["type"]), bool(a.get("requires_approval")))
                    for a in item.get("actions") or []
                ],
            )
        )
    if not playbooks:
        raise ValueError(f"no playbooks defined in {path}")
    return playbooks


def build_target(action: ActionType, event: NormalizedEvent) -> dict[str, Any] | None:
    """Derive a target from observed evidence. Returns None when the event can't support it."""
    if action is ActionType.TERMINATE_PROCESS:
        if event.type is not EventType.PROCESS_START or not event.process:
            return None
        p = event.process
        return {"pid": p.pid, "create_time": p.create_time, "exe": p.exe, "name": p.name, "sha256": p.sha256}
    if action is ActionType.QUARANTINE_FILE:
        if event.type is EventType.YARA_MATCH and event.yara:
            return {"path": event.yara.path, "sha256": event.yara.sha256}
        if event.type is EventType.FILE_EVENT and event.file:
            return {"path": event.file.dest_path or event.file.path, "sha256": event.file.sha256}
    return None


def _dedupe_key(agent_id: str, action: ActionType, target: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json([agent_id, action.value, target])).hexdigest()


class ActionError(Exception):
    """A requested transition is not possible. The message is safe to show the operator."""


class Orchestrator:
    def __init__(
        self,
        store: Store,
        ledger: ActionLedger,
        guardrails: Guardrails,
        playbooks: list[Playbook],
        signer: CommandSigner,
        settings: ResponseSettings,
    ):
        self.store = store
        self.ledger = ledger
        self.guardrails = guardrails
        self.playbooks = playbooks
        self.signer = signer
        self.settings = settings

    def select_playbook(self, verdict: Verdict) -> Playbook | None:
        return next((p for p in self.playbooks if p.matches(verdict)), None)

    def respond(
        self, case_id: str, agent_id: str, verdict: Verdict, events: list[NormalizedEvent]
    ) -> list[dict[str, Any]]:
        """Create the actions for a case. Returns the created action records."""
        playbook = self.select_playbook(verdict)
        if playbook is None:
            self.ledger.append("no_playbook", {"case_id": case_id})
            return []
        self.store.set_case_playbook(case_id, playbook.id)

        created: list[dict[str, Any]] = []
        now = time.time()

        if verdict.classification is not Classification.BENIGN and playbook.action(ActionType.NOTIFY):
            created.append(
                self._create(
                    case_id, agent_id, ActionType.NOTIFY, {}, ActionState.NOTIFIED, playbook.id,
                    ["surfaced for review"], now, None,
                )
            )

        by_id = {e.event_id: e for e in events}
        for rec in verdict.recommended_actions:
            playbook_action = playbook.action(rec.action)
            event = by_id.get(rec.event_id)
            if playbook_action is None or event is None:
                self.ledger.append(
                    "action_not_permitted",
                    {"case_id": case_id, "action": rec.action, "playbook": playbook.id, "event_id": rec.event_id},
                )
                continue
            target = build_target(rec.action, event)
            if target is None:
                self.ledger.append(
                    "action_no_target", {"case_id": case_id, "action": rec.action, "event_id": rec.event_id}
                )
                continue
            if self.store.open_action_exists(_dedupe_key(agent_id, rec.action, target)):
                continue

            decision = self.guardrails.evaluate(
                rec.action,
                target,
                verdict,
                host=agent_id,
                evidence_event_id=rec.event_id,
                playbook_requires_approval=playbook_action.requires_approval,
                now=now,
            )
            if decision.outcome is Outcome.DENY:
                state, expires = ActionState.DENIED, None
            elif decision.outcome is Outcome.SIMULATE:
                state, expires = ActionState.SIMULATED, None
            elif decision.outcome is Outcome.REQUIRE_APPROVAL:
                state, expires = ActionState.PENDING_APPROVAL, now + self.settings.approval_ttl_seconds
            else:
                state, expires = ActionState.APPROVED, now + self.settings.command_ttl_seconds
            created.append(
                self._create(
                    case_id, agent_id, rec.action, target, state, playbook.id, decision.reasons, now,
                    expires, decided_by="guardrails" if state is ActionState.APPROVED else None,
                )
            )
        return created

    def _create(
        self,
        case_id: str,
        agent_id: str,
        action: ActionType,
        target: dict[str, Any],
        state: ActionState,
        playbook_id: str,
        reasons: list[str],
        now: float,
        expires_at: float | None,
        decided_by: str | None = None,
    ) -> dict[str, Any]:
        record = {
            "action_id": f"act_{uuid.uuid4().hex}",
            "case_id": case_id,
            "agent_id": agent_id,
            "type": action.value,
            "target": target,
            "dedupe_key": _dedupe_key(agent_id, action, target)
            if action is not ActionType.NOTIFY
            else f"notify:{case_id}",
            "state": state.value,
            "playbook_id": playbook_id,
            "reasons": reasons,
            "created_at": now,
            "updated_at": now,
            "expires_at": expires_at,
            "decided_by": decided_by,
        }
        self.store.insert_action(record)
        self.ledger.append(
            "action_decided",
            {
                "action_id": record["action_id"],
                "case_id": case_id,
                "agent_id": agent_id,
                "type": action.value,
                "target": target,
                "state": state.value,
                "playbook": playbook_id,
                "reasons": reasons,
            },
        )
        return record

    def approve(self, action_id: str, operator: str) -> dict[str, Any]:
        action = self.store.get_action(action_id)
        if action is None:
            raise ActionError("action not found")
        if action["state"] != ActionState.PENDING_APPROVAL:
            raise ActionError(f"action is {action['state']}, not pending approval")
        now = time.time()
        if action["expires_at"] and action["expires_at"] < now:
            self._expire(action)
            raise ActionError("approval window has expired")

        # The safelist may have changed since this was queued, and operators can't override it.
        blocks = self.guardrails.hard_blocks(ActionType(action["type"]), action["target"], action["agent_id"])
        if blocks:
            self.store.transition_action(action_id, [ActionState.PENDING_APPROVAL], ActionState.DENIED)
            self.ledger.append("approval_blocked", {"action_id": action_id, "operator": operator, "reasons": blocks})
            raise ActionError(f"blocked by safelist: {'; '.join(blocks)}")
        if self.guardrails.mode == "observe":
            raise ActionError("response mode is observe; switch mode before approving actions")

        if not self.store.transition_action(
            action_id,
            [ActionState.PENDING_APPROVAL],
            ActionState.APPROVED,
            decided_by=operator,
            expires_at=now + self.settings.command_ttl_seconds,
        ):
            raise ActionError("action was changed by another request")
        self.ledger.append("action_approved", {"action_id": action_id, "operator": operator})
        return self.store.get_action(action_id)  # type: ignore[return-value]

    def reject(self, action_id: str, operator: str, note: str = "") -> dict[str, Any]:
        if not self.store.transition_action(
            action_id, [ActionState.PENDING_APPROVAL], ActionState.REJECTED, decided_by=operator
        ):
            raise ActionError("action is not pending approval")
        self.ledger.append("action_rejected", {"action_id": action_id, "operator": operator, "note": note[:500]})
        return self.store.get_action(action_id)  # type: ignore[return-value]

    def dispatch(self, agent_id: str) -> list[dict[str, Any]]:
        """Sign and hand over approved commands for this agent. Each is issued at most once."""
        self.expire_stale()
        if self.guardrails.mode == "observe":
            # Observe mode doubles as a kill switch for anything already approved.
            return []
        envelopes = []
        now = time.time()
        for action in self.store.approved_actions_for(agent_id):
            # Re-check: the safelist can change while a command waits for collection.
            blocks = self.guardrails.hard_blocks(ActionType(action["type"]), action["target"], agent_id)
            if blocks:
                self.store.transition_action(action["action_id"], [ActionState.APPROVED], ActionState.DENIED)
                self.ledger.append("dispatch_blocked", {"action_id": action["action_id"], "reasons": blocks})
                continue
            expires_at = now + self.settings.command_ttl_seconds
            if not self.store.transition_action(
                action["action_id"], [ActionState.APPROVED], ActionState.DISPATCHED, expires_at=expires_at
            ):
                continue
            command = {
                "command_id": action["action_id"],
                "agent_id": agent_id,
                "action": action["type"],
                "target": action["target"],
                "issued_at": now,
                "expires_at": expires_at,
                "nonce": secrets.token_hex(16),
            }
            envelopes.append(self.signer.sign(command))
            self.ledger.append(
                "command_dispatched", {"action_id": action["action_id"], "agent_id": agent_id, "expires_at": expires_at}
            )
        return envelopes

    def record_result(self, agent_id: str, action_id: str, status: str, detail: str) -> dict[str, Any]:
        action = self.store.get_action(action_id)
        # Same answer for "absent" and "another agent's", so IDs can't be probed.
        if action is None or action["agent_id"] != agent_id:
            raise ActionError("command not found")
        states = {
            "succeeded": ActionState.SUCCEEDED,
            "failed": ActionState.FAILED,
            "refused": ActionState.REFUSED,
        }
        if status not in states:
            raise ActionError("unknown result status")
        # A result can arrive after the TTL if the agent was slow, and the outcome still matters.
        if not self.store.transition_action(
            action_id,
            [ActionState.DISPATCHED, ActionState.EXPIRED],
            states[status],
            result={"status": status, "detail": detail[:2000]},
        ):
            raise ActionError(f"command is {action['state']}, not awaiting a result")
        self.ledger.append(
            "command_result",
            {"action_id": action_id, "agent_id": agent_id, "status": status, "detail": detail[:2000]},
        )
        return self.store.get_action(action_id)  # type: ignore[return-value]

    def _expire(self, action: dict[str, Any]) -> None:
        if self.store.transition_action(
            action["action_id"],
            [ActionState.PENDING_APPROVAL, ActionState.APPROVED, ActionState.DISPATCHED],
            ActionState.EXPIRED,
        ):
            self.ledger.append("action_expired", {"action_id": action["action_id"], "was": action["state"]})

    def expire_stale(self) -> int:
        stale = self.store.expirable_actions(time.time())
        for action in stale:
            self._expire(action)
        return len(stale)
