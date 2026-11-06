"""Connects the stages: triage, clustering, reasoning, validation, response.

Events are persisted before any processing, and marked processed only afterwards, so a
crash or restart reprocesses them rather than losing them. Action de-duplication makes
that replay safe.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass

from ..config import PipelineSettings
from ..models import EventType, NormalizedEvent, Verdict
from ..store import Store
from .reasoning.fallback_scorer import (
    Assessment,
    assess,
    event_hits,
    is_ransom_extension_event,
    verdict_from_assessment,
)
from .reasoning.llm_client import LLMClient
from .reasoning.mitre_mapper import MitreMapper
from .reasoning.prompts import build_user_prompt
from .reasoning.sanitizer import sanitize_case
from .reasoning.verdict_validator import validate_verdict
from .response.action_ledger import ActionLedger
from .response.orchestrator import Orchestrator

log = logging.getLogger(__name__)


def relation_keys(event: NormalizedEvent) -> set[str]:
    """Identifiers linking events that plausibly belong to the same activity."""
    keys: set[str] = set()
    if event.process:
        keys.add(f"pid:{event.process.pid}")
        if event.process.ppid:
            keys.add(f"pid:{event.process.ppid}")
        if event.process.sha256:
            keys.add(f"sha:{event.process.sha256}")
        if event.process.exe:
            keys.add(f"path:{event.process.exe.lower()}")
    if event.file:
        keys.add(f"path:{event.file.path.lower()}")
        if event.file.dest_path:
            keys.add(f"path:{event.file.dest_path.lower()}")
        if event.file.sha256:
            keys.add(f"sha:{event.file.sha256}")
    if event.yara:
        if event.yara.path:
            keys.add(f"path:{event.yara.path.lower()}")
        if event.yara.sha256:
            keys.add(f"sha:{event.yara.sha256}")
    if event.network and event.network.pid:
        keys.add(f"pid:{event.network.pid}")
    return keys


def cluster_events(events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
    """Union-find over shared identifiers: each cluster becomes one case."""
    parent = list(range(len(events)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[str, int] = {}
    for index, event in enumerate(events):
        keys = relation_keys(event)
        if is_ransom_extension_event(event):
            keys.add("ransom-extension")
        for key in keys:
            if key in seen:
                parent[find(index)] = find(seen[key])
            else:
                seen[key] = index

    groups: dict[int, list[NormalizedEvent]] = defaultdict(list)
    for index, event in enumerate(events):
        groups[find(index)].append(event)
    return list(groups.values())


def case_fingerprint(agent_id: str, assessment: Assessment, events: list[NormalizedEvent]) -> str:
    """Identifies repeated activity. PIDs are left out so a respawn loop has the same print."""
    parts: list[str] = [agent_id, *sorted(assessment.rule_ids)]
    flagged = set(assessment.event_ids)
    for event in events:
        if event.event_id not in flagged:
            continue
        if event.process:
            parts.append(f"{event.process.exe}|{event.process.cmdline}")
        if event.file:
            parts.append(event.file.path)
        if event.yara:
            parts.append(event.yara.path)
    return hashlib.sha256("\x00".join(sorted(set(parts))).encode("utf-8", "replace")).hexdigest()


@dataclass
class ProcessResult:
    events: int = 0
    cases: int = 0
    actions: int = 0


class Engine:
    def __init__(
        self,
        store: Store,
        ledger: ActionLedger,
        orchestrator: Orchestrator,
        llm: LLMClient,
        mapper: MitreMapper,
        settings: PipelineSettings,
    ):
        self.store = store
        self.ledger = ledger
        self.orchestrator = orchestrator
        self.llm = llm
        self.mapper = mapper
        self.settings = settings

    def process_pending(self, limit: int = 1000) -> ProcessResult:
        events = self.store.fetch_unprocessed(limit)
        result = ProcessResult(events=len(events))
        if not events:
            return result

        per_agent: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            per_agent[event.agent_id].append(event)

        for agent_id, agent_events in per_agent.items():
            try:
                self._process_agent(agent_id, agent_events, result)
            except Exception:
                # Fail closed: no response for this batch, but keep the host's next events
                # flowing and leave a record that analysis was lost.
                log.exception("pipeline failure for agent %s", agent_id)
                self.ledger.append(
                    "pipeline_error", {"agent_id": agent_id, "event_ids": [e.event_id for e in agent_events][:200]}
                )
        self.store.mark_processed(events)
        return result

    def _process_agent(self, agent_id: str, events: list[NormalizedEvent], result: ProcessResult) -> None:
        now = time.time()
        burst_count = self.store.count_file_events(agent_id, now - self.settings.burst_window_seconds)
        is_burst = burst_count >= self.settings.burst_file_events

        triggered = [
            e
            for e in events
            if event_hits(e)
            or is_ransom_extension_event(e)
            or (is_burst and e.type is EventType.FILE_EVENT)
        ]
        if not triggered:
            return

        # Renames spread across several agent flushes still count as one mass rename.
        ransom_count = 0
        if any(is_ransom_extension_event(e) for e in triggered):
            recent = self.store.recent_events(agent_id, now - self.settings.burst_window_seconds)
            ransom_count = sum(1 for e in recent if is_ransom_extension_event(e))

        for cluster in cluster_events(triggered):
            assessment = assess(cluster, burst_count, self.settings.burst_file_events, ransom_count)
            if assessment.score < self.settings.triage_threshold:
                continue
            created = self._open_case(agent_id, cluster, assessment, burst_count if is_burst else 0, now)
            result.cases += 1
            result.actions += created

    def _context(
        self, agent_id: str, trigger: list[NormalizedEvent], priority: list[str], now: float
    ) -> list[NormalizedEvent]:
        """Priority events first, then the rest of the trigger, then related history.

        The cap must never push out the reason the case exists. A rule hit on an event
        that didn't make the cut would recommend an action on a target the case can't
        name, and containment would silently not happen.
        """
        cap = self.settings.max_case_events
        rank = {event_id: i for i, event_id in enumerate(priority)}
        ordered = sorted(trigger, key=lambda e: rank.get(e.event_id, len(rank)))
        selected = ordered[:cap]
        keys = set().union(*(relation_keys(e) for e in selected)) if selected else set()
        seen = {e.event_id for e in selected}
        since = now - self.settings.context_window_seconds
        for event in self.store.recent_events(agent_id, since):
            if len(selected) >= cap:
                break
            if event.event_id not in seen and relation_keys(event) & keys:
                selected.append(event)
                seen.add(event.event_id)
        return sorted(selected, key=lambda e: (e.ts, e.event_id))

    def _reason(
        self, agent_id: str, events: list[NormalizedEvent], assessment: Assessment, burst: int, fingerprint: str, now: float
    ) -> Verdict:
        if self.store.llm_recently_used(fingerprint, now - self.settings.llm_cooldown_seconds):
            # Repeat activity skips the model to control cost. It still gets a verdict and
            # a response, or a respawn loop would run free for the whole cooldown.
            return verdict_from_assessment(assessment, "llm_cooldown", self.mapper)

        sanitized = sanitize_case(events)
        prompt = build_user_prompt(sanitized, agent_id, assessment.findings(sanitized.event_id_to_ref), burst)
        response = self.llm.analyze(prompt)
        if response.status != "ok" or response.data is None:
            reason = f"llm_{response.status}" + (f":{response.detail}" if response.detail else "")
            return verdict_from_assessment(assessment, reason, self.mapper)

        outcome = validate_verdict(
            response.data,
            sanitized=sanitized,
            events=events,
            assessment=assessment,
            mapper=self.mapper,
            model=response.model,
        )
        if outcome.verdict is None:
            log.warning("model verdict rejected: %s", outcome.issues)
            verdict = verdict_from_assessment(assessment, "llm_verdict_rejected", self.mapper)
            verdict.validation_issues = [*verdict.validation_issues, *outcome.issues]
            return verdict
        return outcome.verdict

    def _open_case(
        self, agent_id: str, trigger: list[NormalizedEvent], assessment: Assessment, burst: int, now: float
    ) -> int:
        # Action targets first, strongest rule first, then everything else the rules flagged.
        priority = list(dict.fromkeys([r.event_id for r in assessment.recommended_actions()] + assessment.event_ids))
        events = self._context(agent_id, trigger, priority, now)
        fingerprint = case_fingerprint(agent_id, assessment, trigger)
        verdict = self._reason(agent_id, events, assessment, burst, fingerprint, now)

        # Hold the store lock so API readers never see a case without its actions.
        # The LLM call above stays outside it, or a slow model would stall the whole API.
        with self.store.lock:
            case_id = f"case_{uuid.uuid4().hex}"
            self.store.insert_case(
                {
                    "case_id": case_id,
                    "agent_id": agent_id,
                    "created_at": now,
                    "severity": verdict.severity.value,
                    "classification": verdict.classification.value,
                    "confidence": verdict.confidence,
                    "source": verdict.source,
                    "fingerprint": fingerprint,
                    "playbook_id": None,
                    "verdict": verdict.model_dump_json(),
                    "event_ids": json.dumps([e.event_id for e in events]),
                }
            )
            self.ledger.append(
                "verdict",
                {
                    "case_id": case_id,
                    "agent_id": agent_id,
                    "classification": verdict.classification.value,
                    "severity": verdict.severity.value,
                    "confidence": verdict.confidence,
                    "source": verdict.source,
                    "model": verdict.model,
                    "fallback_reason": verdict.fallback_reason,
                    "rules": verdict.matched_rules,
                    "techniques": verdict.techniques,
                    "injection_signals": verdict.injection_signals,
                    "floor_applied": verdict.floor_applied,
                    "issues": verdict.validation_issues,
                },
            )
            return len(self.orchestrator.respond(case_id, agent_id, verdict, events))
