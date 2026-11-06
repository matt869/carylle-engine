"""Decide how much of a model verdict Carylle will believe.

Assume the model may have been manipulated by the telemetry it read. Output is checked
structurally and bound to observed evidence, so a hijacked verdict cannot:

- name a target that was not observed
- cite an ATT&CK technique that does not exist
- clear activity the deterministic rules rated high
- drop the deterministic containment recommendations

If the output cannot be trusted at all, validation fails and the case falls back to the
deterministic scorer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ...models import (
    ActionType,
    Classification,
    EventType,
    NormalizedEvent,
    RecommendedAction,
    Severity,
    Verdict,
)
from .fallback_scorer import Assessment
from .mitre_mapper import MitreMapper
from .sanitizer import SanitizedCase, redact_secrets, strip_invisible

MAX_SUMMARY = 2000
MAX_RATIONALE = 500


class _RawAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["terminate_process", "quarantine_file"]
    evidence_ref: str
    rationale: str = ""


class _RawVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    techniques: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[_RawAction] = Field(default_factory=list)
    injection_suspected: bool = False


@dataclass
class ValidationOutcome:
    verdict: Verdict | None
    issues: list[str] = field(default_factory=list)


def _clean_text(text: str, limit: int) -> str:
    # Model output echoes telemetry, and it ends up in operator views and the ledger.
    redacted, _ = redact_secrets(text)
    return strip_invisible(redacted)[:limit]


def supports_action(event: NormalizedEvent, action: ActionType) -> bool:
    """An action needs enough identity on the event to bind it to one real target."""
    if action is ActionType.TERMINATE_PROCESS:
        return (
            event.type is EventType.PROCESS_START
            and event.process is not None
            and event.process.create_time is not None
            and event.process.pid > 0
        )
    if action is ActionType.QUARANTINE_FILE:
        if event.type is EventType.YARA_MATCH and event.yara:
            return bool(event.yara.path and event.yara.sha256)
        if event.type is EventType.FILE_EVENT and event.file:
            return bool(event.file.sha256 and (event.file.dest_path or event.file.path))
    return False


def validate_verdict(
    raw: dict,
    *,
    sanitized: SanitizedCase,
    events: list[NormalizedEvent],
    assessment: Assessment,
    mapper: MitreMapper,
    model: str | None = None,
) -> ValidationOutcome:
    try:
        parsed = _RawVerdict.model_validate(raw)
    except ValidationError as exc:
        return ValidationOutcome(None, [f"schema violation: {exc.error_count()} errors"])

    issues: list[str] = []
    by_id = {e.event_id: e for e in events}

    if parsed.classification is Classification.BENIGN and parsed.severity.rank >= Severity.HIGH.rank:
        return ValidationOutcome(None, ["incoherent verdict: benign with high severity"])

    evidence_ids: list[str] = []
    for ref in parsed.evidence:
        event_id = sanitized.ref_to_event_id.get(ref)
        if event_id is None:
            issues.append(f"evidence ref not in case: {ref[:16]!r}")
        elif event_id not in evidence_ids:
            evidence_ids.append(event_id)
    if parsed.classification is not Classification.BENIGN and not evidence_ids:
        return ValidationOutcome(None, [*issues, "non-benign verdict with no valid evidence"])

    actions: list[RecommendedAction] = []
    seen: set[tuple[str, str]] = set()
    for item in parsed.recommended_actions:
        event_id = sanitized.ref_to_event_id.get(item.evidence_ref)
        if event_id is None:
            issues.append(f"action ref not in case: {item.evidence_ref[:16]!r}")
            continue
        action = ActionType(item.action)
        if not supports_action(by_id[event_id], action):
            issues.append(f"{item.evidence_ref} cannot support {item.action}")
            continue
        if (action, event_id) not in seen:
            seen.add((action, event_id))
            actions.append(
                RecommendedAction(
                    action=action, event_id=event_id, rationale=_clean_text(item.rationale, MAX_RATIONALE)
                )
            )

    techniques, invalid = mapper.filter_valid(parsed.techniques)
    issues += [f"unknown technique dropped: {t}" for t in invalid]

    classification = parsed.classification
    severity = parsed.severity
    confidence = parsed.confidence
    floor_applied = False

    # Deterministic floor: the model can add context or lower a weak signal, but it
    # cannot clear activity the rules independently rate high.
    if assessment.severity.rank >= Severity.HIGH.rank:
        if severity.rank < assessment.severity.rank:
            severity = assessment.severity
            floor_applied = True
        if classification.rank < assessment.classification.rank:
            classification = assessment.classification
            floor_applied = True
        if floor_applied:
            issues.append("model rated below the deterministic floor; floor applied")
            confidence = max(confidence, assessment.score)
        for rec in assessment.recommended_actions():
            event = by_id.get(rec.event_id)
            if event is None:
                issues.append(f"deterministic evidence {rec.event_id[:16]!r} is outside the case window")
                continue
            if supports_action(event, rec.action) and (rec.action, rec.event_id) not in seen:
                seen.add((rec.action, rec.event_id))
                actions.append(rec)
        for technique in assessment.techniques:
            if mapper.exists(technique) or not mapper.loaded:
                if technique not in techniques:
                    techniques.append(technique)
        for event_id in assessment.event_ids:
            if event_id not in evidence_ids:
                evidence_ids.append(event_id)

    injection_signals = sorted(set(sanitized.injection_signals) | set(assessment.injection_signals))
    injection = bool(injection_signals) or parsed.injection_suspected

    # The model disagreed with strong rules and nothing suggests it was manipulated.
    # That is a plausible false positive, so a person should look before anything runs.
    #
    # With injection indicators present the model's dissent is discounted instead, and
    # deterministic containment stays eligible. Otherwise an attacker could switch off
    # autonomous response just by adding "ignore previous instructions" to a command line.
    # Model-only recommendations still cannot run unattended: guardrails require the
    # target itself to be deterministically flagged.
    requires_human = floor_applied and not injection

    if injection and classification is Classification.BENIGN:
        classification = Classification.SUSPICIOUS
        if severity.rank < Severity.MEDIUM.rank:
            severity = Severity.MEDIUM
        floor_applied = True
        issues.append("injection indicators present; benign verdict not accepted")

    if classification is Classification.BENIGN:
        actions = []

    return ValidationOutcome(
        Verdict(
            classification=classification,
            severity=severity,
            confidence=round(confidence, 4),
            summary=_clean_text(parsed.summary, MAX_SUMMARY),
            techniques=techniques,
            evidence_event_ids=evidence_ids,
            recommended_actions=actions,
            source="llm",
            model=model,
            deterministic_score=assessment.score,
            matched_rules=assessment.rule_ids,
            deterministic_event_ids=assessment.event_ids,
            injection_suspected=injection,
            injection_signals=injection_signals,
            floor_applied=floor_applied,
            requires_human=requires_human,
            validation_issues=issues,
        ),
        issues,
    )
