"""Shared data model for the server pipeline."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Classification(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def rank(self) -> int:
        return ["benign", "suspicious", "malicious"].index(self.value)


class ActionType(StrEnum):
    NOTIFY = "notify"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"


ENDPOINT_ACTIONS = {ActionType.TERMINATE_PROCESS, ActionType.QUARANTINE_FILE}


class ActionState(StrEnum):
    NOTIFIED = "notified"  # no endpoint effect, surfaced for review
    SIMULATED = "simulated"  # observe mode: recorded what would have happened
    DENIED = "denied"  # blocked by guardrails, cannot be approved
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"  # waiting for the agent to collect it
    DISPATCHED = "dispatched"  # handed to the agent, result outstanding
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"  # the agent's local checks declined it
    REJECTED = "rejected"  # an operator said no
    EXPIRED = "expired"


class EventType(StrEnum):
    PROCESS_START = "process_start"
    FILE_EVENT = "file_event"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    YARA_MATCH = "yara_match"
    AGENT_HEALTH = "agent_health"


class ProcessInfo(BaseModel):
    pid: int
    ppid: int | None = None
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    user: str = ""
    create_time: float | None = None
    sha256: str | None = None
    parent_name: str = ""
    parent_exe: str = ""


class FileInfo(BaseModel):
    path: str
    action: str = ""
    sha256: str | None = None
    size: int | None = None
    dest_path: str = ""


class NetworkInfo(BaseModel):
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    proto: str = ""
    pid: int | None = None
    process_name: str = ""
    status: str = ""


class DnsInfo(BaseModel):
    qname: str
    qtype: str = ""


class YaraInfo(BaseModel):
    rule: str
    tags: list[str] = Field(default_factory=list)
    severity: str = "medium"
    attack: str = ""
    description: str = ""
    path: str = ""
    sha256: str | None = None
    size: int | None = None


class NormalizedEvent(BaseModel):
    event_id: str
    agent_id: str
    type: EventType
    ts: float
    received_at: float
    process: ProcessInfo | None = None
    file: FileInfo | None = None
    network: NetworkInfo | None = None
    dns: DnsInfo | None = None
    yara: YaraInfo | None = None
    health: dict | None = None


class RecommendedAction(BaseModel):
    action: ActionType
    event_id: str
    rationale: str = ""


class Verdict(BaseModel):
    classification: Classification
    severity: Severity
    confidence: float
    summary: str
    techniques: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    # Provenance. These are set by Carylle's own code, never taken from model output.
    source: str = "fallback"  # "llm" | "fallback"
    model: str | None = None
    fallback_reason: str | None = None
    deterministic_score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    # Events the deterministic rules flagged independently of any model output.
    deterministic_event_ids: list[str] = Field(default_factory=list)
    injection_suspected: bool = False
    injection_signals: list[str] = Field(default_factory=list)
    floor_applied: bool = False
    requires_human: bool = False
    validation_issues: list[str] = Field(default_factory=list)
