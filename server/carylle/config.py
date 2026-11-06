"""Settings from YAML, secrets from the environment. Missing secrets stop the server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ServerSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8443
    db_path: str = "var/carylle.db"
    ledger_anchor_path: str = "var/ledger.anchor"
    mitre_path: str = "data/mitre/enterprise-attack.json"
    safelist_path: str = "config/safelist.yaml"
    playbooks_path: str = "config/playbooks/response_playbooks.yaml"
    allow_plaintext: bool = False
    max_batch_events: int = 500
    max_body_bytes: int = 5 * 1024 * 1024
    revoked_agents: list[str] = Field(default_factory=list)


class PipelineSettings(BaseModel):
    triage_threshold: float = 0.35
    context_window_seconds: int = 300
    max_case_events: int = 40
    llm_cooldown_seconds: int = 300
    burst_window_seconds: int = 60
    burst_file_events: int = 200
    worker_poll_seconds: float = 2.0


class LLMSettings(BaseModel):
    enabled: bool = True
    model: str = "claude-opus-5-5"
    effort: str = "medium"
    max_tokens: int = 8000
    timeout_seconds: float = 60
    max_retries: int = 1
    max_calls_per_minute: int = 20
    breaker_failures: int = 5
    breaker_cooldown_seconds: int = 120
    server_side_fallbacks: bool = True


class ResponseSettings(BaseModel):
    mode: str = "approve"
    min_autonomous_confidence: float = 0.85
    min_autonomous_severity: str = "high"
    min_deterministic_score: float = 0.6
    max_actions_per_host_per_hour: int = 10
    max_actions_per_hour: int = 50
    max_hosts_per_10min: int = 3
    approval_ttl_seconds: int = 3600
    command_ttl_seconds: int = 120


class Settings(BaseModel):
    server: ServerSettings = Field(default_factory=ServerSettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    response: ResponseSettings = Field(default_factory=ResponseSettings)


def _env_bool(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings(path: str | Path | None = None) -> Settings:
    path = Path(path or os.environ.get("CARYLLE_CONFIG", "config/settings.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    raw = raw or {}
    settings = Settings(**{k: raw[k] for k in ("server", "pipeline", "llm", "response") if k in raw})

    if (db_path := os.environ.get("CARYLLE_DB_PATH")):
        settings.server.db_path = db_path
    if (anchor := os.environ.get("CARYLLE_LEDGER_ANCHOR")):
        settings.server.ledger_anchor_path = anchor
    if (host := os.environ.get("CARYLLE_HOST")):
        settings.server.host = host
    if (port := os.environ.get("CARYLLE_PORT")):
        settings.server.port = int(port)
    if (mode := os.environ.get("CARYLLE_RESPONSE_MODE")):
        settings.response.mode = mode
    if (plaintext := _env_bool("CARYLLE_ALLOW_PLAINTEXT")) is not None:
        settings.server.allow_plaintext = plaintext
    if (llm_enabled := _env_bool("CARYLLE_LLM_ENABLED")) is not None:
        settings.llm.enabled = llm_enabled
    return settings


@dataclass(frozen=True)
class Secrets:
    agent_master_secret: str
    operator_token: str
    ledger_key: str
    command_signing_key: str
    command_public_key: str


class MissingSecrets(RuntimeError):
    pass


def load_secrets() -> Secrets:
    names = {
        "agent_master_secret": "CARYLLE_AGENT_MASTER_SECRET",
        "operator_token": "CARYLLE_OPERATOR_TOKEN",
        "ledger_key": "CARYLLE_LEDGER_KEY",
        "command_signing_key": "CARYLLE_COMMAND_SIGNING_KEY",
        "command_public_key": "CARYLLE_COMMAND_PUBLIC_KEY",
    }
    values = {field: os.environ.get(env, "") for field, env in names.items()}
    missing = [names[field] for field, value in values.items() if not value]
    if missing:
        raise MissingSecrets(
            f"Missing required secrets: {', '.join(missing)}. Generate them with: carylle-admin init-env"
        )
    return Secrets(**values)
