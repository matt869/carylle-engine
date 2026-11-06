"""Agent configuration: the agent section of settings.yaml, with secrets from the environment."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(RuntimeError):
    pass


@dataclass
class AgentConfig:
    agent_id: str
    token: str
    command_public_key: str
    server_url: str
    verify_tls: bool | str = True
    allow_insecure_http: bool = False
    safelist_path: str = "config/safelist.yaml"
    flush_interval_seconds: float = 2.0
    command_poll_seconds: float = 5.0
    heartbeat_seconds: float = 30.0
    max_batch_events: int = 200
    queue_size: int = 10000
    spool_dir: str = "var/spool"
    spool_max_bytes: int = 100 * 1024 * 1024
    state_dir: str = "var/agent"
    actuators_enabled: bool = False
    quarantine_dir: str = "var/quarantine"
    terminate_grace_seconds: float = 3.0
    sensors: dict[str, Any] = field(default_factory=dict)
    yara: dict[str, Any] = field(default_factory=dict)


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config(path: str | Path | None = None) -> AgentConfig:
    path = Path(path or os.environ.get("CARYLLE_CONFIG", "config/settings.yaml"))
    raw = {}
    if path.exists():
        raw = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("agent") or {}

    token = os.environ.get("CARYLLE_AGENT_TOKEN", "")
    public_key = os.environ.get("CARYLLE_COMMAND_PUBLIC_KEY", "")
    missing = [
        name
        for name, value in (("CARYLLE_AGENT_TOKEN", token), ("CARYLLE_COMMAND_PUBLIC_KEY", public_key))
        if not value
    ]
    if missing:
        raise ConfigError(f"Missing required settings: {', '.join(missing)}")

    verify_tls = raw.get("verify_tls", True)
    if (ca_bundle := os.environ.get("CARYLLE_CA_BUNDLE")):
        verify_tls = ca_bundle

    sensors = raw.get("sensors") or {}
    if (paths := os.environ.get("CARYLLE_WATCH_PATHS")):
        sensors.setdefault("file_watcher", {})["paths"] = [p for p in paths.split(os.pathsep) if p]

    known = {k: raw[k] for k in AgentConfig.__dataclass_fields__ if k in raw}
    known.update(
        {
            "agent_id": os.environ.get("CARYLLE_AGENT_ID") or raw.get("agent_id") or socket.gethostname(),
            "token": token,
            "command_public_key": public_key,
            "server_url": os.environ.get("CARYLLE_SERVER_URL") or raw.get("server_url", "https://127.0.0.1:8443"),
            "verify_tls": verify_tls,
            "allow_insecure_http": _bool_env("CARYLLE_ALLOW_INSECURE_HTTP", bool(raw.get("allow_insecure_http"))),
            "actuators_enabled": _bool_env("CARYLLE_ACTUATORS_ENABLED", bool(raw.get("actuators_enabled"))),
            "sensors": sensors,
        }
    )
    return AgentConfig(**known)
