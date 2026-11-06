"""Turn raw agent payloads into validated, size-bounded events.

Everything here is untrusted: a compromised agent can send anything. A bad event is
rejected on its own and never fails the batch. Identity comes from the authenticated
token, never from the payload.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from pydantic import ValidationError

from ..models import (
    DnsInfo,
    EventType,
    FileInfo,
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    YaraInfo,
)

log = logging.getLogger(__name__)

MAX_STR = 8192
MAX_NAME = 512
MAX_PATH = 4096
MAX_EVENT_ID = 128
# Agent clocks drift, but a timestamp far from now is either broken or an attempt to
# fall outside correlation windows.
MAX_CLOCK_SKEW_SECONDS = 24 * 3600
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[A-Za-z0-9_.:\-]+$")


class EventRejected(ValueError):
    pass


def _s(value: Any, limit: int = MAX_STR) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    text = str(value)
    return text[:limit]


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if out == out and abs(out) != float("inf") else None


def _sha(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    return lowered if _SHA256.match(lowered) else None


def _process(data: dict[str, Any]) -> ProcessInfo:
    pid = _int(data.get("pid"))
    if pid is None or pid < 0:
        raise EventRejected("process event without a valid pid")
    return ProcessInfo(
        pid=pid,
        ppid=_int(data.get("ppid")),
        name=_s(data.get("name"), MAX_NAME),
        exe=_s(data.get("exe"), MAX_PATH),
        cmdline=_s(data.get("cmdline")),
        user=_s(data.get("user"), MAX_NAME),
        create_time=_float(data.get("create_time")),
        sha256=_sha(data.get("sha256")),
        parent_name=_s(data.get("parent_name"), MAX_NAME),
        parent_exe=_s(data.get("parent_exe"), MAX_PATH),
    )


def _file(data: dict[str, Any]) -> FileInfo:
    path = _s(data.get("path"), MAX_PATH)
    if not path:
        raise EventRejected("file event without a path")
    return FileInfo(
        path=path,
        action=_s(data.get("action"), 32),
        sha256=_sha(data.get("sha256")),
        size=_int(data.get("size")),
        dest_path=_s(data.get("dest_path"), MAX_PATH),
    )


def _network(data: dict[str, Any]) -> NetworkInfo:
    return NetworkInfo(
        src_ip=_s(data.get("src_ip"), 64),
        src_port=_int(data.get("src_port")),
        dst_ip=_s(data.get("dst_ip"), 64),
        dst_port=_int(data.get("dst_port")),
        proto=_s(data.get("proto"), 16),
        pid=_int(data.get("pid")),
        process_name=_s(data.get("process_name"), MAX_NAME),
        status=_s(data.get("status"), 32),
    )


def _dns(data: dict[str, Any]) -> DnsInfo:
    qname = _s(data.get("qname"), 1024)
    if not qname:
        raise EventRejected("dns event without a qname")
    return DnsInfo(qname=qname, qtype=_s(data.get("qtype"), 16))


def _yara(data: dict[str, Any]) -> YaraInfo:
    rule = _s(data.get("rule"), MAX_NAME)
    if not rule:
        raise EventRejected("yara event without a rule")
    tags = data.get("tags")
    return YaraInfo(
        rule=rule,
        tags=[_s(t, 64) for t in tags[:32]] if isinstance(tags, list) else [],
        severity=_s(data.get("severity"), 16).lower() or "medium",
        attack=_s(data.get("attack"), 32),
        description=_s(data.get("description"), 1024),
        path=_s(data.get("path"), MAX_PATH),
        sha256=_sha(data.get("sha256")),
        size=_int(data.get("size")),
    )


def _health(data: dict[str, Any]) -> dict[str, Any]:
    keep = ("version", "sensors", "dropped_events", "yara_available", "actuators_enabled", "platform")
    out: dict[str, Any] = {}
    for key in keep:
        value = data.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value if not isinstance(value, str) else value[:256]
        elif isinstance(value, dict):
            out[key] = {str(k)[:64]: str(v)[:128] for k, v in list(value.items())[:32]}
    return out


def normalize_event(raw: Any, agent_id: str, now: float | None = None) -> NormalizedEvent:
    now = time.time() if now is None else now
    if not isinstance(raw, dict):
        raise EventRejected("event is not an object")

    event_id = raw.get("event_id")
    if (
        not isinstance(event_id, str)
        or not 0 < len(event_id) <= MAX_EVENT_ID
        or not _EVENT_ID.match(event_id)
    ):
        raise EventRejected("invalid event_id")

    try:
        event_type = EventType(raw.get("type"))
    except ValueError as exc:
        raise EventRejected(f"unknown event type: {str(raw.get('type'))[:64]!r}") from exc

    data = raw.get("data")
    if not isinstance(data, dict):
        raise EventRejected("event data is not an object")

    ts = _float(raw.get("ts"))
    if ts is None or abs(ts - now) > MAX_CLOCK_SKEW_SECONDS:
        ts = now

    fields: dict[str, Any] = {}
    try:
        if event_type is EventType.PROCESS_START:
            fields["process"] = _process(data)
        elif event_type is EventType.FILE_EVENT:
            fields["file"] = _file(data)
        elif event_type is EventType.NETWORK_CONNECTION:
            fields["network"] = _network(data)
        elif event_type is EventType.DNS_QUERY:
            fields["dns"] = _dns(data)
        elif event_type is EventType.YARA_MATCH:
            fields["yara"] = _yara(data)
        elif event_type is EventType.AGENT_HEALTH:
            fields["health"] = _health(data)
        return NormalizedEvent(
            event_id=event_id, agent_id=agent_id, type=event_type, ts=ts, received_at=now, **fields
        )
    except ValidationError as exc:
        raise EventRejected(f"schema violation: {exc.error_count()} errors") from exc


def normalize_batch(
    raw_events: list[Any], agent_id: str, now: float | None = None
) -> tuple[list[NormalizedEvent], list[str]]:
    accepted: list[NormalizedEvent] = []
    rejected: list[str] = []
    for raw in raw_events:
        try:
            accepted.append(normalize_event(raw, agent_id, now))
        except EventRejected as exc:
            rejected.append(str(exc))
    if rejected:
        log.warning("agent %s: rejected %d of %d events", agent_id, len(rejected), len(raw_events))
    return accepted, rejected
