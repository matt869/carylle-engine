"""Prepare untrusted telemetry for the model.

An attacker controls command lines, file names and DNS queries, so those strings are
a prompt-injection channel straight into the reasoning layer. This module:

- strips characters used to hide text (control, bidi, zero-width)
- bounds field lengths
- redacts secrets, because telemetry leaves the host for a third-party API
- flags instruction-like text as a detection signal
- swaps event IDs for opaque references, so model output cannot name arbitrary targets

Detection here is a signal and not the defence. The defence is that model output has
limited authority: see verdict_validator and guardrails.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import unicodedata
from dataclasses import dataclass, field

from ...models import NormalizedEvent

MAX_FIELD = 2048
MAX_PATH_FIELD = 1024

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)),
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}")),
    # After the Anthropic pattern, which this would otherwise swallow.
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("api_key", re.compile(r"\b(sk|pk|rk)[-_](live|test|prod)[-_][A-Za-z0-9]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")),
    ("bearer", re.compile(r"(?i)\b(authorization:\s*)?bearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@")),
    (
        "credential_arg",
        re.compile(
            r"(?i)(--?(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key)(?:=|\s+)"
            r"|\b(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key)=)"
            r"(\"[^\"]*\"|'[^']*'|\S+)"
        ),
    ),
    ("sshpass", re.compile(r"(?i)\bsshpass\s+-p\s*\S+")),
    ("mysql_password", re.compile(r"\bmysql\b[^\n]*?\s-p[^\s-]\S*")),
]

# These look for natural-language instructions, not keywords. Ordinary command lines
# ("eslint --ignore-path x --rule y", "pkill sshd", running a tool called claude) must
# not match: this signal opens a case by itself, so loose patterns become constant noise.
_DETERMINERS = r"(?:all |any |the |your |my |previous |prior |above |earlier |these |those |preceding |system )"
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_instructions",
        re.compile(
            rf"\b(?:ignore|disregard|forget|override)\s+{_DETERMINERS}{{1,4}}"
            r"(?:instruction|prompt|rule|directive|guideline|context|polic)"
        ),
    ),
    ("new_instructions", re.compile(r"\b(?:new|updated|revised|real) (?:instructions?|directives?|system prompt)\b")),
    ("role_reassignment", re.compile(r"\byou are (?:now|actually|no longer)\b|\bact as (?:an?|the) |\bpretend (?:to be|you)\b")),
    ("system_prompt_reference", re.compile(r"\bsystem prompt\b|\byour (?:instructions|prompt|rules)\b")),
    ("fake_role_marker", re.compile(r"</?\s*(?:system|assistant|instructions?|human)\s*>|\b(?:assistant|human)\s*:\s")),
    (
        "verdict_steering",
        re.compile(
            r"\b(?:classify|mark|label|report|treat|rate|score)\b.{0,40}\bas (?:an? )?(?:benign|safe|clean|harmless|false positive|legitimate)\b"
            r"|\bnot (?:malicious|a threat)\b"
            r"|\bthis is (?:an? )?(?:authorized|approved|sanctioned) (?:test|pentest|exercise|activity)\b"
        ),
    ),
    (
        "alert_suppression",
        re.compile(r"\b(?:do not|don'?t|never) (?:flag|report|alert|escalate|notify|quarantine|terminate)\b"),
    ),
    (
        "action_steering",
        re.compile(
            r"\b(?:you (?:must|should)|please|immediately) (?:terminate|kill|quarantine)\b"
            r"|\brecommend\b.{0,30}\b(?:terminat|kill|quarantin)"
        ),
    ),
    (
        "model_address",
        re.compile(
            r"\b(?:attention|dear|hey|hello|note to|message for|instructions for)[ ,:]+(?:the )?"
            r"(?:claude|chatgpt|gpt-?\d|llm|ai|ai (?:assistant|analyst|model|agent)|language model|analyst)\b"
        ),
    ),
    ("output_format_steering", re.compile(r"\b(?:respond|reply|answer|output) (?:only )?(?:with|in|using)\b.{0,30}\b(?:json|verdict|benign)\b")),
]

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_INVISIBLE_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn"}


def strip_invisible(text: str) -> str:
    """Remove hidden characters, keeping line structure visible as literal escapes."""
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return "".join(ch for ch in text if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES)


def redact_secrets(text: str) -> tuple[str, int]:
    count = 0
    for name, pattern in _SECRET_PATTERNS:
        if name in {"credential_arg"}:
            text, n = pattern.subn(lambda m, label=name: f"{m.group(1)}[REDACTED:{label}]", text)
        elif name == "url_credentials":
            text, n = pattern.subn(lambda m, label=name: f"{m.group(1)}[REDACTED:{label}]@", text)
        else:
            text, n = pattern.subn(lambda m, label=name: f"[REDACTED:{label}]", text)
        count += n
    return text, count


def _matches(text: str) -> set[str]:
    return {name for name, pattern in _INJECTION_PATTERNS if pattern.search(text)}


def detect_injection(text: str) -> set[str]:
    """Return signal names for instruction-like text, looking through common obfuscation."""
    if not text:
        return set()
    # NFKC folds fullwidth and compatibility forms; invisible characters are dropped so
    # that "ig\u200bnore" still reads as "ignore".
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES)
    folded = re.sub(r"\s+", " ", folded).lower()
    signals = _matches(folded)
    for token in _B64_TOKEN.findall(text)[:8]:
        try:
            decoded = base64.b64decode(token, validate=False).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        hits = _matches(re.sub(r"\s+", " ", decoded).lower())
        signals |= {f"b64:{name}" for name in hits}
    return signals


def _clean(value: str, limit: int = MAX_FIELD) -> tuple[str, int]:
    text, redactions = redact_secrets(value)
    text = strip_invisible(text)
    if len(text) > limit:
        omitted = len(text) - limit
        text = f"{text[:limit]}...[{omitted} chars truncated]"
    return text, redactions


@dataclass
class SanitizedCase:
    events: list[dict]
    ref_to_event_id: dict[str, str]
    event_id_to_ref: dict[str, str]
    injection_signals: list[str]
    redaction_count: int
    fence: str = field(default_factory=lambda: secrets.token_hex(12))


def event_strings(event: NormalizedEvent) -> list[str]:
    """Every attacker-influenced string on an event."""
    out: list[str] = []
    if event.process:
        p = event.process
        out += [p.name, p.exe, p.cmdline, p.user, p.parent_name, p.parent_exe]
    if event.file:
        out += [event.file.path, event.file.dest_path]
    if event.network:
        out += [event.network.process_name]
    if event.dns:
        out += [event.dns.qname]
    if event.yara:
        out += [event.yara.path, event.yara.description]
    return [s for s in out if s]


def event_injection_signals(event: NormalizedEvent) -> set[str]:
    signals: set[str] = set()
    for text in event_strings(event):
        signals |= detect_injection(text)
    return signals


def sanitize_case(events: list[NormalizedEvent]) -> SanitizedCase:
    views: list[dict] = []
    ref_to_id: dict[str, str] = {}
    id_to_ref: dict[str, str] = {}
    signals: set[str] = set()
    redactions = 0

    def clean(value: str, limit: int = MAX_FIELD) -> str:
        nonlocal redactions
        text, n = _clean(value, limit)
        redactions += n
        return text

    for index, event in enumerate(events, start=1):
        ref = f"e{index}"
        ref_to_id[ref] = event.event_id
        id_to_ref[event.event_id] = ref
        signals |= event_injection_signals(event)

        view: dict = {"ref": ref, "type": event.type.value, "ts": round(event.ts, 3)}
        if event.process:
            p = event.process
            view["process"] = {
                "pid": p.pid,
                "ppid": p.ppid,
                "name": clean(p.name, 256),
                "exe": clean(p.exe, MAX_PATH_FIELD),
                "cmdline": clean(p.cmdline),
                "user": clean(p.user, 128),
                "parent_name": clean(p.parent_name, 256),
                "parent_exe": clean(p.parent_exe, MAX_PATH_FIELD),
                "sha256": p.sha256,
            }
        if event.file:
            view["file"] = {
                "path": clean(event.file.path, MAX_PATH_FIELD),
                "action": clean(event.file.action, 32),
                "dest_path": clean(event.file.dest_path, MAX_PATH_FIELD),
                "sha256": event.file.sha256,
                "size": event.file.size,
            }
        if event.network:
            n = event.network
            view["network"] = {
                "src_ip": clean(n.src_ip, 64),
                "src_port": n.src_port,
                "dst_ip": clean(n.dst_ip, 64),
                "dst_port": n.dst_port,
                "proto": clean(n.proto, 16),
                "pid": n.pid,
                "process_name": clean(n.process_name, 256),
                "status": clean(n.status, 32),
            }
        if event.dns:
            view["dns"] = {"qname": clean(event.dns.qname, 512), "qtype": clean(event.dns.qtype, 16)}
        if event.yara:
            y = event.yara
            view["yara"] = {
                "rule": clean(y.rule, 256),
                "severity": clean(y.severity, 16),
                "tags": [clean(t, 64) for t in y.tags],
                "description": clean(y.description, 512),
                "path": clean(y.path, MAX_PATH_FIELD),
                "sha256": y.sha256,
            }
        views.append(view)

    return SanitizedCase(
        events=views,
        ref_to_event_id=ref_to_id,
        event_id_to_ref=id_to_ref,
        injection_signals=sorted(signals),
        redaction_count=redactions,
    )
