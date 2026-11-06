"""Deterministic detection rules.

These rules do three jobs. They triage, so the LLM only sees events worth its cost.
They decide alone when the LLM is unavailable. And they set a floor the LLM cannot
talk down, which is what makes model manipulation unprofitable for an attacker.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from ...models import (
    ActionType,
    Classification,
    EventType,
    NormalizedEvent,
    RecommendedAction,
    Severity,
    Verdict,
)
from .sanitizer import event_injection_signals

TERMINATE = ActionType.TERMINATE_PROCESS
QUARANTINE = ActionType.QUARANTINE_FILE


@dataclass(frozen=True)
class CmdRule:
    rule_id: str
    weight: float
    techniques: tuple[str, ...]
    pattern: re.Pattern[str]
    description: str
    action: ActionType | None = TERMINATE


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


CMD_RULES: tuple[CmdRule, ...] = (
    CmdRule(
        "reverse_shell", 0.85, ("T1059.004",),
        _rx(
            r"bash\s+-i\s+>&\s*/dev/(tcp|udp)/|/dev/(tcp|udp)/\d{1,3}\.\d{1,3}"
            r"|\bnc(at)?(\.exe)?\b.*\s-[a-z]*e\s|mkfifo\s+\S+.*\bnc(at)?\b"
            r"|socat\b.*\bexec:|python[\d.]*\s+-c\s+.*socket.*(dup2|connect)"
            r"|perl\s+-e\s+.*socket|php\s+-r\s+.*fsockopen"
        ),
        "Reverse shell command pattern",
    ),
    CmdRule(
        "encoded_powershell", 0.7, ("T1059.001", "T1027.010"),
        _rx(r"powershell(\.exe)?\b.*\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}"),
        "PowerShell with an encoded command",
    ),
    CmdRule(
        "powershell_download_cradle", 0.75, ("T1059.001", "T1105"),
        _rx(r"(iex|invoke-expression)\b.*(downloadstring|invoke-webrequest|\biwr\b)|downloadstring\(.*\)\s*\|\s*iex"),
        "PowerShell download-and-execute cradle",
    ),
    CmdRule(
        "download_execute", 0.75, ("T1105", "T1059.004"),
        _rx(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
        "Downloaded content piped straight into a shell",
    ),
    CmdRule(
        "decode_pipe_shell", 0.72, ("T1140", "T1059.004"),
        _rx(r"base64\s+(-d|--decode)\b.*\|\s*(ba|z|da)?sh\b"),
        "Decoded payload piped into a shell",
    ),
    CmdRule(
        "credential_dump_lsass", 0.85, ("T1003.001",),
        _rx(r"mimikatz|sekurlsa|procdump.*lsass|comsvcs(\.dll)?.*minidump"),
        "LSASS credential dumping tool or technique",
    ),
    CmdRule(
        "credential_dump_shadow", 0.72, ("T1003.008",),
        _rx(r"\b(cat|cp|tar|less|more|head|tail|strings|base64)\b.*\s/etc/shadow\b|\bunshadow\b"),
        "Access to /etc/shadow",
    ),
    CmdRule(
        "credential_dump_sam", 0.8, ("T1003.002",),
        _rx(r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)\b"),
        "Registry hive export for credential theft",
    ),
    CmdRule(
        "inhibit_recovery", 0.92, ("T1490",),
        _rx(
            r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete\s+catalog"
            r"|bcdedit(\.exe)?\b.*recoveryenabled\s+no|wmic(\.exe)?\s+shadowcopy\s+delete"
        ),
        "Backups or recovery deliberately destroyed",
    ),
    CmdRule(
        "cron_persistence", 0.5, ("T1053.003",),
        _rx(r"crontab\s+-\s*$|\|\s*crontab\b|>>?\s*/etc/cron|>>?\s*/var/spool/cron"),
        "Cron entry written from the command line",
    ),
    CmdRule(
        "schtask_persistence", 0.5, ("T1053.005",),
        _rx(r"schtasks(\.exe)?\s+/create"),
        "Scheduled task created",
    ),
    CmdRule(
        "account_creation", 0.45, ("T1136",),
        _rx(r"\buseradd\b|\badduser\b|net(\.exe)?\s+user\s+\S+\s+\S*\s*/add"),
        "Local account created",
        None,
    ),
    CmdRule(
        "log_tamper_linux", 0.72, ("T1685.006",),
        _rx(r"\brm\b.*\s/var/log\b|\btruncate\b.*\s/var/log/|>\s*/var/log/(auth|secure|syslog|messages)"),
        "System logs removed or truncated",
    ),
    CmdRule(
        "log_tamper_history", 0.55, ("T1070.003",),
        _rx(r"\bhistory\s+-c\b|unset\s+histfile|histfile=/dev/null|rm\s+\S*\.bash_history"),
        "Shell history cleared",
    ),
    CmdRule(
        "log_tamper_windows", 0.78, ("T1685.005",),
        _rx(r"wevtutil(\.exe)?\s+cl\b|clear-eventlog\b"),
        "Windows event logs cleared",
    ),
    CmdRule(
        "disable_security_tools", 0.72, ("T1685",),
        _rx(
            r"systemctl\s+(stop|disable|mask)\s+(auditd|falco|carylle\S*|clamav\S*|apparmor|crowdstrike\S*|falcon\S*)"
            r"|\bsetenforce\s+0\b|set-mppreference\b.*-disable\w+\s+\$?true|\bpkill\b.*\b(auditd|carylle)\b"
        ),
        "Security tooling disabled",
    ),
    CmdRule(
        "cryptominer", 0.78, ("T1496",),
        _rx(r"\bxmrig\b|stratum\+(tcp|ssl)://|\bminerd\b|--donate-level\b|\bcpuminer\b"),
        "Cryptocurrency miner",
    ),
    CmdRule(
        "lolbin_mshta", 0.65, ("T1218.005",),
        _rx(r"mshta(\.exe)?\s+(https?:|javascript:|vbscript:)"),
        "mshta running remote or inline script",
    ),
    CmdRule(
        "lolbin_rundll32", 0.65, ("T1218.011",),
        _rx(r"rundll32(\.exe)?\b.*(javascript:|https?:)"),
        "rundll32 running script or remote content",
    ),
)

TEMP_EXEC = _rx(r"^(/tmp/|/var/tmp/|/dev/shm/)|\\(temp|appdata\\local\\temp)\\")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe"}
WEB_SERVERS = {
    "nginx", "apache2", "httpd", "php-fpm", "php-cgi", "w3wp.exe", "tomcat", "lighttpd", "caddy",
}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
# Names attackers borrow, and where the real binary lives.
MASQUERADE_DIRS: dict[str, tuple[str, ...]] = {
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "lsass.exe": ("c:\\windows\\system32\\",),
    "csrss.exe": ("c:\\windows\\system32\\",),
    "services.exe": ("c:\\windows\\system32\\",),
    "explorer.exe": ("c:\\windows\\",),
    "sshd": ("/usr/sbin/", "/usr/bin/", "/sbin/", "/usr/lib/"),
    "systemd": ("/lib/systemd/", "/usr/lib/systemd/", "/sbin/", "/usr/sbin/", "/bin/", "/usr/bin/"),
    "cron": ("/usr/sbin/", "/usr/bin/", "/sbin/"),
    "crond": ("/usr/sbin/", "/usr/bin/", "/sbin/"),
    "kworker": (),
    "kthreadd": (),
}

FILE_PERSISTENCE: tuple[tuple[str, float, tuple[str, ...], re.Pattern[str], ActionType | None], ...] = (
    ("cron_file", 0.55, ("T1053.003",), _rx(r"^/etc/cron|^/var/spool/cron"), QUARANTINE),
    ("systemd_unit", 0.55, ("T1543.002",), _rx(r"^/etc/systemd/system/.*\.(service|timer)$|/\.config/systemd/user/.*\.service$"), QUARANTINE),
    ("ssh_authorized_keys", 0.6, ("T1098.004",), _rx(r"/\.ssh/authorized_keys2?$"), None),
    ("shell_profile", 0.45, ("T1546.004",), _rx(r"/\.(bashrc|bash_profile|profile|zshrc)$|^/etc/profile\.d/"), None),
    ("windows_startup", 0.55, ("T1547.001",), _rx(r"\\start menu\\programs\\startup\\"), QUARANTINE),
)
WEBSHELL_DROP = _rx(r"(^/var/www/|\\inetpub\\wwwroot\\|/public_html/).*\.(php\d?|phtml|jsp|jspx|asp|aspx)$")
RANSOM_EXTENSION = _rx(r"\.(locked|encrypted|crypted|crypt|enc|ransom|wncry|lockbit)$")
RANSOM_NOTE = _rx(r"(^|[/\\])(read_?me_?(to_?)?decrypt|how_?to_?(decrypt|restore|recover)|restore_?(my_?)?files|decrypt_?instructions)[^/\\]*$")
C2_PORTS = {4444, 1337, 31337, 5555, 6666, 9001}
MINING_PORTS = {3333, 14444, 45700}
RANSOM_EXTENSION_MIN = 10

YARA_WEIGHTS = {"critical": 0.97, "high": 0.9, "medium": 0.55, "low": 0.25}


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    weight: float
    techniques: tuple[str, ...]
    event_id: str
    description: str
    action: ActionType | None = None


@dataclass
class Assessment:
    score: float = 0.0
    severity: Severity = Severity.INFO
    classification: Classification = Classification.BENIGN
    hits: list[RuleHit] = field(default_factory=list)
    injection_signals: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return list(dict.fromkeys(t for h in self.hits for t in h.techniques))

    @property
    def rule_ids(self) -> list[str]:
        return list(dict.fromkeys(h.rule_id for h in self.hits))

    @property
    def event_ids(self) -> list[str]:
        return list(dict.fromkeys(h.event_id for h in self.hits))

    def recommended_actions(self) -> list[RecommendedAction]:
        seen: set[tuple[str, str]] = set()
        out: list[RecommendedAction] = []
        for hit in sorted(self.hits, key=lambda h: -h.weight):
            if hit.action is None or (hit.action, hit.event_id) in seen:
                continue
            seen.add((hit.action, hit.event_id))
            out.append(RecommendedAction(action=hit.action, event_id=hit.event_id, rationale=hit.description))
        return out

    def findings(self, id_to_ref: dict[str, str]) -> list[dict]:
        return [
            {
                "rule": h.rule_id,
                "event": id_to_ref.get(h.event_id, "?"),
                "description": h.description,
                "techniques": list(h.techniques),
            }
            for h in self.hits
        ]


def _basename(path: str) -> str:
    return re.split(r"[/\\]", path)[-1].lower() if path else ""


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def _process_hits(event: NormalizedEvent) -> list[RuleHit]:
    p = event.process
    assert p is not None
    hits: list[RuleHit] = []
    name = (p.name or _basename(p.exe)).lower()
    exe = p.exe.lower()
    parent = (p.parent_name or _basename(p.parent_exe)).lower()
    # Argv can be empty when the agent lacks permission, and scanning the name too
    # catches a miner run with no telling arguments.
    haystack = f"{p.cmdline} {p.name}"

    for rule in CMD_RULES:
        if rule.pattern.search(haystack):
            hits.append(
                RuleHit(rule.rule_id, rule.weight, rule.techniques, event.event_id, rule.description, rule.action)
            )
    if exe and TEMP_EXEC.search(exe):
        hits.append(
            RuleHit("exec_from_temp", 0.3, ("T1204.002",), event.event_id, "Executable ran from a temporary directory", TERMINATE)
        )
    if parent in WEB_SERVERS and name in SHELLS:
        hits.append(
            RuleHit("webserver_spawned_shell", 0.82, ("T1505.003",), event.event_id, f"Shell spawned by web server {parent}", TERMINATE)
        )
    if parent in OFFICE_APPS and name in SHELLS:
        hits.append(
            RuleHit("office_spawned_shell", 0.75, ("T1204.002",), event.event_id, f"Shell spawned by Office application {parent}", TERMINATE)
        )
    if exe and name in MASQUERADE_DIRS:
        allowed = MASQUERADE_DIRS[name]
        if not allowed or not exe.startswith(allowed):
            hits.append(
                RuleHit("masquerading_binary", 0.72, ("T1036.005",), event.event_id, f"Binary named {name} outside its usual location", TERMINATE)
            )
    return hits


def _file_hits(event: NormalizedEvent) -> list[RuleHit]:
    f = event.file
    assert f is not None
    if f.action not in {"created", "modified", "moved"}:
        return []
    path = (f.dest_path or f.path).lower()
    hits: list[RuleHit] = []
    for rule_id, weight, techniques, pattern, action in FILE_PERSISTENCE:
        if pattern.search(path):
            hits.append(RuleHit(rule_id, weight, techniques, event.event_id, f"Persistence location changed: {rule_id}", action))
    if WEBSHELL_DROP.search(path):
        hits.append(RuleHit("webshell_drop", 0.55, ("T1505.003",), event.event_id, "Script written into a web root", QUARANTINE))
    if RANSOM_NOTE.search(path):
        hits.append(RuleHit("ransom_note_file", 0.7, ("T1486",), event.event_id, "File named like a ransom note", QUARANTINE))
    return hits


def _network_hits(event: NormalizedEvent) -> list[RuleHit]:
    n = event.network
    assert n is not None
    hits: list[RuleHit] = []
    name = n.process_name.lower()
    if n.dst_port in C2_PORTS and name in SHELLS:
        hits.append(RuleHit("shell_to_c2_port", 0.65, ("T1571",), event.event_id, f"Shell connected to port {n.dst_port}"))
    if n.dst_port in MINING_PORTS:
        hits.append(RuleHit("mining_port", 0.4, ("T1496",), event.event_id, f"Connection to mining port {n.dst_port}"))
    return hits


def _dns_hits(event: NormalizedEvent) -> list[RuleHit]:
    qname = event.dns.qname if event.dns else ""
    labels = qname.rstrip(".").split(".")
    longest = max((len(label) for label in labels), default=0)
    if longest >= 50 or (longest >= 32 and _entropy(max(labels, key=len)) > 4.0):
        return [RuleHit("dns_tunnel_label", 0.45, ("T1071.004",), event.event_id, "DNS label shaped like tunnelled data")]
    return []


def _yara_hits(event: NormalizedEvent) -> list[RuleHit]:
    y = event.yara
    assert y is not None
    severity = y.severity if y.severity in YARA_WEIGHTS else "medium"
    weight = YARA_WEIGHTS[severity]
    rule_id = "yara_match_high" if weight >= 0.9 else f"yara_match_{severity}"
    techniques = (y.attack,) if y.attack else ("T1204.002",)
    return [RuleHit(rule_id, weight, techniques, event.event_id, f"YARA rule {y.rule} matched", QUARANTINE)]


def event_hits(event: NormalizedEvent) -> list[RuleHit]:
    hits: list[RuleHit]
    if event.type is EventType.PROCESS_START and event.process:
        hits = _process_hits(event)
    elif event.type is EventType.FILE_EVENT and event.file:
        hits = _file_hits(event)
    elif event.type is EventType.NETWORK_CONNECTION and event.network:
        hits = _network_hits(event)
    elif event.type is EventType.DNS_QUERY and event.dns:
        hits = _dns_hits(event)
    elif event.type is EventType.YARA_MATCH and event.yara:
        hits = _yara_hits(event)
    else:
        hits = []
    signals = event_injection_signals(event)
    if signals:
        hits.append(
            RuleHit("prompt_injection_text", 0.4, (), event.event_id, "Telemetry contains text aimed at an AI analyst")
        )
    return hits


def is_ransom_extension_event(event: NormalizedEvent) -> bool:
    if event.type is not EventType.FILE_EVENT or not event.file:
        return False
    return bool(RANSOM_EXTENSION.search((event.file.dest_path or event.file.path).lower()))


def severity_for(score: float) -> Severity:
    if score >= 0.9:
        return Severity.CRITICAL
    if score >= 0.7:
        return Severity.HIGH
    if score >= 0.4:
        return Severity.MEDIUM
    if score >= 0.2:
        return Severity.LOW
    return Severity.INFO


def classification_for(score: float) -> Classification:
    if score >= 0.7:
        return Classification.MALICIOUS
    if score >= 0.35:
        return Classification.SUSPICIOUS
    return Classification.BENIGN


def assess(
    events: list[NormalizedEvent], burst_count: int = 0, burst_threshold: int = 0, ransom_count: int = 0
) -> Assessment:
    hits: list[RuleHit] = []
    signals: set[str] = set()
    ransom_events: list[NormalizedEvent] = []
    for event in events:
        hits.extend(event_hits(event))
        signals |= event_injection_signals(event)
        if is_ransom_extension_event(event):
            ransom_events.append(event)

    renamed = max(len(ransom_events), ransom_count)
    if ransom_events and renamed >= RANSOM_EXTENSION_MIN:
        hits.append(
            RuleHit(
                "mass_encrypted_extensions", 0.85, ("T1486",), ransom_events[0].event_id,
                f"{renamed} files renamed to ransomware-style extensions",
            )
        )
    if burst_threshold and burst_count >= burst_threshold:
        anchor = next((e.event_id for e in events if e.type is EventType.FILE_EVENT), None)
        if anchor:
            hits.append(
                RuleHit("file_write_burst", 0.55, ("T1486",), anchor, f"{burst_count} file events in the burst window")
            )

    # Noisy-OR across distinct rules: independent evidence adds up and never exceeds 1.
    # Taking each rule once stops repetition of a single weak signal from inflating the score.
    best: dict[str, float] = {}
    for hit in hits:
        best[hit.rule_id] = max(best.get(hit.rule_id, 0.0), hit.weight)
    remainder = 1.0
    for weight in best.values():
        remainder *= 1.0 - weight
    score = round(1.0 - remainder, 4) if best else 0.0

    return Assessment(
        score=score,
        severity=severity_for(score),
        classification=classification_for(score),
        hits=hits,
        injection_signals=sorted(signals),
    )


def verdict_from_assessment(assessment: Assessment, reason: str, mapper=None) -> Verdict:
    techniques = assessment.techniques
    issues: list[str] = []
    if mapper is not None:
        techniques, invalid = mapper.filter_valid(techniques)
        issues = [f"unknown technique from rules: {t}" for t in invalid]
    rules = ", ".join(assessment.rule_ids) or "none"
    summary = (
        f"Deterministic assessment ({reason}). Score {assessment.score:.2f} from rules: {rules}."
    )
    return Verdict(
        classification=assessment.classification,
        severity=assessment.severity,
        confidence=assessment.score,
        summary=summary,
        techniques=techniques,
        evidence_event_ids=assessment.event_ids,
        recommended_actions=assessment.recommended_actions(),
        source="fallback",
        fallback_reason=reason,
        deterministic_score=assessment.score,
        matched_rules=assessment.rule_ids,
        deterministic_event_ids=assessment.event_ids,
        injection_suspected=bool(assessment.injection_signals),
        injection_signals=assessment.injection_signals,
        validation_issues=issues,
    )
