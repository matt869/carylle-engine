"""MITRE ATT&CK lookups from the official STIX bundle.

Technique IDs get renumbered between ATT&CK releases, so nothing here is hardcoded:
detection rules and model output are both checked against the loaded dataset.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    is_subtechnique: bool


@dataclass
class MitreMapper:
    techniques: dict[str, Technique] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> MitreMapper:
        """Parse the bundle and keep only a small index, since the source file is ~55 MB."""
        path = Path(path)
        if not path.exists() or path.stat().st_size == 0:
            log.warning("ATT&CK data missing at %s: techniques cannot be validated", path)
            return cls()
        bundle = json.loads(path.read_text(encoding="utf-8"))
        techniques: dict[str, Technique] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tid = ref["external_id"]
                    tactics = tuple(
                        phase["phase_name"]
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    )
                    techniques[tid] = Technique(
                        id=tid,
                        name=obj.get("name", ""),
                        tactics=tactics,
                        url=ref.get("url", ""),
                        is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
                    )
                    break
        log.info("Loaded %d ATT&CK techniques", len(techniques))
        return cls(techniques=techniques)

    @property
    def loaded(self) -> bool:
        return bool(self.techniques)

    def exists(self, technique_id: str) -> bool:
        return technique_id in self.techniques

    def filter_valid(self, ids: list[str]) -> tuple[list[str], list[str]]:
        """Split IDs into valid (deduplicated, ordered) and invalid.

        With no dataset loaded, well-formed IDs pass, because losing technique labels is
        worse than carrying an unverified one.
        """
        valid: list[str] = []
        invalid: list[str] = []
        for raw in ids:
            tid = str(raw).strip().upper()
            if not _TECHNIQUE_ID.match(tid):
                invalid.append(str(raw)[:32])
            elif self.loaded and tid not in self.techniques:
                invalid.append(tid)
            elif tid not in valid:
                valid.append(tid)
        return valid, invalid

    def enrich(self, ids: list[str]) -> list[dict]:
        out = []
        for tid in ids:
            technique = self.techniques.get(tid)
            if technique:
                out.append(
                    {
                        "id": technique.id,
                        "name": technique.name,
                        "tactics": list(technique.tactics),
                        "url": technique.url,
                    }
                )
            else:
                out.append({"id": tid, "name": "", "tactics": [], "url": ""})
        return out
