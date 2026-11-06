"""Technique IDs get renumbered between ATT&CK releases. These catch that on a dataset update."""

from __future__ import annotations

from pathlib import Path

import yaml
from carylle.pipeline.reasoning import fallback_scorer as fs

ROOT = Path(__file__).resolve().parent.parent


def test_dataset_loaded(mapper):
    assert mapper.loaded and len(mapper.techniques) > 500
    assert mapper.techniques["T1059.004"].name == "Unix Shell"


def test_every_detection_rule_technique_exists(mapper):
    techniques = {t for rule in fs.CMD_RULES for t in rule.techniques}
    techniques |= {t for rule in fs.FILE_PERSISTENCE for t in rule[2]}
    techniques |= {"T1204.002", "T1505.003", "T1036.005", "T1486", "T1571", "T1496", "T1071.004"}
    missing = sorted(t for t in techniques if not mapper.exists(t))
    assert not missing, f"Rules cite techniques not in this ATT&CK release: {missing}"


def test_every_playbook_technique_exists(mapper):
    raw = yaml.safe_load((ROOT / "config/playbooks/response_playbooks.yaml").read_text(encoding="utf-8"))
    techniques = {t for p in raw["playbooks"] for t in (p.get("match") or {}).get("techniques", [])}
    missing = sorted(t for t in techniques if not mapper.exists(t))
    assert not missing, f"Playbooks cite techniques not in this ATT&CK release: {missing}"


def test_every_yara_rule_technique_exists(mapper):
    import re

    text = (ROOT / "config/yara/carylle_base.yar").read_text(encoding="utf-8")
    techniques = set(re.findall(r'attack = "(T[\d.]+)"', text))
    assert techniques
    missing = sorted(t for t in techniques if not mapper.exists(t))
    assert not missing, f"YARA rules cite techniques not in this ATT&CK release: {missing}"


def test_filter_valid(mapper):
    valid, invalid = mapper.filter_valid(["t1059.004", "T1059.004", "T9999", "garbage"])
    assert valid == ["T1059.004"] and invalid == ["T9999", "garbage"]


def test_enrich(mapper):
    enriched = mapper.enrich(["T1059.004"])[0]
    assert enriched["name"] == "Unix Shell" and "execution" in enriched["tactics"]


def test_revoked_techniques_are_excluded(mapper):
    assert not mapper.exists("T1562.001")


def test_missing_dataset_passes_well_formed_ids(tmp_path):
    from carylle.pipeline.reasoning.mitre_mapper import MitreMapper

    empty = MitreMapper.load(tmp_path / "absent.json")
    assert not empty.loaded
    assert empty.filter_valid(["T1059", "nope"]) == (["T1059"], ["nope"])
