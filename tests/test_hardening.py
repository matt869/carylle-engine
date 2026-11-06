"""Regression tests for edge cases found in review: caps, limits and corrupt state."""

from __future__ import annotations

import json
import time
import uuid

from carylle import cli
from carylle.models import ActionState
from carylle.pipeline.reasoning.llm_client import LLMResult
from carylle_agent.actuators.file_quarantine import FileQuarantine
from carylle_agent.commands import ReplayGuard
from carylle_agent.safelist import AgentSafelist
from carylle_agent.util import sha256_file

from .conftest import REVERSE_SHELL, ROOT, raw_process


def shell_to_c2(i: int) -> dict:
    return {
        "event_id": uuid.uuid4().hex,
        "type": "network_connection",
        "ts": 999.0 + i * 0.001,
        "data": {"dst_ip": "203.0.113.10", "dst_port": 4444, "pid": 4242, "process_name": "bash"},
    }


def noisy_reverse_shell() -> list[dict]:
    """More related events than a case holds, with the only killable target arriving last."""
    return [shell_to_c2(i) for i in range(45)] + [raw_process(REVERSE_SHELL, pid=4242)]


class TestCaseCap:
    def test_fallback_still_contains_when_evidence_arrives_late(self, harness):
        harness.post(noisy_reverse_shell())
        assert len(harness.cases()) == 1
        actions = harness.actions()
        assert any(a["type"] == "terminate_process" for a in actions), actions

    def test_model_path_survives_evidence_beyond_the_cap(self, harness):
        benign = {
            "classification": "benign", "severity": "low", "confidence": 0.2,
            "summary": "looks fine", "evidence": [], "techniques": [],
        }
        harness.llm(LLMResult(status="ok", model="m", data=benign))
        harness.post(noisy_reverse_shell())

        cases = harness.cases()
        assert len(cases) == 1, "the case was lost to a pipeline error"
        assert cases[0]["verdict"]["floor_applied"]
        assert any(a["type"] == "terminate_process" for a in harness.actions())

    def test_flagged_events_are_kept_in_the_case(self, harness):
        harness.post(noisy_reverse_shell())
        case = harness.client.get(f"/api/v1/cases/{harness.cases()[0]['case_id']}", headers=harness.operator).json()
        assert len(case["events"]) <= harness.services.settings.pipeline.max_case_events
        assert any(e["type"] == "process_start" for e in case["events"])


class TestBodyLimit:
    def test_chunked_upload_without_length_is_capped(self, harness):
        limit = harness.services.settings.server.max_body_bytes

        def body():
            chunk = b"x" * 65536
            for _ in range(limit // len(chunk) + 2):
                yield chunk

        response = harness.client.post(
            "/api/v1/events", content=body(), headers={**harness.agent_headers(), "content-type": "application/json"}
        )
        assert response.status_code == 413

    def test_invalid_content_length(self, harness):
        response = harness.client.post(
            "/api/v1/events", content=b"{}", headers={**harness.agent_headers(), "content-length": "nope"}
        )
        assert response.status_code == 400


class TestStatus:
    def test_pending_approvals_is_not_capped_by_pagination(self, harness):
        now = time.time()
        for i in range(205):
            harness.services.store.insert_action(
                {
                    "action_id": f"act_{i}", "case_id": "case_x", "agent_id": "host-1", "type": "terminate_process",
                    "target": {"pid": i}, "dedupe_key": f"k{i}", "state": ActionState.PENDING_APPROVAL.value,
                    "playbook_id": None, "reasons": [], "created_at": now, "updated_at": now, "expires_at": None,
                }
            )
        status = harness.client.get("/api/v1/status", headers=harness.operator).json()
        assert status["pending_approvals"] == 205


class TestLedgerAnchor:
    def _anchor(self, services):
        return services.ledger._anchor

    def test_malformed_anchor_fails_verification_instead_of_crashing(self, services):
        services.ledger.append("a", {"i": 1})
        self._anchor(services).write_text("{not json", encoding="utf-8")
        result = services.ledger.verify()
        assert not result["ok"] and "malformed" in result["error"]

    def test_anchor_one_behind_is_accepted(self, services):
        first = services.ledger.append("a", {"i": 1})
        services.ledger.append("a", {"i": 2})
        # As if the server stopped between the second insert and its anchor write.
        self._anchor(services).write_text(json.dumps(first), encoding="utf-8")
        assert services.ledger.verify()["ok"]

    def test_lagging_anchor_must_still_match_its_entry(self, services):
        for i in range(3):
            services.ledger.append("a", {"i": i})
        self._anchor(services).write_text(json.dumps({"seq": 1, "hash": "f" * 64}), encoding="utf-8")
        result = services.ledger.verify()
        assert not result["ok"] and "entry 1" in result["error"]


class TestAdminCli:
    def test_verify_ledger_refuses_a_missing_database(self, tmp_path, monkeypatch, capsys):
        config = tmp_path / "settings.yaml"
        config.write_text(f"server:\n  db_path: {(tmp_path / 'absent.db').as_posix()}\n", encoding="utf-8")
        monkeypatch.setenv("CARYLLE_LEDGER_KEY", "k")
        monkeypatch.delenv("CARYLLE_DB_PATH", raising=False)
        assert cli.main(["verify-ledger", "--config", str(config)]) == 2
        assert not (tmp_path / "absent.db").exists()

    def test_agent_token_rejects_odd_ids(self, monkeypatch, capsys):
        monkeypatch.setenv("CARYLLE_AGENT_MASTER_SECRET", "m")
        assert cli.main(["agent-token", "host one\n"]) == 2
        assert cli.main(["agent-token", "host-1.lab"]) == 0
        assert capsys.readouterr().out.startswith("host-1.lab.")


class TestAgentState:
    def test_replay_guard_survives_a_non_object_state_file(self, tmp_path):
        (tmp_path / "seen_commands.json").write_text("[1, 2, 3]", encoding="utf-8")
        guard = ReplayGuard(tmp_path)
        assert guard.first_time("cmd-1", time.time() + 60)
        assert not guard.first_time("cmd-1", time.time() + 60)

    def test_unreadable_file_is_put_back_with_an_honest_reason(self, tmp_path, monkeypatch):
        safelist = AgentSafelist.load(ROOT / "config/safelist.yaml")
        quarantine = FileQuarantine(tmp_path / "q", safelist)
        path = tmp_path / "evil.bin"
        path.write_bytes(b"malicious")
        target = {"path": str(path), "sha256": sha256_file(path)}

        monkeypatch.setattr("carylle_agent.actuators.file_quarantine.sha256_file", lambda _p: None)
        result = quarantine.quarantine(target)
        assert result.status == "refused" and "could not be read" in result.detail
        assert path.read_bytes() == b"malicious"
        assert list(quarantine.directory.glob("*.bin")) == []


class TestFileWatcherDebounce:
    def test_a_file_that_never_goes_quiet_is_still_reported(self, tmp_path, monkeypatch):
        import threading

        from carylle_agent.sensors import file_watcher as fw

        clock = {"now": 100.0}
        monkeypatch.setattr(fw.time, "monotonic", lambda: clock["now"])
        events: list[dict] = []
        watcher = fw.FileWatcher(
            events.append, threading.Event(), [str(tmp_path)], debounce_seconds=0.5, max_delay_seconds=5.0
        )
        target = tmp_path / "payload.bin"
        target.write_bytes(b"x")

        watcher.record(str(target), "created")
        # Touched every 0.2 s: never quiet for the 0.5 s debounce.
        for _ in range(24):
            clock["now"] += 0.2
            watcher.record(str(target), "modified")
            watcher._flush()
        assert events == [], "reported before max_delay"
        clock["now"] += 0.2
        watcher.record(str(target), "modified")
        watcher._flush()
        assert len(events) == 1 and events[0]["data"]["action"] == "created"


class TestLoopback:
    def test_every_spelling_of_loopback_is_local(self):
        from carylle_agent.sensors.network_sniffer import is_local

        for ip in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "::1%lo"]:
            assert is_local(ip), ip
        for ip in ["203.0.113.10", "::ffff:203.0.113.10", "2001:db8::1", "", "not-an-ip"]:
            assert not is_local(ip), ip


class TestMoreSecrets:
    def test_common_cloud_keys_are_redacted(self):
        from carylle.pipeline.reasoning.sanitizer import redact_secrets

        leaks = {
            "openai_key": "sk-proj-" + "A1b2C3d4" * 5,
            "google_api_key": "AIza" + "B" * 35,
            "gitlab_token": "glpat-" + "x1Y2z3" * 4,
        }
        for label, secret in leaks.items():
            cleaned, count = redact_secrets(f"curl -H 'key: {secret}' https://example.com")
            assert secret not in cleaned and f"REDACTED:{label}" in cleaned and count == 1, (label, cleaned)

    def test_anthropic_keys_keep_their_own_label(self):
        from carylle.pipeline.reasoning.sanitizer import redact_secrets

        cleaned, _ = redact_secrets("sk-ant-api03-" + "q" * 40)
        assert "REDACTED:anthropic_key" in cleaned and "openai_key" not in cleaned

    def test_ordinary_words_are_left_alone(self):
        from carylle.pipeline.reasoning.sanitizer import redact_secrets

        text = "pip install scikit-learn && ./sk-tool --help"
        assert redact_secrets(text) == (text, 0)
