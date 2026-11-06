"""The real thing: a uvicorn server on a socket, the real agent code, and real effects.

Sensors are pointed only at a temp directory, and the agent acts only on child processes
started here. Nothing else on the machine can be touched.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

import psutil
import pytest
import uvicorn
from carylle.main import create_app
from carylle.security import derive_agent_token
from carylle_agent.config import AgentConfig
from carylle_agent.main import Agent

from purple import runner

from .conftest import ROOT, FakeLLM

# Real antivirus (Windows Defender on a dev machine) quarantines EICAR and web shell samples
# the moment they reach disk. So the shipped rules are tested in memory, and tests that need
# a file on disk use a rule matching this harmless marker.
MARKER = "CARYLLE-TEST-MARKER-" + "7f3a9c"
MARKER_RULE = (
    'rule Carylle_Test_Marker { meta: severity = "high" attack = "T1204.002" '
    f'strings: $a = "{MARKER}" condition: $a }}'
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def live_server(settings, secrets, monkeypatch, mapper):
    monkeypatch.setattr("carylle.main.MitreMapper.load", lambda _path: mapper)
    settings.pipeline.worker_poll_seconds = 0.2
    # Scenarios all report from one host, and the limit isn't what's under test here.
    settings.response.max_actions_per_host_per_hour = 1000
    app = create_app(settings, secrets, llm=FakeLLM())
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield f"http://127.0.0.1:{port}", secrets
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def api(live_server):
    url, secrets = live_server
    return runner.Api(url, secrets.operator_token)


def test_agent_detects_and_quarantines_a_real_file(live_server, api, tmp_path):
    url, secrets = live_server
    watched = tmp_path / "watched"
    watched.mkdir()
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "marker.yar").write_text(MARKER_RULE, encoding="ascii")
    config = AgentConfig(
        agent_id="e2e-agent",
        token=derive_agent_token(secrets.agent_master_secret, "e2e-agent"),
        command_public_key=secrets.command_public_key,
        server_url=url,
        safelist_path=str(ROOT / "config/safelist.yaml"),
        flush_interval_seconds=0.2,
        command_poll_seconds=0.2,
        heartbeat_seconds=1,
        spool_dir=str(tmp_path / "spool"),
        state_dir=str(tmp_path / "state"),
        quarantine_dir=str(tmp_path / "quarantine"),
        actuators_enabled=True,
        sensors={
            "process_monitor": {"enabled": False},
            "network_sniffer": {"enabled": False},
            "file_watcher": {"enabled": True, "paths": [str(watched)], "debounce_seconds": 0.1},
        },
        yara={"enabled": True, "rules_dir": str(rules)},
    )
    agent = Agent(config)
    thread = threading.Thread(target=agent.run, daemon=True)
    thread.start()
    try:
        time.sleep(1)
        sample = watched / "sample.txt"
        sample.write_text(MARKER, encoding="ascii")

        deadline = time.time() + 30
        action = None
        while time.time() < deadline:
            actions = api.operator.get("/api/v1/actions", params={"state": "succeeded"}).json()["actions"]
            action = next((a for a in actions if a["type"] == "quarantine_file"), None)
            if action:
                break
            time.sleep(0.2)
        assert action, api.operator.get("/api/v1/actions").json()
        assert not sample.exists()
        assert agent.quarantine.list_items()[0]["original_path"] == str(sample)

        agents = api.operator.get("/api/v1/agents").json()["agents"]
        record = next(a for a in agents if a["agent_id"] == "e2e-agent")
        assert record["health"]["yara_available"] is True and record["health"]["actuators_enabled"] is True
        assert api.ledger_verify()["ok"]
    finally:
        agent.stop.set()
        thread.join(timeout=15)


def test_agent_terminates_a_real_process_end_to_end(live_server, api, tmp_path):
    """The server decides, signs and dispatches. The agent verifies and kills the process."""
    url, secrets = live_server
    token = derive_agent_token(secrets.agent_master_secret, "e2e-agent-2")
    config = AgentConfig(
        agent_id="e2e-agent-2",
        token=token,
        command_public_key=secrets.command_public_key,
        server_url=url,
        safelist_path=str(ROOT / "config/safelist.yaml"),
        spool_dir=str(tmp_path / "spool"),
        state_dir=str(tmp_path / "state"),
        quarantine_dir=str(tmp_path / "quarantine"),
        actuators_enabled=True,
        sensors={
            "process_monitor": {"enabled": False},
            "network_sniffer": {"enabled": False},
            "file_watcher": {"enabled": False},
        },
        yara={"enabled": False},
    )
    agent = Agent(config)
    # The comment makes the command line match the reverse shell rule. The process only sleeps.
    code = "import time; time.sleep(60) # socket dup2"
    decoy = subprocess.Popen([sys.executable, "-c", code])
    try:
        live = psutil.Process(decoy.pid)
        cmdline = f"python3 -c {code}"
        event = {
            "event_id": f"decoy-{decoy.pid}",
            "type": "process_start",
            "ts": time.time(),
            "data": {
                "pid": decoy.pid,
                "ppid": live.ppid(),
                "name": live.name(),
                "exe": live.exe(),
                "cmdline": cmdline,
                "create_time": live.create_time(),
            },
        }
        assert agent.transport.send_events([event])

        deadline = time.time() + 15
        while time.time() < deadline and decoy.poll() is None:
            agent.poll_commands_once()
            time.sleep(0.2)
        assert decoy.poll() is not None, api.operator.get("/api/v1/actions").json()

        actions = api.operator.get("/api/v1/actions", params={"state": "succeeded"}).json()["actions"]
        assert [a["type"] for a in actions] == ["terminate_process"]
    finally:
        if decoy.poll() is None:
            decoy.kill()
        decoy.wait(timeout=5)
        agent.transport.close()


def test_purple_synthetic_scorecard_passes(live_server, tmp_path):
    url, secrets = live_server
    agent_token = derive_agent_token(secrets.agent_master_secret, "purple-synthetic")
    api = runner.Api(url, secrets.operator_token, agent_token)
    results = runner.run_synthetic(api, timeout=10, settle=1.0)
    results += runner.check_auth(api)
    failed = [(r.id, r.detail) for r in results if not r.passed]
    assert not failed, failed
    assert len(results) >= 20

    stem = str(tmp_path / "report")
    runner.write_report(results, stem)
    assert "checks passed" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_live_mode_refuses_outside_a_lab(monkeypatch):
    monkeypatch.delenv("CARYLLE_LAB", raising=False)
    with pytest.raises(SystemExit, match="Refusing live mode"):
        runner.assert_lab_host()

    # The environment variable alone isn't enough: the marker file must exist too.
    monkeypatch.setenv("CARYLLE_LAB", "1")
    monkeypatch.setattr(runner, "LAB_MARKER", ROOT / "does-not-exist")
    with pytest.raises(SystemExit, match="Refusing live mode"):
        runner.assert_lab_host()
