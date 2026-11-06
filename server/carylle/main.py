"""Carylle server: agent ingest, command channel and operator API."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import MissingSecrets, Secrets, ServerSettings, Settings, load_secrets, load_settings
from .models import ActionState, EventType
from .pipeline.engine import Engine
from .pipeline.normalizer import normalize_batch
from .pipeline.reasoning.llm_client import LLMClient
from .pipeline.reasoning.mitre_mapper import MitreMapper
from .pipeline.response.action_ledger import ActionLedger
from .pipeline.response.guardrails import VALID_MODES, Guardrails, Safelist
from .pipeline.response.orchestrator import ActionError, Orchestrator, load_playbooks
from .security import CommandSigner, verify_agent_token, verify_operator_token
from .store import Store

log = logging.getLogger("carylle")


class EventBatch(BaseModel):
    events: list[Any]


class CommandResult(BaseModel):
    status: str = Field(max_length=32)
    detail: str = Field(default="", max_length=4000)


class Decision(BaseModel):
    operator: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=500)


class ModeChange(BaseModel):
    mode: str
    operator: str = Field(min_length=1, max_length=128)


class _BodyTooLarge(HTTPException):
    # An HTTPException, because FastAPI turns any other error raised while it reads the
    # body into a generic 400.
    def __init__(self) -> None:
        super().__init__(413, "request body too large")


class BodyLimit:
    """Cap request bodies, counting the bytes actually received.

    Checking Content-Length alone is not enough: a chunked upload carries no length
    header and would otherwise be read into memory whole.
    """

    def __init__(self, app: ASGIApp, server: ServerSettings):
        self.app = app
        # Read the limit per request, so a settings change applies without a restart.
        self.server = server

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = self.server.max_body_bytes

        length = dict(scope["headers"]).get(b"content-length")
        if length is not None:
            try:
                declared = int(length)
            except ValueError:
                await JSONResponse({"detail": "invalid content-length"}, 400)(scope, receive, send)
                return
            if declared > max_bytes:
                await JSONResponse({"detail": "request body too large"}, 413)(scope, receive, send)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await JSONResponse({"detail": "request body too large"}, 413)(scope, receive, send)


@dataclass
class Services:
    settings: Settings
    secrets: Secrets
    store: Store
    ledger: ActionLedger
    guardrails: Guardrails
    orchestrator: Orchestrator
    engine: Engine
    mapper: MitreMapper
    llm: LLMClient


def build_services(settings: Settings, secrets: Secrets, llm: LLMClient | None = None) -> Services:
    store = Store(settings.server.db_path)
    ledger = ActionLedger(store, secrets.ledger_key, settings.server.ledger_anchor_path)
    # A missing safelist or broken playbook file raises here on purpose. Running without
    # them would mean acting with no idea what must be protected.
    safelist = Safelist.load(settings.server.safelist_path)
    playbooks = load_playbooks(settings.server.playbooks_path)
    guardrails = Guardrails(settings.response, safelist, store)
    orchestrator = Orchestrator(
        store, ledger, guardrails, playbooks, CommandSigner(secrets.command_signing_key), settings.response
    )
    mapper = MitreMapper.load(settings.server.mitre_path)
    llm = llm or LLMClient(settings.llm)
    engine = Engine(store, ledger, orchestrator, llm, mapper, settings.pipeline)
    return Services(settings, secrets, store, ledger, guardrails, orchestrator, engine, mapper, llm)


def create_app(
    settings: Settings | None = None,
    secrets: Secrets | None = None,
    *,
    llm: LLMClient | None = None,
    run_worker: bool = True,
) -> FastAPI:
    settings = settings or load_settings()
    secrets = secrets or load_secrets()
    services = build_services(settings, secrets, llm)
    wake = threading.Event()

    def worker_tick() -> None:
        # Drain a backlog before sleeping, so a burst isn't worked off one poll at a time.
        batch = 1000
        while services.engine.process_pending(batch).events >= batch:
            pass
        services.orchestrator.expire_stale()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = None
        if run_worker:
            stopping = asyncio.Event()

            async def worker() -> None:
                while not stopping.is_set():
                    try:
                        await asyncio.to_thread(worker_tick)
                    except Exception:
                        log.exception("pipeline worker error")
                    await asyncio.to_thread(wake.wait, settings.pipeline.worker_poll_seconds)
                    wake.clear()

            task = asyncio.create_task(worker())
        log.info("Carylle server ready. Response mode: %s", services.guardrails.mode)
        yield
        if task:
            stopping.set()
            wake.set()
            await task
        services.store.close()

    app = FastAPI(title="Carylle", version="0.1.0", lifespan=lifespan)
    app.state.services = services
    app.state.worker_tick = worker_tick

    app.add_middleware(BodyLimit, server=settings.server)

    def _bearer(authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
        return authorization[7:].strip()

    def require_agent(authorization: Annotated[str | None, Header()] = None) -> str:
        agent_id = verify_agent_token(secrets.agent_master_secret, _bearer(authorization))
        if agent_id is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
        if agent_id in settings.server.revoked_agents:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "agent revoked")
        return agent_id

    def require_operator(authorization: Annotated[str | None, Header()] = None) -> None:
        if not verify_operator_token(secrets.operator_token, _bearer(authorization)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")

    # Annotated[...] aliases defined in a closure can't be resolved under postponed
    # annotations, so the agent dependency is passed as a parameter default.
    agent_auth = Depends(require_agent)
    operator_only = [Depends(require_operator)]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # --- Agent API. Plain def handlers run in FastAPI's threadpool, off the event loop. ---

    @app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED)
    def ingest(batch: EventBatch, agent_id: str = agent_auth) -> dict[str, int]:
        if len(batch.events) > settings.server.max_batch_events:
            raise HTTPException(413, "too many events in batch")
        accepted, rejected = normalize_batch(batch.events, agent_id)
        health = next((e.health for e in reversed(accepted) if e.type is EventType.AGENT_HEALTH), None)
        services.store.touch_agent(agent_id, health)
        inserted = services.store.insert_events(accepted)
        if inserted:
            wake.set()
        return {"accepted": inserted, "duplicates": len(accepted) - inserted, "rejected": len(rejected)}

    @app.get("/api/v1/commands")
    def get_commands(agent_id: str = agent_auth) -> dict[str, list[dict[str, Any]]]:
        services.store.touch_agent(agent_id)
        return {"commands": services.orchestrator.dispatch(agent_id)}

    @app.post("/api/v1/commands/{command_id}/result")
    def post_result(command_id: str, result: CommandResult, agent_id: str = agent_auth) -> dict[str, str]:
        try:
            action = services.orchestrator.record_result(agent_id, command_id, result.status, result.detail)
        except ActionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"state": action["state"]}

    # --- Operator API ---

    @app.get("/api/v1/status", dependencies=operator_only)
    def get_status() -> dict[str, Any]:
        return {
            "mode": services.guardrails.mode,
            "llm_enabled": settings.llm.enabled,
            "llm_model": settings.llm.model,
            "attack_techniques_loaded": len(services.mapper.techniques),
            "pending_approvals": services.store.count_actions(ActionState.PENDING_APPROVAL.value),
            "agents": len(services.store.list_agents()),
        }

    @app.get("/api/v1/cases", dependencies=operator_only)
    def list_cases(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100, agent_id: str | None = None
    ) -> dict[str, Any]:
        return {"cases": services.store.list_cases(limit, agent_id)}

    @app.get("/api/v1/cases/{case_id}", dependencies=operator_only)
    def get_case(case_id: str) -> dict[str, Any]:
        case = services.store.get_case(case_id)
        if case is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
        case["attack"] = services.mapper.enrich(case["verdict"]["techniques"])
        case["events"] = [
            e.model_dump(mode="json") for e in services.store.get_events(case["agent_id"], case["event_ids"])
        ]
        case["actions"] = services.store.list_actions(case_id=case_id)
        return case

    @app.get("/api/v1/actions", dependencies=operator_only)
    def list_actions(
        state: str | None = None,
        case_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        return {"actions": services.store.list_actions(state, case_id, limit)}

    @app.post("/api/v1/actions/{action_id}/approve", dependencies=operator_only)
    def approve(action_id: str, decision: Decision) -> dict[str, Any]:
        try:
            return services.orchestrator.approve(action_id, decision.operator)
        except ActionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @app.post("/api/v1/actions/{action_id}/reject", dependencies=operator_only)
    def reject(action_id: str, decision: Decision) -> dict[str, Any]:
        try:
            return services.orchestrator.reject(action_id, decision.operator, decision.note)
        except ActionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @app.get("/api/v1/agents", dependencies=operator_only)
    def list_agents() -> dict[str, Any]:
        return {"agents": services.store.list_agents(), "now": time.time()}

    @app.get("/api/v1/ledger", dependencies=operator_only)
    def ledger_entries(
        after_seq: Annotated[int, Query(ge=0)] = 0, limit: Annotated[int, Query(ge=1, le=1000)] = 200
    ) -> dict[str, Any]:
        return {"entries": services.ledger.entries(after_seq, limit)}

    @app.get("/api/v1/ledger/verify", dependencies=operator_only)
    def ledger_verify() -> dict[str, Any]:
        return services.ledger.verify()

    @app.post("/api/v1/response/mode", dependencies=operator_only)
    def set_mode(change: ModeChange) -> dict[str, str]:
        """Setting observe also works as a kill switch: approved commands stop going out."""
        if change.mode not in VALID_MODES:
            raise HTTPException(422, f"mode must be one of {sorted(VALID_MODES)}")
        previous = services.guardrails.mode
        services.guardrails.set_mode(change.mode)
        services.ledger.append(
            "mode_changed", {"from": previous, "to": change.mode, "operator": change.operator}
        )
        return {"mode": change.mode}

    return app


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="carylle-server", description=__doc__)
    parser.add_argument("--config", default=None)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("CARYLLE_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    import uvicorn

    settings = load_settings(args.config)
    cert, key = os.environ.get("CARYLLE_TLS_CERT"), os.environ.get("CARYLLE_TLS_KEY")
    if not (cert and key) and not settings.server.allow_plaintext and not _is_loopback(settings.server.host):
        print(
            "Refusing to serve bearer tokens over plain HTTP on a non-loopback address. "
            "Set CARYLLE_TLS_CERT and CARYLLE_TLS_KEY (see: carylle-admin gen-cert).",
            file=sys.stderr,
        )
        return 2
    try:
        secrets = load_secrets()
    except MissingSecrets as exc:
        print(str(exc), file=sys.stderr)
        return 2

    app = create_app(settings, secrets)
    uvicorn.run(app, host=settings.server.host, port=settings.server.port, ssl_certfile=cert, ssl_keyfile=key)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
