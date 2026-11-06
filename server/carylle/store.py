"""SQLite persistence. A single connection behind a lock keeps writes ordered."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import ActionState, NormalizedEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    agent_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ts REAL NOT NULL,
    received_at REAL NOT NULL,
    type TEXT NOT NULL,
    body TEXT NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_events_unprocessed ON events(processed, received_at);
CREATE INDEX IF NOT EXISTS idx_events_agent_time ON events(agent_id, received_at);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    severity TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    playbook_id TEXT,
    verdict TEXT NOT NULL,
    event_ids TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_time ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_cases_fp ON cases(fingerprint, source, created_at);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    state TEXT NOT NULL,
    playbook_id TEXT,
    reasons TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    expires_at REAL,
    decided_by TEXT,
    result TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_state ON actions(state, agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_case ON actions(case_id);
CREATE INDEX IF NOT EXISTS idx_actions_dedupe ON actions(dedupe_key, state);

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    health TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    entry_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
"""

# States in which a new action on the same target would be a duplicate.
OPEN_STATES = (ActionState.PENDING_APPROVAL, ActionState.APPROVED, ActionState.DISPATCHED)
# States that count against rate limits: something really was, or is about to be, done.
EXECUTED_STATES = (
    ActionState.APPROVED,
    ActionState.DISPATCHED,
    ActionState.SUCCEEDED,
    ActionState.FAILED,
    ActionState.REFUSED,
)


class Store:
    def __init__(self, db_path: str):
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self.lock:
            self._conn.close()

    # --- agents ---------------------------------------------------------------

    def touch_agent(self, agent_id: str, health: dict | None = None) -> None:
        now = time.time()
        with self.lock:
            self._conn.execute(
                "INSERT INTO agents(agent_id, first_seen, last_seen, health) VALUES (?,?,?,?) "
                "ON CONFLICT(agent_id) DO UPDATE SET last_seen=excluded.last_seen, "
                "health=COALESCE(excluded.health, agents.health)",
                (agent_id, now, now, json.dumps(health) if health else None),
            )

    def list_agents(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
        return [
            {**dict(r), "health": json.loads(r["health"]) if r["health"] else None} for r in rows
        ]

    # --- events ---------------------------------------------------------------

    def insert_events(self, events: Iterable[NormalizedEvent]) -> int:
        inserted = 0
        with self.lock:
            self._conn.execute("BEGIN")
            try:
                for e in events:
                    cur = self._conn.execute(
                        "INSERT OR IGNORE INTO events"
                        "(agent_id, event_id, ts, received_at, type, body) VALUES (?,?,?,?,?,?)",
                        (e.agent_id, e.event_id, e.ts, e.received_at, e.type.value, e.model_dump_json()),
                    )
                    inserted += cur.rowcount
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return inserted

    def fetch_unprocessed(self, limit: int = 1000) -> list[NormalizedEvent]:
        with self.lock:
            rows = self._conn.execute(
                "SELECT body FROM events WHERE processed=0 ORDER BY received_at, rowid LIMIT ?", (limit,)
            ).fetchall()
        return [NormalizedEvent.model_validate_json(r["body"]) for r in rows]

    def mark_processed(self, events: Iterable[NormalizedEvent]) -> None:
        with self.lock:
            self._conn.executemany(
                "UPDATE events SET processed=1 WHERE agent_id=? AND event_id=?",
                [(e.agent_id, e.event_id) for e in events],
            )

    def recent_events(self, agent_id: str, since: float, limit: int = 2000) -> list[NormalizedEvent]:
        with self.lock:
            rows = self._conn.execute(
                "SELECT body FROM events WHERE agent_id=? AND received_at>=? "
                "ORDER BY received_at DESC, rowid DESC LIMIT ?",
                (agent_id, since, limit),
            ).fetchall()
        return [NormalizedEvent.model_validate_json(r["body"]) for r in rows]

    def get_events(self, agent_id: str, event_ids: list[str]) -> list[NormalizedEvent]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        with self.lock:
            rows = self._conn.execute(
                f"SELECT body FROM events WHERE agent_id=? AND event_id IN ({placeholders})",  # noqa: S608
                [agent_id, *event_ids],
            ).fetchall()
        return [NormalizedEvent.model_validate_json(r["body"]) for r in rows]

    def count_file_events(self, agent_id: str, since: float) -> int:
        with self.lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE agent_id=? AND type='file_event' AND received_at>=?",
                (agent_id, since),
            ).fetchone()
        return int(row["n"])

    # --- cases ----------------------------------------------------------------

    def insert_case(self, case: dict[str, Any]) -> None:
        with self.lock:
            self._conn.execute(
                "INSERT INTO cases(case_id, agent_id, created_at, severity, classification, confidence, "
                "source, fingerprint, playbook_id, verdict, event_ids) "
                "VALUES (:case_id,:agent_id,:created_at,:severity,:classification,:confidence,"
                ":source,:fingerprint,:playbook_id,:verdict,:event_ids)",
                case,
            )

    def set_case_playbook(self, case_id: str, playbook_id: str) -> None:
        with self.lock:
            self._conn.execute("UPDATE cases SET playbook_id=? WHERE case_id=?", (playbook_id, case_id))

    def llm_recently_used(self, fingerprint: str, since: float) -> bool:
        with self.lock:
            row = self._conn.execute(
                "SELECT 1 FROM cases WHERE fingerprint=? AND source='llm' AND created_at>=? LIMIT 1",
                (fingerprint, since),
            ).fetchone()
        return row is not None

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        out["verdict"] = json.loads(out["verdict"])
        out["event_ids"] = json.loads(out["event_ids"])
        return out

    def list_cases(self, limit: int = 100, agent_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM cases"
        params: list[Any] = []
        if agent_id:
            query += " WHERE agent_id=?"
            params.append(agent_id)
        query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(limit)
        with self.lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._case_row(r) for r in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self._conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return self._case_row(row) if row else None

    # --- actions --------------------------------------------------------------

    @staticmethod
    def _action_row(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        out["target"] = json.loads(out["target"])
        out["reasons"] = json.loads(out["reasons"])
        out["result"] = json.loads(out["result"]) if out["result"] else None
        return out

    def insert_action(self, action: dict[str, Any]) -> None:
        row = {
            **action,
            "target": json.dumps(action["target"], sort_keys=True),
            "reasons": json.dumps(action["reasons"]),
            "result": None,
            "decided_by": action.get("decided_by"),
        }
        with self.lock:
            self._conn.execute(
                "INSERT INTO actions(action_id, case_id, agent_id, type, target, dedupe_key, state, "
                "playbook_id, reasons, created_at, updated_at, expires_at, decided_by, result) VALUES "
                "(:action_id,:case_id,:agent_id,:type,:target,:dedupe_key,:state,:playbook_id,:reasons,"
                ":created_at,:updated_at,:expires_at,:decided_by,:result)",
                row,
            )

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self._conn.execute("SELECT * FROM actions WHERE action_id=?", (action_id,)).fetchone()
        return self._action_row(row) if row else None

    def list_actions(
        self, state: str | None = None, case_id: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if state:
            clauses.append("state=?")
            params.append(state)
        if case_id:
            clauses.append("case_id=?")
            params.append(case_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.lock:
            rows = self._conn.execute(
                f"SELECT * FROM actions{where} ORDER BY created_at DESC, rowid DESC LIMIT ?",  # noqa: S608
                [*params, limit],
            ).fetchall()
        return [self._action_row(r) for r in rows]

    def transition_action(
        self,
        action_id: str,
        from_states: Iterable[ActionState],
        to_state: ActionState,
        *,
        decided_by: str | None = None,
        result: dict | None = None,
        expires_at: float | None = None,
    ) -> bool:
        """Compare-and-set a state change, so two callers cannot both win the same transition."""
        states = [s.value for s in from_states]
        placeholders = ",".join("?" for _ in states)
        now = time.time()
        with self.lock:
            cur = self._conn.execute(
                f"UPDATE actions SET state=?, updated_at=?, "  # noqa: S608
                "decided_by=COALESCE(?, decided_by), result=COALESCE(?, result), "
                f"expires_at=COALESCE(?, expires_at) WHERE action_id=? AND state IN ({placeholders})",
                [
                    to_state.value,
                    now,
                    decided_by,
                    json.dumps(result) if result is not None else None,
                    expires_at,
                    action_id,
                    *states,
                ],
            )
        return cur.rowcount == 1

    def open_action_exists(self, dedupe_key: str) -> bool:
        placeholders = ",".join("?" for _ in OPEN_STATES)
        with self.lock:
            row = self._conn.execute(
                f"SELECT 1 FROM actions WHERE dedupe_key=? AND state IN ({placeholders}) LIMIT 1",  # noqa: S608
                [dedupe_key, *[s.value for s in OPEN_STATES]],
            ).fetchone()
        return row is not None

    def approved_actions_for(self, agent_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._conn.execute(
                "SELECT * FROM actions WHERE agent_id=? AND state=? ORDER BY created_at LIMIT ?",
                (agent_id, ActionState.APPROVED.value, limit),
            ).fetchall()
        return [self._action_row(r) for r in rows]

    def expirable_actions(self, now: float) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._conn.execute(
                "SELECT * FROM actions WHERE expires_at IS NOT NULL AND expires_at<? AND state IN (?,?,?)",
                (now, *[s.value for s in OPEN_STATES]),
            ).fetchall()
        return [self._action_row(r) for r in rows]

    def count_executed_actions(self, since: float, agent_id: str | None = None) -> int:
        placeholders = ",".join("?" for _ in EXECUTED_STATES)
        query = (
            f"SELECT COUNT(*) AS n FROM actions WHERE created_at>=? AND state IN ({placeholders})"  # noqa: S608
        )
        params: list[Any] = [since, *[s.value for s in EXECUTED_STATES]]
        if agent_id:
            query += " AND agent_id=?"
            params.append(agent_id)
        with self.lock:
            return int(self._conn.execute(query, params).fetchone()["n"])

    def count_hosts_with_actions(self, since: float) -> int:
        placeholders = ",".join("?" for _ in EXECUTED_STATES)
        with self.lock:
            row = self._conn.execute(
                f"SELECT COUNT(DISTINCT agent_id) AS n FROM actions "  # noqa: S608
                f"WHERE created_at>=? AND state IN ({placeholders})",
                [since, *[s.value for s in EXECUTED_STATES]],
            ).fetchone()
        return int(row["n"])

    # --- meta -----------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with self.lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def set_meta_if_absent(self, key: str, value: str) -> None:
        with self.lock:
            self._conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES (?,?)", (key, value))
