"""Tamper-evident audit log for every decision and action.

Each entry is an HMAC over the previous hash and its own content, so editing or removing
a row breaks the chain for anyone holding the key. SQLite triggers stop accidental edits.
A separate anchor file records the head, which catches the one thing a chain alone
misses: deleting entries from the end. Keep the anchor on storage the DB's writer can't
reach if you want that protection to hold against a compromised server.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from ...security import canonical_json
from ...store import Store

GENESIS = "0" * 64


class ActionLedger:
    def __init__(self, store: Store, key: str, anchor_path: str | None = None):
        self._store = store
        self._key = key.encode()
        self._anchor = Path(anchor_path) if anchor_path else None
        if self._anchor:
            self._anchor.parent.mkdir(parents=True, exist_ok=True)

    def _hash(self, seq: int, ts: float, entry_type: str, payload: str, prev_hash: str) -> str:
        material = canonical_json(
            {"seq": seq, "ts": ts, "type": entry_type, "payload": payload, "prev": prev_hash}
        )
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def append(self, entry_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self._store.lock:
            row = self._store.conn.execute(
                "SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = (row["seq"] + 1) if row else 1
            prev_hash = row["hash"] if row else GENESIS
            ts = time.time()
            digest = self._hash(seq, ts, entry_type, body, prev_hash)
            self._store.conn.execute(
                "INSERT INTO ledger(seq, ts, entry_type, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (seq, ts, entry_type, body, prev_hash, digest),
            )
            self._write_anchor(seq, digest)
        return {"seq": seq, "hash": digest}

    def _write_anchor(self, seq: int, digest: str) -> None:
        if not self._anchor:
            return
        tmp = self._anchor.with_suffix(self._anchor.suffix + ".tmp")
        tmp.write_text(json.dumps({"seq": seq, "hash": digest}), encoding="utf-8")
        os.replace(tmp, self._anchor)

    def entries(self, after_seq: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        with self._store.lock:
            rows = self._store.conn.execute(
                "SELECT * FROM ledger WHERE seq>? ORDER BY seq LIMIT ?", (after_seq, limit)
            ).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]

    def verify(self) -> dict[str, Any]:
        """Walk the whole chain. Returns ok plus the first problem found."""
        expected_seq = 1
        prev_hash = GENESIS
        count = 0
        with self._store.lock:
            cursor = self._store.conn.execute("SELECT * FROM ledger ORDER BY seq")
            for row in cursor:
                if row["seq"] != expected_seq:
                    return self._bad(count, prev_hash, f"sequence gap at {expected_seq}, found {row['seq']}")
                if row["prev_hash"] != prev_hash:
                    return self._bad(count, prev_hash, f"broken link at seq {row['seq']}")
                digest = self._hash(row["seq"], row["ts"], row["entry_type"], row["payload"], row["prev_hash"])
                if not hmac.compare_digest(digest, row["hash"]):
                    return self._bad(count, prev_hash, f"hash mismatch at seq {row['seq']}")
                prev_hash = row["hash"]
                expected_seq += 1
                count += 1

        anchor_status = "not_configured"
        if self._anchor:
            if self._anchor.exists():
                anchor = json.loads(self._anchor.read_text(encoding="utf-8"))
                if anchor["seq"] > count:
                    return self._bad(count, prev_hash, f"anchor at seq {anchor['seq']} but only {count} entries: truncated")
                if anchor["seq"] == count and anchor["hash"] != prev_hash:
                    return self._bad(count, prev_hash, "head does not match the anchor")
                anchor_status = "ok"
            elif count:
                return self._bad(count, prev_hash, "ledger has entries but the anchor is missing")
            else:
                anchor_status = "empty"
        return {"ok": True, "entries": count, "head": prev_hash, "anchor": anchor_status, "error": None}

    @staticmethod
    def _bad(count: int, head: str, error: str) -> dict[str, Any]:
        return {"ok": False, "entries": count, "head": head, "anchor": None, "error": error}
