"""Talk to the server. If it can't be reached, events wait on disk rather than disappear.

An attacker who cuts the network shouldn't erase the record of what happened while it
was down, so failed batches go to a size-capped spool and are replayed first on recovery.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)


class TransportConfigError(RuntimeError):
    pass


def check_url_is_safe(url: str, allow_insecure_http: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme == "https":
        return
    if parts.scheme != "http":
        raise TransportConfigError(f"unsupported server URL scheme: {parts.scheme!r}")
    host = parts.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and not allow_insecure_http:
        raise TransportConfigError(
            "Refusing to send a bearer token over plain HTTP to a non-loopback server. "
            "Use https://, or set allow_insecure_http for an isolated lab."
        )


class Transport:
    def __init__(
        self,
        server_url: str,
        token: str,
        *,
        verify_tls: bool | str = True,
        allow_insecure_http: bool = False,
        spool_dir: str | Path = "var/spool",
        spool_max_bytes: int = 100 * 1024 * 1024,
        timeout: float = 15.0,
        client: httpx.Client | None = None,
    ):
        check_url_is_safe(server_url, allow_insecure_http)
        self._client = client or httpx.Client(
            base_url=server_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            verify=verify_tls,
            timeout=timeout,
        )
        self._spool_dir = Path(spool_dir)
        self._spool_max_bytes = spool_max_bytes
        self.spool_dropped = 0
        self._retry_at = 0.0
        self._failures = 0

    def close(self) -> None:
        self._client.close()

    # --- backoff --------------------------------------------------------------

    def _online(self) -> bool:
        return time.monotonic() >= self._retry_at

    def _note_failure(self) -> None:
        self._failures += 1
        delay = min(2 ** self._failures, 60)
        self._retry_at = time.monotonic() + delay

    def _note_success(self) -> None:
        self._failures = 0
        self._retry_at = 0.0

    # --- events ---------------------------------------------------------------

    def _post_events(self, events: list[dict[str, Any]]) -> str:
        """Returns 'sent', 'retry' (keep it) or 'drop' (the server will never accept it)."""
        try:
            response = self._client.post("/api/v1/events", json={"events": events})
        except httpx.HTTPError as exc:
            log.warning("Server unreachable: %s", type(exc).__name__)
            return "retry"
        if response.status_code < 300:
            return "sent"
        if response.status_code in {401, 403}:
            log.error("Server rejected this agent's token (%s): spooling", response.status_code)
            return "retry"
        if response.status_code == 429 or response.status_code >= 500:
            return "retry"
        log.error("Server refused a batch of %d events (%s): dropping it", len(events), response.status_code)
        return "drop"

    def send_events(self, events: list[dict[str, Any]]) -> bool:
        """Deliver events or spool them. Returns True if they reached the server."""
        if not events:
            return True
        if self._online():
            self._replay_spool()
        if not self._online():
            self._spool(events)
            return False
        outcome = self._post_events(events)
        if outcome == "retry":
            self._note_failure()
            self._spool(events)
            return False
        self._note_success()
        return outcome == "sent"

    # --- spool ----------------------------------------------------------------

    def _spool_files(self) -> list[Path]:
        return sorted(self._spool_dir.glob("*.jsonl")) if self._spool_dir.exists() else []

    def _spool(self, events: list[dict[str, Any]]) -> None:
        try:
            self._spool_dir.mkdir(parents=True, exist_ok=True)
            # Timestamp-first names keep replay in the original order.
            name = f"{time.time_ns():020d}-{os.getpid()}.jsonl"
            tmp = self._spool_dir / f"{name}.tmp"
            tmp.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            os.replace(tmp, self._spool_dir / name)
            self._enforce_spool_cap()
        except OSError:
            self.spool_dropped += len(events)
            log.exception("Could not spool %d events", len(events))

    def _enforce_spool_cap(self) -> None:
        files = self._spool_files()
        total = sum(f.stat().st_size for f in files)
        while files and total > self._spool_max_bytes:
            oldest = files.pop(0)
            total -= oldest.stat().st_size
            self.spool_dropped += sum(1 for _ in oldest.open(encoding="utf-8"))
            oldest.unlink()
            log.error("Spool over its cap: dropped %s", oldest.name)

    def _replay_spool(self) -> None:
        for path in self._spool_files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
                events = [json.loads(line) for line in lines if line]
            except (OSError, ValueError):
                log.error("Corrupt spool file removed: %s", path.name)
                path.unlink(missing_ok=True)
                continue
            outcome = self._post_events(events)
            if outcome == "retry":
                self._note_failure()
                return
            path.unlink(missing_ok=True)
            self._note_success()

    def flush_spool(self) -> None:
        if self._online():
            self._replay_spool()

    # --- commands -------------------------------------------------------------

    def fetch_commands(self) -> list[dict[str, Any]]:
        try:
            response = self._client.get("/api/v1/commands")
            response.raise_for_status()
            commands = response.json().get("commands", [])
            return commands if isinstance(commands, list) else []
        except (httpx.HTTPError, ValueError) as exc:
            log.debug("Could not fetch commands: %s", type(exc).__name__)
            return []

    def send_result(self, command_id: str, status: str, detail: str, attempts: int = 3) -> bool:
        for attempt in range(attempts):
            try:
                response = self._client.post(
                    f"/api/v1/commands/{command_id}/result", json={"status": status, "detail": detail}
                )
                if response.status_code < 300:
                    return True
                if response.status_code < 500:
                    log.error("Server refused result for %s: %s", command_id, response.status_code)
                    return False
            except httpx.HTTPError as exc:
                log.warning("Could not report result for %s: %s", command_id, type(exc).__name__)
            if attempt + 1 < attempts:
                time.sleep(min(2 ** attempt, 5))
        log.error("Gave up reporting result for %s after %d attempts", command_id, attempts)
        return False
