"""Network metadata: outbound connections, plus DNS queries where capture is permitted.

Records metadata only. It never reads or stores application payloads: the DNS parser
looks at question names and nothing else. Raw capture needs scapy and CAP_NET_RAW, and
without them the sensor continues with connection polling alone.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import psutil

from ..util import make_event

log = logging.getLogger(__name__)

_REMOTE_STATES = {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT}
_SEEN_TTL_SECONDS = 600
_DNS_TTL_SECONDS = 60
_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


class NetworkSniffer(threading.Thread):
    def __init__(
        self,
        emit: Callable[[dict[str, Any]], None],
        stop: threading.Event,
        mode: str = "auto",
        poll_seconds: float = 5.0,
        interface: str | None = None,
    ):
        super().__init__(name="network-sniffer", daemon=True)
        self._emit = emit
        self._stop_event = stop
        self._mode = mode
        self._poll = poll_seconds
        self._interface = interface
        self._seen: dict[tuple, float] = {}
        self._dns_seen: dict[str, float] = {}
        self.dns_capture_active = False

    def poll_connections(self) -> None:
        now = time.monotonic()
        self._seen = {k: t for k, t in self._seen.items() if now - t < _SEEN_TTL_SECONDS}
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr or conn.status not in _REMOTE_STATES:
                continue
            # Loopback is local plumbing, not something leaving the machine.
            if conn.raddr.ip.startswith("127.") or conn.raddr.ip == "::1":
                continue
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            if key in self._seen:
                continue
            self._seen[key] = now
            name = ""
            if conn.pid:
                try:
                    name = psutil.Process(conn.pid).name()
                except psutil.Error:
                    pass
            self._emit(
                make_event(
                    "network_connection",
                    {
                        "src_ip": conn.laddr.ip if conn.laddr else "",
                        "src_port": conn.laddr.port if conn.laddr else None,
                        "dst_ip": conn.raddr.ip,
                        "dst_port": conn.raddr.port,
                        "proto": "tcp" if conn.type == 1 else "udp",
                        "pid": conn.pid,
                        "process_name": name,
                        "status": conn.status,
                    },
                )
            )

    def _on_packet(self, packet: Any) -> None:
        try:
            from scapy.layers.dns import DNSQR

            if not packet.haslayer(DNSQR):
                return
            question = packet[DNSQR]
            qname = question.qname.decode("utf-8", "replace").rstrip(".")
            now = time.monotonic()
            # Repeats of the same name would just be noise, so report once a minute.
            if now - self._dns_seen.get(qname, -_DNS_TTL_SECONDS) < _DNS_TTL_SECONDS:
                return
            if len(self._dns_seen) > 10000:
                self._dns_seen.clear()
            self._dns_seen[qname] = now
            self._emit(make_event("dns_query", {"qname": qname, "qtype": _QTYPES.get(question.qtype, str(question.qtype))}))
        except Exception:
            log.debug("could not parse DNS packet", exc_info=True)

    def _start_capture(self) -> Any | None:
        if self._mode not in {"auto", "capture"}:
            return None
        try:
            from scapy.all import AsyncSniffer

            sniffer = AsyncSniffer(
                iface=self._interface, filter="udp port 53", store=False, prn=self._on_packet
            )
            sniffer.start()
            self.dns_capture_active = True
            log.info("DNS capture active")
            return sniffer
        except Exception as exc:
            log.info("DNS capture unavailable (%s): connection polling only", exc)
            return None

    def run(self) -> None:
        capture = self._start_capture()
        try:
            while not self._stop_event.wait(self._poll):
                try:
                    self.poll_connections()
                except psutil.AccessDenied:
                    log.warning("Not permitted to list connections: run the agent with more privilege")
                except Exception:
                    log.exception("connection poll failed")
        finally:
            if capture is not None:
                try:
                    capture.stop()
                except Exception:
                    log.debug("capture stop failed", exc_info=True)
