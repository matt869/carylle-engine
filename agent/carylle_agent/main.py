"""Carylle endpoint agent."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import queue
import signal
import sys
import threading
from typing import Any

from . import __version__
from .actuators.file_quarantine import FileQuarantine
from .commands import CommandExecutor, ReplayGuard
from .config import AgentConfig, ConfigError, load_config
from .safelist import AgentSafelist
from .scanners.yara_scanner import YaraScanner
from .transport import Transport, TransportConfigError
from .util import make_event

log = logging.getLogger("carylle_agent")


class Agent:
    def __init__(self, config: AgentConfig, transport: Transport | None = None):
        self.config = config
        self.stop = threading.Event()
        self.queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=config.queue_size)
        self.dropped = 0
        self.transport = transport or Transport(
            config.server_url,
            config.token,
            verify_tls=config.verify_tls,
            allow_insecure_http=config.allow_insecure_http,
            spool_dir=config.spool_dir,
            spool_max_bytes=config.spool_max_bytes,
        )
        self.safelist = AgentSafelist.load(config.safelist_path)
        if not self.safelist.loaded:
            log.error("Safelist %s could not be loaded: all response actions will be refused", config.safelist_path)
        self.quarantine = FileQuarantine(config.quarantine_dir, self.safelist)
        self.executor = CommandExecutor(
            config.agent_id,
            config.command_public_key,
            self.safelist,
            self.quarantine,
            ReplayGuard(config.state_dir),
            actuators_enabled=config.actuators_enabled,
            terminate_grace_seconds=config.terminate_grace_seconds,
        )
        self.scanner: YaraScanner | None = None
        self.sensors: dict[str, threading.Thread] = {}

    def emit(self, event: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            # Reported in the heartbeat, because a gap in telemetry is itself a signal.
            self.dropped += 1

    def _build_sensors(self) -> None:
        sensors = self.config.sensors
        yara_cfg = self.config.yara or {}
        if yara_cfg.get("enabled", True):
            self.scanner = YaraScanner(
                yara_cfg.get("rules_dir", "config/yara"),
                yara_cfg.get("timeout_seconds", 30),
                yara_cfg.get("max_scan_bytes", 64 * 1024 * 1024),
            )

        process_cfg = sensors.get("process_monitor") or {}
        if process_cfg.get("enabled", True):
            from .sensors.process_monitor import ProcessMonitor

            self.sensors["process_monitor"] = ProcessMonitor(
                self.emit, self.stop, process_cfg.get("poll_seconds", 1.0), process_cfg.get("max_hash_bytes", 64 * 1024 * 1024)
            )

        file_cfg = sensors.get("file_watcher") or {}
        if file_cfg.get("enabled", True):
            from .sensors.file_watcher import FileWatcher

            self.sensors["file_watcher"] = FileWatcher(
                self.emit,
                self.stop,
                file_cfg.get("paths") or [],
                self.scanner,
                exclude=[self.config.quarantine_dir, self.config.spool_dir, self.config.state_dir],
                max_hash_bytes=file_cfg.get("max_hash_bytes", 64 * 1024 * 1024),
                debounce_seconds=file_cfg.get("debounce_seconds", 0.5),
            )

        network_cfg = sensors.get("network_sniffer") or {}
        if network_cfg.get("enabled", True):
            from .sensors.network_sniffer import NetworkSniffer

            self.sensors["network_sniffer"] = NetworkSniffer(
                self.emit,
                self.stop,
                network_cfg.get("mode", "auto"),
                network_cfg.get("poll_seconds", 5.0),
                network_cfg.get("interface"),
            )

    def _health_event(self) -> dict[str, Any]:
        return make_event(
            "agent_health",
            {
                "version": __version__,
                "sensors": {name: "running" if t.is_alive() else "stopped" for name, t in self.sensors.items()},
                "dropped_events": self.dropped + self.transport.spool_dropped,
                "yara_available": bool(self.scanner and self.scanner.available),
                "actuators_enabled": self.config.actuators_enabled,
                "platform": platform.platform(),
            },
        )

    def _drain(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while len(batch) < self.config.max_batch_events:
            try:
                batch.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _flush_loop(self) -> None:
        while not self.stop.wait(self.config.flush_interval_seconds):
            batch = self._drain()
            if batch:
                self.transport.send_events(batch)
            else:
                self.transport.flush_spool()
        # Final flush, so the last events before a shutdown aren't lost.
        while batch := self._drain():
            self.transport.send_events(batch)

    def _heartbeat_loop(self) -> None:
        self.emit(self._health_event())
        while not self.stop.wait(self.config.heartbeat_seconds):
            self.emit(self._health_event())

    def poll_commands_once(self) -> None:
        for envelope in self.transport.fetch_commands():
            outcome = self.executor.handle(envelope)
            if outcome is not None:
                log.warning("Command %s: %s (%s)", outcome.command_id, outcome.result.status, outcome.result.detail)
                self.transport.send_result(outcome.command_id, outcome.result.status, outcome.result.detail)

    def _command_loop(self) -> None:
        while not self.stop.wait(self.config.command_poll_seconds):
            try:
                self.poll_commands_once()
            except Exception:
                log.exception("Command handling failed")

    def run(self) -> None:
        self._build_sensors()
        loops = [
            threading.Thread(target=self._flush_loop, name="flush"),
            threading.Thread(target=self._heartbeat_loop, name="heartbeat", daemon=True),
            threading.Thread(target=self._command_loop, name="commands", daemon=True),
        ]
        for sensor in self.sensors.values():
            sensor.start()
        for loop in loops:
            loop.start()
        mode = "enabled" if self.config.actuators_enabled else "DISABLED (observe only)"
        log.info("Agent %s running. Sensors: %s. Actuators: %s", self.config.agent_id, list(self.sensors), mode)
        self.stop.wait()
        loops[0].join(timeout=30)
        self.transport.close()


def _quarantine_tool(args: argparse.Namespace) -> int:
    import yaml

    path = args.config or os.environ.get("CARYLLE_CONFIG", "config/settings.yaml")
    with open(path, encoding="utf-8") as handle:
        raw = (yaml.safe_load(handle) or {}).get("agent") or {}
    tool = FileQuarantine(
        raw.get("quarantine_dir", "var/quarantine"), AgentSafelist.load(raw.get("safelist_path", "config/safelist.yaml"))
    )
    if args.command == "quarantine-list":
        print(json.dumps(tool.list_items(), indent=2))
        return 0
    result = tool.restore(args.id)
    print(f"{result.status}: {result.detail}")
    return 0 if result.status == "succeeded" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="carylle-agent", description=__doc__)
    parser.add_argument("--config", default=None)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="Run the agent (default)")
    sub.add_parser("quarantine-list", help="List quarantined files")
    restore = sub.add_parser("quarantine-restore", help="Put a quarantined file back")
    restore.add_argument("id")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("CARYLLE_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if args.command in {"quarantine-list", "quarantine-restore"}:
        return _quarantine_tool(args)

    try:
        config = load_config(args.config)
        agent = Agent(config)
    except (ConfigError, TransportConfigError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    def shutdown(signum: int, _frame: Any) -> None:
        log.info("Signal %s received, shutting down", signum)
        agent.stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
