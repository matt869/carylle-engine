"""Terminate a process, proving first that it is the same process the evidence described."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import psutil

from ..safelist import AgentSafelist, normalize_path

log = logging.getLogger(__name__)
_CREATE_TIME_TOLERANCE = 0.01


@dataclass
class ActionResult:
    status: str  # succeeded | failed | refused
    detail: str


def _protected_lineage() -> set[int]:
    """The agent and its ancestors: killing these would take out the sensor itself."""
    pids = {os.getpid()}
    try:
        for parent in psutil.Process(os.getpid()).parents():
            pids.add(parent.pid)
    except psutil.Error:
        pass
    return pids


def terminate_process(target: dict[str, Any], safelist: AgentSafelist, grace_seconds: float = 3.0) -> ActionResult:
    try:
        pid = int(target["pid"])
        create_time = float(target["create_time"])
    except (KeyError, TypeError, ValueError):
        return ActionResult("refused", "target lacks a valid pid and create_time")

    if pid in _protected_lineage():
        return ActionResult("refused", "target is the agent or one of its ancestors")

    try:
        proc = psutil.Process(pid)
        live_create_time = proc.create_time()
    except psutil.NoSuchProcess:
        return ActionResult("succeeded", "process had already exited")
    except psutil.Error as exc:
        return ActionResult("failed", f"could not inspect process: {type(exc).__name__}")

    # PIDs get reused. Without this check a delayed command could kill an innocent process.
    if abs(live_create_time - create_time) > _CREATE_TIME_TOLERANCE:
        return ActionResult("refused", "pid now belongs to a different process")

    try:
        live_exe = proc.exe()
    except psutil.AccessDenied:
        # An unidentifiable process can't be shown to be safe to kill.
        return ActionResult("refused", "cannot read the live executable path, so its safety is unproven")
    except psutil.NoSuchProcess:
        return ActionResult("succeeded", "process had already exited")
    except psutil.Error as exc:
        return ActionResult("failed", f"could not inspect process: {type(exc).__name__}")

    expected_exe = target.get("exe") or ""
    if expected_exe and live_exe and normalize_path(expected_exe) != normalize_path(live_exe):
        return ActionResult("refused", "live executable differs from the evidence")

    # Check the live path rather than the command's claim.
    if (problem := safelist.check_process(pid, live_exe)) is not None:
        return ActionResult("refused", problem)

    # Children die too: a killed reverse shell shouldn't leave its payload running.
    protected = _protected_lineage()
    victims = [proc]
    skipped = 0
    try:
        for child in proc.children(recursive=True):
            try:
                child_exe = child.exe()
            except psutil.Error:
                skipped += 1
                continue
            if child.pid in protected or safelist.check_process(child.pid, child_exe) is not None:
                skipped += 1
                continue
            victims.append(child)
    except psutil.Error:
        pass

    # Keep going past a descendant that refuses: stopping early would leave its siblings
    # running. Only the target itself refusing means the action failed outright.
    signalled: list[psutil.Process] = []
    for victim in victims:
        try:
            victim.terminate()
            signalled.append(victim)
        except psutil.NoSuchProcess:
            pass
        except psutil.Error as exc:
            if victim is proc:
                return ActionResult("failed", f"terminate denied: {type(exc).__name__}")
            skipped += 1

    _, alive = psutil.wait_procs(signalled, timeout=grace_seconds)
    for victim in alive:
        try:
            victim.kill()
        except psutil.Error:
            pass
    if alive:
        _, alive = psutil.wait_procs(alive, timeout=grace_seconds)
    if alive:
        return ActionResult("failed", f"{len(alive)} process(es) survived kill")

    descendants = sum(1 for v in signalled if v is not proc)
    detail = f"terminated pid {pid} and {descendants} descendant(s)"
    if skipped:
        detail += f"; left {skipped} protected or unreadable descendant(s) running"
    log.warning("Actuator: %s", detail)
    return ActionResult("succeeded", detail)
