"""Executes lab scenarios step-by-step through the in-process harness.

A running scenario keeps a set of live ``LabClient`` objects (so session cookies persist
between steps) in a process-local registry keyed by run id. The virtual clock starts in the
present and advances by each step's ``advance_s`` so inter-request timing is realistic even
though the whole scenario runs in well under a second of wall-clock time.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.database.base import utcnow
from app.models import SecurityEvent, SimulationRun, SimulationStep, UserSession
from app.security.events import THREAT_TYPES, serialize_event
from app.websocket.hub import hub

from .harness import LabClient, PROFILES
from .scenarios import SCENARIOS, Scenario, Step

LAB_USERS = {"laptop": "ada", "laptop_updated": "ada", "cafe": "ada", "phone": "ada",
             "replayer": "ada", "replayer_cloned": "ada", "script": "ada", "relay": "ada"}
DEFAULT_LAB_PASSWORD = "Demo-User!2027"


@dataclass
class RunState:
    run_id: int
    scenario: Scenario
    mode: str
    app: Any
    clients: dict[str, LabClient] = field(default_factory=dict)
    clock: float = field(default_factory=time.time)
    clock_start: float = 0.0
    cursor: int = 0
    finished: bool = False
    first_threat_ts: float | None = None
    contain_ts: float | None = None
    detect_wall_ms: float | None = None
    exchanges: list[dict] = field(default_factory=list)

    async def client(self, key: str) -> LabClient:
        if key not in self.clients:
            self.clients[key] = LabClient(self.app, PROFILES[key], self.run_id)
        return self.clients[key]

    async def close(self) -> None:
        await asyncio.gather(*(c.close() for c in self.clients.values()), return_exceptions=True)
        self.clients.clear()


_runs: dict[int, RunState] = {}
_lock = asyncio.Lock()


def _password_for(step: Step) -> str:
    return DEFAULT_LAB_PASSWORD if step.password == "use-default" else (step.password or DEFAULT_LAB_PASSWORD)


async def _execute_step(state: RunState, step: Step, db: Session) -> dict[str, Any]:
    exchanges: list[dict] = []
    note = ""

    async def one(path: str, method: str, body=None, synthetic=None, client_key=None, malicious=None):
        state.clock += step.advance_s
        c = await state.client(client_key or step.client)
        ex = await c.request(method, path, clock=state.clock, json_body=body, synthetic=synthetic,
                             malicious=step.malicious if malicious is None else malicious)
        exchanges.append(ex.as_dict())

    if step.action == "login":
        state.clock += step.advance_s
        c = await state.client(step.client)
        ex = await c.request("POST", "/api/auth/login", clock=state.clock,
                             json_body={"username": LAB_USERS[step.client], "password": _password_for(step)})
        exchanges.append(ex.as_dict())
        if state.mode == "traditional" and ex.ok:
            sess = db.query(UserSession).order_by(UserSession.id.desc()).first()
            if sess:
                sess.protection_mode = "traditional"
                db.commit()

    elif step.action == "note":
        note = step.explanation

    elif step.action in ("get", "post"):
        method = "POST" if step.action == "post" else "GET"
        # A roaming/continuing client picks up the session from its source on first use (same
        # token moving to a new network or device, or a script using the owner's cookie).
        if step.source_client:
            dst = await state.client(step.client)
            if not dst.session_token:
                dst.adopt_cookies_from(await state.client(step.source_client))
                note = f"'{dst.profile.label}' continues the session from '{step.source_client}'."
        for _ in range(max(1, step.repeat)):
            await one(step.path, method, body=step.body, synthetic=step.synthetic)

    elif step.action == "replay_adopt":
        src = await state.client(step.source_client)
        dst = await state.client(step.client)
        dst.adopt_cookies_from(src)
        note = f"Harness copied the demo token from '{src.profile.label}' to '{dst.profile.label}'."
        await one(step.path or "/api/portal/dashboard", "POST" if step.method == "POST" else "GET",
                  synthetic=step.synthetic)

    elif step.action == "retry_revoked":
        await one(step.path or "/api/portal/dashboard", "GET")

    elif step.action == "reauth":
        state.clock += step.advance_s
        c = await state.client(step.client)
        ex = await c.request("POST", "/api/auth/reauthenticate", clock=state.clock,
                             json_body={"password": _password_for(step)})
        exchanges.append(ex.as_dict())

    return {"exchanges": exchanges, "note": note}


def _new_events_for_run(db: Session, run_id: int, after_id: int) -> list[SecurityEvent]:
    return (db.query(SecurityEvent).filter(SecurityEvent.simulation_run_id == run_id, SecurityEvent.id > after_id)
            .order_by(SecurityEvent.id.asc()).all())


async def start_run(app: Any, scenario_key: str, mode: str) -> dict[str, Any]:
    if scenario_key not in SCENARIOS:
        raise KeyError(scenario_key)
    scenario = SCENARIOS[scenario_key]
    db = SessionLocal()
    try:
        run = SimulationRun(scenario_name=scenario_key, protection_mode=mode, status="running", started_at=utcnow(),
                            summary={"name": scenario.name, "mode": mode})
        db.add(run)
        db.commit()
        run_id = run.id
    finally:
        db.close()
    now = time.time()
    async with _lock:
        _runs[run_id] = RunState(run_id=run_id, scenario=scenario, mode=mode, app=app, clock=now, clock_start=now)
    hub.publish("simulation", {"event": "started", "run_id": run_id, "scenario": scenario_key, "mode": mode})
    return {"run_id": run_id, "scenario": scenario_key, "mode": mode, "total_steps": len(scenario.steps),
            "name": scenario.name}


async def step_run(run_id: int) -> dict[str, Any]:
    async with _lock:
        state = _runs.get(run_id)
    if state is None:
        raise KeyError(run_id)
    if state.finished or state.cursor >= len(state.scenario.steps):
        return await finish_run(run_id)

    step = state.scenario.steps[state.cursor]
    db = SessionLocal()
    try:
        last_event_id = db.query(SecurityEvent.id).order_by(SecurityEvent.id.desc()).limit(1).scalar() or 0
        t0 = time.perf_counter()
        result = await _execute_step(state, step, db)
        wall_ms = (time.perf_counter() - t0) * 1000

        new_events = _new_events_for_run(db, run_id, last_event_id)
        for ev in new_events:
            if ev.event_type in THREAT_TYPES and state.first_threat_ts is None:
                state.first_threat_ts = state.clock
                state.detect_wall_ms = wall_ms
            if ev.event_type in ("SESSION_REVOKED", "THREAT_CONTAINED") and state.contain_ts is None:
                state.contain_ts = state.clock

        payload = {
            "index": state.cursor, "title": step.title, "action": step.action, "client": step.client,
            "explanation": step.explanation, "expect": step.expect, "note": result["note"],
            "exchanges": result["exchanges"],
            "events": [serialize_event(e) for e in new_events],
            "wall_ms": round(wall_ms, 2), "virtual_clock": state.clock, "malicious": step.malicious,
        }
        db.add(SimulationStep(run_id=run_id, index=state.cursor, title=step.title, payload=payload))
        db.commit()
    finally:
        db.close()

    state.cursor += 1
    state.exchanges.extend(result["exchanges"])
    is_last = state.cursor >= len(state.scenario.steps)
    hub.publish("simulation", {"event": "step", "run_id": run_id, "index": payload["index"], "is_last": is_last})
    payload["has_next"] = not is_last
    payload["run_id"] = run_id
    if is_last:
        payload["final"] = await finish_run(run_id)
    return payload


def _summarise(state: RunState, db: Session) -> dict[str, Any]:
    events = (db.query(SecurityEvent).filter_by(simulation_run_id=state.run_id)
              .order_by(SecurityEvent.id.asc()).all())
    malicious_reqs = [e for e in state.exchanges if e.get("malicious")]
    attacker_accepted = sum(1 for e in malicious_reqs if e.get("ok"))
    attacker_blocked = sum(1 for e in malicious_reqs if not e.get("ok"))
    peak_risk = max((e.get("risk") or 0) for e in state.exchanges) if state.exchanges else 0
    revoked = any(e.event_type == "SESSION_REVOKED" for e in events)
    challenged = any(e.event_type == "REAUTHENTICATION_REQUIRED" for e in events)
    detected = any(e.event_type in THREAT_TYPES for e in events)

    # Latencies are measured on the virtual clock: time from the first attacker request to the
    # first threat event (detection) and to containment.
    first_attacker_ts = next((e["virtual_ts"] for e in malicious_reqs), None)
    detection_latency = (state.first_threat_ts - first_attacker_ts) if state.first_threat_ts and first_attacker_ts else None
    contain_latency = (state.contain_ts - first_attacker_ts) if state.contain_ts and first_attacker_ts else None

    if state.mode == "traditional":
        outcome = "accepted_all" if attacker_accepted else "no_attacker_traffic"
    elif revoked:
        outcome = "contained_revoked"
    elif challenged:
        outcome = "challenged_step_up"
    elif detected:
        outcome = "detected_monitored"
    else:
        outcome = "clean"

    return {
        "outcome": outcome, "detected": detected, "revoked": revoked, "challenged": challenged,
        "attacker_requests": len(malicious_reqs), "attacker_accepted": attacker_accepted,
        "attacker_blocked": attacker_blocked, "peak_risk": round(peak_risk, 2),
        "threat_events": sum(1 for e in events if e.event_type in THREAT_TYPES),
        "total_events": len(events),
        "detection_latency_s": round(detection_latency, 2) if detection_latency is not None else None,
        "containment_latency_s": round(contain_latency, 2) if contain_latency is not None else None,
        "detection_wall_ms": round(state.detect_wall_ms, 2) if state.detect_wall_ms else None,
    }


async def finish_run(run_id: int) -> dict[str, Any]:
    async with _lock:
        state = _runs.get(run_id)
    if state is None:
        db = SessionLocal()
        try:
            run = db.get(SimulationRun, run_id)
            return {"run_id": run_id, "status": run.status if run else "unknown", "summary": run.summary if run else {}}
        finally:
            db.close()

    db = SessionLocal()
    try:
        summary = _summarise(state, db)
        run = db.get(SimulationRun, run_id)
        if run:
            run.status = "completed"
            run.completed_at = utcnow()
            run.outcome = summary["outcome"]
            run.containment_latency = summary["containment_latency_s"]
            run.detection_latency = summary["detection_latency_s"]
            run.detection_latency_ms = summary["detection_wall_ms"]
            run.summary = {**run.summary, **summary}
            db.commit()
            result = {"run_id": run_id, "scenario": state.scenario.key, "mode": state.mode, "status": "completed",
                      "summary": run.summary}
        else:
            result = {"run_id": run_id, "status": "unknown"}
    finally:
        db.close()

    state.finished = True
    await state.close()
    async with _lock:
        _runs.pop(run_id, None)
    hub.publish("simulation", {"event": "completed", "run_id": run_id, "summary": result.get("summary", {})})
    return result


async def run_all(app: Any, scenario_key: str, mode: str) -> dict[str, Any]:
    started = await start_run(app, scenario_key, mode)
    run_id = started["run_id"]
    steps = []
    while True:
        async with _lock:
            state = _runs.get(run_id)
        if state is None or state.finished or state.cursor >= len(state.scenario.steps):
            break
        payload = await step_run(run_id)
        steps.append(payload)
        if "final" in payload:
            return {"run_id": run_id, "scenario": scenario_key, "mode": mode, "steps": steps, "final": payload["final"]}
    final = await finish_run(run_id)
    return {"run_id": run_id, "scenario": scenario_key, "mode": mode, "steps": steps, "final": final}


async def reset_runs() -> None:
    async with _lock:
        states = list(_runs.values())
        _runs.clear()
    await asyncio.gather(*(s.close() for s in states), return_exceptions=True)
