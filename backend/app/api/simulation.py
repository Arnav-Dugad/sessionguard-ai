from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.containment.pipeline import AuthContext, console, deny
from app.database import get_db
from app.database.base import utcnow
from app.models import SecurityEvent, SimulationRun, UserSession
from app.schemas import SimulationStartIn, SimulationStepIn
from app.security.events import serialize_event
from app.simulation import runner
from app.simulation.harness import PROFILES
from app.simulation.scenarios import SCENARIOS, scenario_catalog

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


def _guard() -> None:
    if not get_settings().enable_simulation_lab:
        raise deny(403, "lab_disabled", "The Attack Simulation Lab is disabled in this configuration.")


@router.get("/scenarios")
def scenarios(auth: AuthContext = Depends(console)):
    return {"scenarios": scenario_catalog(), "clients": {
        k: {"label": p.label, "role": p.role, "description": p.description, "ip": p.ip}
        for k, p in PROFILES.items()}}


@router.post("/start")
async def start(body: SimulationStartIn, request: Request, auth: AuthContext = Depends(console)):
    _guard()
    if body.scenario not in SCENARIOS:
        raise deny(404, "unknown_scenario", f"No scenario '{body.scenario}'.")
    return await runner.start_run(request.app, body.scenario, body.mode)


@router.post("/step")
async def step(body: SimulationStepIn, auth: AuthContext = Depends(console)):
    _guard()
    try:
        return await runner.step_run(body.run_id)
    except KeyError:
        raise deny(404, "unknown_run", "That simulation run is not active. Start it again.")


@router.post("/run-all")
async def run_all(body: SimulationStartIn, request: Request, auth: AuthContext = Depends(console)):
    _guard()
    if body.scenario not in SCENARIOS:
        raise deny(404, "unknown_scenario", f"No scenario '{body.scenario}'.")
    return await runner.run_all(request.app, body.scenario, body.mode)


@router.post("/reset")
async def reset(request: Request, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    """Revoke all lab sessions and clear in-memory runs so the demo can be repeated cleanly."""
    _guard()
    await runner.reset_runs()
    now = utcnow()
    revoked = 0
    for s in db.query(UserSession).filter(UserSession.is_lab.is_(True), UserSession.status.in_(("active", "step_up"))).all():
        s.status, s.revoked_at, s.revoked_reason = "revoked", now, "lab reset"
        revoked += 1
    for run in db.query(SimulationRun).filter(SimulationRun.status == "running").all():
        run.status = "reset"
        run.completed_at = now
    db.commit()
    return {"ok": True, "revoked_lab_sessions": revoked}


@router.get("/runs")
def runs(limit: int = 50, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    rows = db.query(SimulationRun).order_by(SimulationRun.id.desc()).limit(limit).all()
    return {"runs": [{"id": r.id, "scenario": r.scenario_name, "mode": r.protection_mode, "status": r.status,
                      "outcome": r.outcome, "started_at": r.started_at.isoformat() + "Z",
                      "completed_at": r.completed_at.isoformat() + "Z" if r.completed_at else None,
                      "containment_latency_s": r.containment_latency, "summary": r.summary} for r in rows]}


@router.get("/results/{run_id}")
def results(run_id: int, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    run = db.get(SimulationRun, run_id)
    if run is None:
        raise deny(404, "not_found", "Run not found.")
    events = db.query(SecurityEvent).filter_by(simulation_run_id=run_id).order_by(SecurityEvent.id.asc()).all()
    return {
        "run": {"id": run.id, "scenario": run.scenario_name, "mode": run.protection_mode, "status": run.status,
                "outcome": run.outcome, "summary": run.summary,
                "started_at": run.started_at.isoformat() + "Z",
                "completed_at": run.completed_at.isoformat() + "Z" if run.completed_at else None},
        "steps": [s.payload for s in run.steps],
        "events": [serialize_event(e) for e in events],
    }
