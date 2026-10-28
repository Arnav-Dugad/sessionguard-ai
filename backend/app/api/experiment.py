"""Experimental comparison: run the same scenario through traditional and SessionGuard
validation and report, from real run data, how each handled the attacker traffic."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.containment.pipeline import AuthContext, console, deny
from app.simulation import runner
from app.simulation.scenarios import SCENARIOS

router = APIRouter(prefix="/api/experiment", tags=["experiment"])

ATTACK_SCENARIOS = ["token_replay", "device_anomaly", "network_anomaly", "request_burst", "revocation", "bitm"]


class CompareIn(BaseModel):
    scenario: str = "token_replay"


def _row(scenario: str, mode: str, final: dict) -> dict:
    s = final.get("summary", {})
    return {
        "mode": mode,
        "accepted_attacker_requests": s.get("attacker_accepted", 0),
        "blocked_attacker_requests": s.get("attacker_blocked", 0),
        "attacker_requests": s.get("attacker_requests", 0),
        "detected": s.get("detected", False),
        "revoked": s.get("revoked", False),
        "challenged": s.get("challenged", False),
        "peak_risk": s.get("peak_risk", 0),
        "detection_latency_s": s.get("detection_latency_s"),
        "containment_latency_s": s.get("containment_latency_s"),
        "outcome": final.get("summary", {}).get("outcome", final.get("status")),
        "run_id": final.get("run_id"),
    }


@router.post("/compare")
async def compare(body: CompareIn, request: Request, auth: AuthContext = Depends(console)):
    if body.scenario not in SCENARIOS:
        raise deny(404, "unknown_scenario", f"No scenario '{body.scenario}'.")
    exp_id = "exp_" + secrets.token_hex(4)
    out = {}
    for mode in ("traditional", "sessionguard"):
        result = await runner.run_all(request.app, body.scenario, mode)
        out[mode] = _row(body.scenario, mode, result.get("final", {}))
    trad, sg = out["traditional"], out["sessionguard"]
    verdict = {
        "attacker_requests_blocked_delta": sg["blocked_attacker_requests"] - trad["blocked_attacker_requests"],
        "traditional_contained": trad["revoked"] or trad["challenged"],
        "sessionguard_contained": sg["revoked"] or sg["challenged"],
        "sessionguard_detected": sg["detected"],
    }
    return {"experiment_id": exp_id, "scenario": body.scenario, "name": SCENARIOS[body.scenario].name,
            "traditional": trad, "sessionguard": sg, "verdict": verdict}


@router.post("/compare-all")
async def compare_all(request: Request, auth: AuthContext = Depends(console)):
    results = []
    for key in ATTACK_SCENARIOS:
        exp = await compare(CompareIn(scenario=key), request, auth)
        results.append(exp)
    agg = {
        "scenarios": len(results),
        "traditional_accepted": sum(r["traditional"]["accepted_attacker_requests"] for r in results),
        "sessionguard_accepted": sum(r["sessionguard"]["accepted_attacker_requests"] for r in results),
        "traditional_contained": sum(1 for r in results if r["verdict"]["traditional_contained"]),
        "sessionguard_contained": sum(1 for r in results if r["verdict"]["sessionguard_contained"]),
        "sessionguard_detected": sum(1 for r in results if r["verdict"]["sessionguard_detected"]),
    }
    return {"results": results, "aggregate": agg}
