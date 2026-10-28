"""End-to-end acceptance tests mirroring docs/MASTER_PROMPT_v2.md section 13."""
import pytest


def _run(admin, scenario, mode="sessionguard"):
    r = admin.post("/api/simulation/run-all", json={"scenario": scenario, "mode": mode})
    assert r.status_code == 200, r.text
    return r.json()["final"]["summary"]


def test_normal_scenario_stays_clean(admin):
    s = _run(admin, "normal")
    assert s["detected"] is False
    assert s["revoked"] is False
    assert s["peak_risk"] < 25


def test_token_replay_detected_and_contained(admin):
    s = _run(admin, "token_replay")
    assert s["detected"] is True
    assert s["revoked"] is True
    assert s["attacker_accepted"] == 0  # no attacker request ultimately succeeds post-containment
    assert s["peak_risk"] >= 75


def test_traditional_mode_accepts_replay(admin):
    s = _run(admin, "token_replay", mode="traditional")
    assert s["attacker_accepted"] > 0  # the valid token is accepted with no risk awareness
    assert s["revoked"] is False


def test_revocation_scenario_enforced_server_side(admin):
    s = _run(admin, "revocation")
    assert s["revoked"] is True
    # The last step retries the revoked token; it must be blocked.
    assert s["attacker_blocked"] >= 1


def test_false_positive_challenges_then_recovers(admin):
    s = _run(admin, "false_positive")
    assert s["challenged"] is True
    assert s["revoked"] is False  # legitimate user is never permanently locked out


def test_device_anomaly_is_proportional(admin):
    s = _run(admin, "device_anomaly")
    assert s["detected"] is True
    assert s["revoked"] is False  # device change alone must not auto-revoke


def test_bitm_events_labelled_synthetic(admin):
    r = admin.post("/api/simulation/run-all", json={"scenario": "bitm", "mode": "sessionguard"})
    events = r.json()["final"]
    run_id = events["run_id"]
    detail = admin.get(f"/api/simulation/results/{run_id}").json()
    bitm_events = [e for e in detail["events"] if e["event_type"] == "BITM_RELAY_SUSPECTED"]
    assert bitm_events
    assert all(e["synthetic"] for e in bitm_events)


def test_experiment_comparison_shows_difference(admin):
    r = admin.post("/api/experiment/compare", json={"scenario": "token_replay"})
    assert r.status_code == 200
    data = r.json()
    assert data["traditional"]["accepted_attacker_requests"] > data["sessionguard"]["accepted_attacker_requests"]
    assert data["verdict"]["sessionguard_contained"] is True


def test_overview_reflects_activity(admin):
    _run(admin, "token_replay")
    ov = admin.get("/api/security/overview").json()
    assert ov["threats_detected"] >= 1
    assert ov["auto_revoked"] >= 1
    assert ov["model"]["active_model"] in ("rules", "logreg", "xgboost", "aexgb")


def test_incident_detail_has_timeline_and_outcome(admin):
    _run(admin, "token_replay")
    incidents = admin.get("/api/security/alerts").json()["incidents"]
    assert incidents
    detail = admin.get(f"/api/security/alerts/{incidents[0]['id']}").json()
    assert detail["timeline"]
    assert "outcome" in detail


def test_reset_revokes_lab_sessions(admin):
    _run(admin, "token_replay")
    r = admin.post("/api/simulation/reset")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_metrics_endpoint_returns_series(admin):
    _run(admin, "request_burst")
    m = admin.get("/api/security/metrics?window_minutes=60").json()
    assert "series" in m and len(m["series"]) > 0
    assert "risk_distribution" in m
