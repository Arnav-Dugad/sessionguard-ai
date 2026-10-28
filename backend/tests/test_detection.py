"""Unit tests for the deterministic detection, risk and feature layers (no HTTP)."""
import math

from app.detection.rules import context_change_strength, extract_evidence
from app.risk.engine import assess, band_for
from app.risk.policy import Policy
from app.telemetry.features import FEATURES, Baseline, Obs, extract_features


def _baseline(ts=0.0):
    dev = {"browser": "Chrome", "os": "Windows", "device_type": "desktop", "lang": "en-us", "ua_hash": "aaa", "automation": False}
    net = {"subnet": "192.0.2.0/25", "region": "Northbridge"}
    return Baseline(ts, "aaa", dev, net)


def _obs(ts, cat="page", ua="aaa", subnet="192.0.2.0/25", region="Northbridge", automation=False, status=200, syn=None):
    dev = {"browser": "Chrome" if ua == "aaa" else "Firefox", "os": "Windows" if ua == "aaa" else "Linux",
           "device_type": "desktop", "lang": "en-us", "ua_hash": ua, "automation": automation}
    return Obs(ts, cat, status, ua, dev, {"subnet": subnet, "region": region}, syn or {})


def test_feature_vector_has_all_features():
    f = extract_features([], _obs(1.0), _baseline())
    assert set(FEATURES).issubset(f)


def test_normal_activity_low_risk():
    b = _baseline()
    hist = [_obs(float(i * 20)) for i in range(4)]
    f = extract_features(hist, _obs(80.0), b)
    r = assess(f, 0.03, Policy())
    assert r.band == "low"
    assert r.score < 25


def test_device_change_raises_risk_but_not_critical_alone():
    b = _baseline()
    hist = [_obs(float(i * 20)) for i in range(3)]
    f = extract_features(hist, _obs(70.0, ua="bbb"), b)  # different UA/device, same network, human pace
    assert f["ua_mismatch"] == 1.0
    assert f["device_change_score"] > 0
    assert context_change_strength(f) > 0
    assert any(e.key == "device" for e in extract_evidence(f))
    # Even if the model agrees moderately, a device change with no network/behaviour corroboration
    # must stay well below the critical band (proportionality).
    r = assess(f, 0.6, Policy())
    clean = assess(extract_features(hist, _obs(70.0), b), 0.05, Policy())
    assert r.score > clean.score  # device change raises risk above a clean request
    assert r.band != "critical"


def test_network_change_contributes():
    b = _baseline()
    f = extract_features([_obs(10.0)], _obs(40.0, subnet="203.0.113.0/25", region="Far Harbor"), b)
    assert f["region_change"] == 1.0
    assert any(e.key == "network" for e in extract_evidence(f))


def test_replay_concurrency_pattern_is_high():
    b = _baseline()
    # Interleave two contexts on the same token within 5 minutes.
    hist = [_obs(0.0), _obs(10.0, ua="bbb", subnet="203.0.113.0/25", region="Far Harbor"),
            _obs(20.0), _obs(30.0, ua="bbb", subnet="203.0.113.0/25", region="Far Harbor")]
    f = extract_features(hist, _obs(40.0, ua="bbb", subnet="203.0.113.0/25", region="Far Harbor"), b)
    assert f["distinct_contexts_5m"] >= 2
    assert f["context_switches_5m"] >= 2
    r = assess(f, 0.85, Policy())
    assert r.score >= 50


def test_burst_raises_behavior_evidence():
    b = _baseline()
    hist = [_obs(float(i) * 0.3) for i in range(12)]
    f = extract_features(hist, _obs(3.7), b)
    assert f["rate_10s"] > 5
    assert any(e.key == "behavior" for e in extract_evidence(f))


def test_risk_is_bounded_and_attributed():
    b = _baseline()
    f = extract_features([_obs(0.0)], _obs(1.0, ua="bbb", subnet="203.0.113.0/25", region="Far Harbor", automation=True), b)
    r = assess(f, 0.99, Policy())
    assert 0 <= r.score <= 100
    total = sum(c["points"] for c in r.contributions.values())
    assert math.isclose(total, r.score, abs_tol=0.5)  # contributions sum to the score


def test_bands_match_thresholds():
    p = Policy()
    assert band_for(10, p) == "low"
    assert band_for(30, p) == "elevated"
    assert band_for(60, p) == "high"
    assert band_for(90, p) == "critical"


def test_missing_synthetic_features_are_nan():
    f = extract_features([], _obs(1.0), _baseline())
    assert math.isnan(f["token_exchange_ms"])
    assert math.isnan(f["relay_indicator"])


def test_decay_recovers_over_clean_requests():
    p = Policy()
    f_clean = extract_features([_obs(0.0)], _obs(600.0), _baseline())
    r = assess(f_clean, 0.01, p, previous_score=80.0, seconds_since_previous=600.0)
    assert r.score < 80.0  # decayed toward the clean instant score
