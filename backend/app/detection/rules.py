"""Stage 2a - transparent rule-based evidence extraction.

Each evidence source maps the feature vector to a strength in [0, 1] plus a human-readable
explanation. Correlated raw features are folded into one source (taking the max), so the risk
engine never double counts, e.g., "UA changed" and "browser changed".
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from app.telemetry.features import clip01


@dataclass
class Evidence:
    key: str
    label: str
    strength: float
    detail: str
    synthetic: bool = False


EVIDENCE_LABELS = {
    "ml": "ML anomaly probability",
    "device": "Device profile inconsistency",
    "network": "Network context change",
    "concurrency": "Concurrent token use (replay pattern)",
    "behavior": "Abnormal request rate",
    "auth": "Authentication / authorization failures",
    "sensitive": "Sensitive or out-of-flow activity",
    "synthetic": "Relay / token-exchange indicators (synthetic)",
}


def _f(features: dict[str, float], key: str) -> float:
    v = features.get(key)
    return 0.0 if v is None or (isinstance(v, float) and math.isnan(v)) else float(v)


def extract_evidence(features: dict[str, float]) -> list[Evidence]:
    out: list[Evidence] = []

    # Device group: UA mismatch, structural device change, automation tooling.
    dev_change = _f(features, "device_change_score")
    ua_mm = _f(features, "ua_mismatch")
    auto = _f(features, "automation_ua")
    dev = max(dev_change, 0.3 * ua_mm, auto)
    if dev > 0:
        parts = []
        if auto:
            parts.append("client identifies as an automation tool")
        if dev_change:
            parts.append(f"{round(dev_change * 4)} of 4 device attributes differ from the baseline")
        elif ua_mm:
            parts.append("User-Agent string changed (same browser family / OS)")
        out.append(Evidence("device", EVIDENCE_LABELS["device"], dev, "; ".join(parts)))

    # Network group: subnet vs region change.
    net = max(0.5 * _f(features, "subnet_change"), _f(features, "region_change"))
    if net > 0:
        detail = "request arrived from a different region than the baseline" if _f(features, "region_change") else (
            "different network block within the same region"
        )
        out.append(Evidence("network", EVIDENCE_LABELS["network"], net, detail))

    # Concurrency: the same token alternating between contexts is the strongest replay signal.
    distinct = _f(features, "distinct_contexts_5m")
    switches = _f(features, "context_switches_5m")
    if distinct >= 2 and switches >= 2:
        conc = clip01((switches - 1) / 3)
        out.append(Evidence(
            "concurrency", EVIDENCE_LABELS["concurrency"], conc,
            f"{int(distinct)} contexts used this token in 5 min with {int(switches)} alternations",
        ))

    # Request behaviour.
    r10, r60 = _f(features, "rate_10s"), _f(features, "rate_60s")
    beh = max(clip01((r10 - 5) / 15), clip01((r60 - 25) / 50))
    if beh > 0:
        out.append(Evidence("behavior", EVIDENCE_LABELS["behavior"], beh, f"{int(r10)} req / 10 s, {int(r60)} req / 60 s"))

    # Authentication and authorization failures, including privilege probing.
    fa, az, ap = _f(features, "failed_auth_15m"), _f(features, "authz_failures_5m"), _f(features, "admin_probe")
    auth = max(clip01(fa / 5), clip01(az / 4), clip01(ap / 3))
    if auth > 0:
        out.append(Evidence(
            "auth", EVIDENCE_LABELS["auth"], auth,
            f"{int(fa)} failed logins / 15 min, {int(az)} denied requests and {int(ap)} admin probes / 5 min",
        ))

    # Sensitive or out-of-flow activity.
    sc, seq = _f(features, "sensitive_count_5m"), _f(features, "seq_anomaly")
    sens = max(clip01((sc - 2) / 6), seq)
    if sens > 0:
        out.append(Evidence(
            "sensitive", EVIDENCE_LABELS["sensitive"], sens,
            f"{int(sc)} sensitive operations / 5 min; {round(seq * 100)}% of recent transitions out of flow",
        ))

    # Synthetic research indicators (only present for harness traffic).
    tx, relay, cm = features.get("token_exchange_ms"), features.get("relay_indicator"), features.get("cookie_misuse")
    syn_parts, syn = [], 0.0
    if tx is not None and not math.isnan(tx):
        s = clip01((tx - 300) / 900)
        syn = max(syn, s)
        syn_parts.append(f"token exchange {int(tx)} ms")
    if relay is not None and not math.isnan(relay):
        syn = max(syn, clip01(relay))
        syn_parts.append(f"relay indicator {relay:.2f}")
    if cm is not None and not math.isnan(cm):
        syn = max(syn, clip01(cm))
        syn_parts.append("cookie-misuse flag" if cm else "no cookie misuse")
    if syn > 0:
        out.append(Evidence("synthetic", EVIDENCE_LABELS["synthetic"], syn, "; ".join(syn_parts), synthetic=True))

    return out


def context_change_strength(features: dict[str, float]) -> float:
    """How far the current request's context is from the authenticated baseline (0-1)."""
    dev = max(_f(features, "device_change_score"), 0.3 * _f(features, "ua_mismatch"), _f(features, "automation_ua"))
    net = max(0.5 * _f(features, "subnet_change"), _f(features, "region_change"))
    return max(dev, net)
