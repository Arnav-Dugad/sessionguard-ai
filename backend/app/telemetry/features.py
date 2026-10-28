"""Feature engineering shared by the live pipeline and the synthetic dataset generator.

``extract_features`` is a pure function of (history, current observation, baseline). The
runtime builds history from ``request_logs``; ``ml/datasets/generate.py`` builds it from
simulated sessions. Using one code path is what guarantees train/serve parity.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

NAN = float("nan")

FEATURES: list[str] = [
    "session_age_min",
    "log_gap_s",
    "rate_10s",
    "rate_60s",
    "ua_mismatch",
    "device_change_score",
    "automation_ua",
    "subnet_change",
    "region_change",
    "distinct_contexts_5m",
    "context_switches_5m",
    "failed_auth_15m",
    "authz_failures_5m",
    "sensitive_count_5m",
    "sensitive_ratio_5m",
    "seq_anomaly",
    "admin_probe",
    "token_exchange_ms",
    "relay_indicator",
    "cookie_misuse",
]

SYNTHETIC_FEATURES = {"token_exchange_ms", "relay_indicator", "cookie_misuse"}

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "session_age_min": "Minutes since the session (or its last re-baseline) was created",
    "log_gap_s": "log(1 + seconds since the previous request in this session)",
    "rate_10s": "Requests in the last 10 seconds",
    "rate_60s": "Requests in the last 60 seconds",
    "ua_mismatch": "User-Agent string differs from the session baseline",
    "device_change_score": "Fraction of browser / OS / device type / language that changed",
    "automation_ua": "User-Agent looks like a script, headless browser or HTTP library",
    "subnet_change": "Client network block differs from the baseline",
    "region_change": "Client region differs from the baseline",
    "distinct_contexts_5m": "Distinct (device, network) contexts using this token in 5 minutes",
    "context_switches_5m": "How often consecutive requests alternated between contexts (interleaving)",
    "failed_auth_15m": "Failed password attempts for this account in 15 minutes",
    "authz_failures_5m": "401/403 responses in this session in 5 minutes",
    "sensitive_count_5m": "Sensitive operations in 5 minutes",
    "sensitive_ratio_5m": "Share of recent requests that were sensitive",
    "seq_anomaly": "Share of recent transitions that skip the normal navigation flow",
    "admin_probe": "Admin endpoint attempts by a non-admin in 5 minutes",
    "token_exchange_ms": "SYNTHETIC: simulated OIDC token-exchange latency (ms)",
    "relay_indicator": "SYNTHETIC: simulated Browser-in-the-Middle relay indicator (0-1)",
    "cookie_misuse": "SYNTHETIC: simulated cookie-misuse / script-access indicator (0/1)",
}

# Transitions that skip the usual navigation flow (e.g. jumping straight from login to a
# sensitive action, or chaining sensitive actions back to back).
_IMPROBABLE = {("auth", "sensitive"), ("sensitive", "sensitive"), ("auth", "admin"), ("sensitive", "admin")}


@dataclass
class Obs:
    ts: float
    category: str  # auth | page | data | sensitive | admin
    status: int
    ua_hash: str
    device: dict[str, Any]
    network: dict[str, Any]
    synthetic: dict[str, float] = field(default_factory=dict)

    @property
    def context(self) -> tuple[str, str]:
        return (self.ua_hash, str(self.network.get("subnet", "")))


@dataclass
class Baseline:
    created_ts: float
    ua_hash: str
    device: dict[str, Any]
    network: dict[str, Any]


def _clip(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def extract_features(
    history: Sequence[Obs],
    current: Obs,
    baseline: Baseline,
    *,
    failed_auth_15m: int = 0,
    is_admin: bool = False,
) -> dict[str, float]:
    """Compute the 20-feature vector for ``current`` given prior requests in the same session.

    ``history`` must be ordered by time and must not include ``current``.
    """
    t = current.ts
    prev = history[-1] if history else None
    window = [h for h in history if h.ts >= t - 300] + [current]

    bd, cd = baseline.device, current.device
    changed = [bd.get(k) != cd.get(k) for k in ("browser", "os", "device_type", "lang")]

    contexts = [o.context for o in window]
    switches = sum(1 for a, b in zip(contexts, contexts[1:]) if a != b)

    recent = (list(history[-10:]) + [current])
    transitions = list(zip([o.category for o in recent], [o.category for o in recent][1:]))
    improbable = sum(1 for tr in transitions if tr in _IMPROBABLE)

    sensitive = sum(1 for o in window if o.category == "sensitive")
    admin_attempts = 0 if is_admin else sum(1 for o in window if o.category == "admin")

    return {
        "session_age_min": max(0.0, t - baseline.created_ts) / 60.0,
        "log_gap_s": math.log1p(max(0.0, t - prev.ts)) if prev else NAN,
        "rate_10s": float(1 + sum(1 for h in history if h.ts >= t - 10)),
        "rate_60s": float(1 + sum(1 for h in history if h.ts >= t - 60)),
        "ua_mismatch": float(current.ua_hash != baseline.ua_hash),
        "device_change_score": sum(changed) / len(changed),
        "automation_ua": float(bool(cd.get("automation"))),
        "subnet_change": float(current.network.get("subnet") != baseline.network.get("subnet")),
        "region_change": float(current.network.get("region") != baseline.network.get("region")),
        "distinct_contexts_5m": float(len(set(contexts))),
        "context_switches_5m": float(switches),
        "failed_auth_15m": float(failed_auth_15m),
        "authz_failures_5m": float(sum(1 for o in window[:-1] if o.status in (401, 403))),
        "sensitive_count_5m": float(sensitive),
        "sensitive_ratio_5m": sensitive / len(window),
        "seq_anomaly": improbable / len(transitions) if transitions else 0.0,
        "admin_probe": float(admin_attempts),
        "token_exchange_ms": float(current.synthetic.get("token_exchange_ms", NAN)),
        "relay_indicator": float(current.synthetic.get("relay_indicator", NAN)),
        "cookie_misuse": float(current.synthetic.get("cookie_misuse", NAN)),
    }


def to_vector(features: dict[str, float]) -> list[float]:
    """Order a feature dict; missing keys become NaN (handled by every model)."""
    out = []
    for name in FEATURES:
        v = features.get(name, NAN)
        try:
            out.append(float(v) if v is not None else NAN)
        except (TypeError, ValueError):
            out.append(NAN)
    return out


def json_safe(features: dict[str, float]) -> dict[str, float | None]:
    return {k: (None if isinstance(v, float) and math.isnan(v) else round(v, 4)) for k, v in features.items()}


def clip01(x: float) -> float:
    return _clip(x)
