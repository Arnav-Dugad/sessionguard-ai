"""Stage 3 - continuous, explainable risk scoring.

Fusion is noisy-OR over evidence sources:

    instant = 100 * (1 - prod_i (1 - w_i * s_i / 100))

which is bounded to [0, 100] and saturates instead of over-counting when many signals agree.
Each source's contribution is attributed in proportion to ``w_i * s_i`` so the displayed
contributions always sum to the score. The session score combines the instant score with
the decayed previous score: spikes apply immediately, recovery is gradual.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.detection.rules import EVIDENCE_LABELS, Evidence, extract_evidence

from .policy import Policy

BANDS = ("low", "elevated", "high", "critical")


@dataclass
class RiskResult:
    instant: float
    score: float
    band: str
    contributions: dict[str, dict] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    decayed_previous: float = 0.0


def band_for(score: float, policy: Policy) -> str:
    t = policy.thresholds
    if score >= t.critical:
        return "critical"
    if score >= t.high:
        return "high"
    if score >= t.elevated:
        return "elevated"
    return "low"


def fuse(evidence: list[Evidence], weights: dict[str, float]) -> tuple[float, dict[str, dict]]:
    remaining = 1.0
    raw: dict[str, float] = {}
    for ev in evidence:
        w = weights.get(ev.key, 0.0)
        p = max(0.0, min(1.0, w * ev.strength / 100.0))
        if p <= 0:
            continue
        remaining *= 1.0 - p
        raw[ev.key] = w * ev.strength
    instant = 100.0 * (1.0 - remaining)
    total = sum(raw.values())
    contributions: dict[str, dict] = {}
    for ev in evidence:
        if ev.key not in raw:
            continue
        contributions[ev.key] = {
            "label": ev.label,
            "points": round(instant * raw[ev.key] / total, 2) if total else 0.0,
            "strength": round(ev.strength, 3),
            "weight": weights.get(ev.key, 0.0),
            "detail": ev.detail,
            "synthetic": ev.synthetic,
        }
    return instant, contributions


def assess(
    features: dict[str, float],
    ml_probability: float | None,
    policy: Policy,
    *,
    previous_score: float = 0.0,
    seconds_since_previous: float = 0.0,
) -> RiskResult:
    evidence = extract_evidence(features)
    if ml_probability is not None and policy.ml_enabled:
        floor = policy.ml_floor
        strength = 0.0 if ml_probability <= floor else (ml_probability - floor) / (1.0 - floor)
        if strength > 0:
            evidence.insert(0, Evidence("ml", EVIDENCE_LABELS["ml"], strength,
                                        f"model probability {ml_probability:.3f} (operating floor {floor:.2f})"))

    instant, contributions = fuse(evidence, policy.weights.model_dump())

    decayed = previous_score * policy.decay_per_request * 0.5 ** (max(0.0, seconds_since_previous) / policy.half_life_s)
    score = max(instant, decayed)
    if score > instant:
        # Carry-over from earlier evidence is shown explicitly rather than hidden in the factors.
        contributions["carry_over"] = {
            "label": "Residual risk from earlier requests (decaying)",
            "points": round(score - instant, 2),
            "strength": round(decayed / 100, 3),
            "weight": None,
            "detail": f"previous score {previous_score:.1f} decayed to {decayed:.1f}",
            "synthetic": False,
        }
    score = round(min(100.0, score), 2)
    return RiskResult(
        instant=round(instant, 2),
        score=score,
        band=band_for(score, policy),
        contributions=contributions,
        evidence=evidence,
        decayed_previous=round(decayed, 2),
    )
