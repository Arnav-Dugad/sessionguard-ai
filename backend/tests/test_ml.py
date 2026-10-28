"""ML pipeline tests. Dataset generation and inference must be reproducible and robust."""
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "datasets"))

from app.detection.ml_detector import get_detector  # noqa: E402
from app.telemetry.features import FEATURES  # noqa: E402


def test_dataset_generation_is_deterministic():
    import generate
    df1, m1 = generate.generate(seed=7, n_sessions=120)
    df2, m2 = generate.generate(seed=7, n_sessions=120)
    assert len(df1) == len(df2)
    assert df1["label"].sum() == df2["label"].sum()
    assert m1["class_distribution"] == m2["class_distribution"]


def test_dataset_has_both_classes_and_all_features():
    import generate
    df, meta = generate.generate(seed=1, n_sessions=200)
    assert df["label"].nunique() == 2
    assert set(FEATURES).issubset(df.columns)
    assert meta["class_distribution"]["session_positive"] > 0


def test_detector_loads_or_degrades_gracefully():
    d = get_detector()
    status = d.status()
    assert "rules" in status["available"]
    # If models are trained, active should be a real model; otherwise it falls back to rules.
    assert status["active_model"] in ("rules", "logreg", "xgboost", "aexgb")


@pytest.mark.skipif(not (ROOT / "ml" / "artifacts" / "xgboost.joblib").exists(),
                    reason="models not trained; run scripts/train_models.ps1")
def test_inference_outputs_probability_and_handles_nan():
    d = get_detector()
    feats = {f: 0.0 for f in FEATURES}
    feats["token_exchange_ms"] = float("nan")  # missing synthetic feature
    feats["relay_indicator"] = float("nan")
    prob, ms = d.predict(feats)
    if prob is not None:  # a model is loaded
        assert 0.0 <= prob <= 1.0
        assert ms >= 0.0


@pytest.mark.skipif(not (ROOT / "ml" / "artifacts" / "xgboost.joblib").exists(),
                    reason="models not trained")
def test_suspicious_vector_scores_higher_than_benign():
    d = get_detector()
    benign = {f: 0.0 for f in FEATURES}
    benign["session_age_min"] = 10
    benign["log_gap_s"] = 3.0
    benign["rate_60s"] = 3
    suspicious = {f: 0.0 for f in FEATURES}
    suspicious.update({"ua_mismatch": 1, "device_change_score": 0.75, "subnet_change": 1, "region_change": 1,
                       "distinct_contexts_5m": 3, "context_switches_5m": 3, "automation_ua": 1, "rate_10s": 10})
    pb, _ = d.predict(benign)
    ps, _ = d.predict(suspicious)
    if pb is not None and ps is not None:
        assert ps > pb
