"""Stage 2b - runtime ML inference.

Loads the artifacts produced by ``ml/training/train.py``. If they are missing, the detector
reports itself as unavailable and the risk engine falls back to rule-only scoring; it never
invents a probability.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np

from app.config import get_settings
from app.telemetry.features import FEATURES, to_vector

log = logging.getLogger("sessionguard.ml")

MODEL_FILES = {
    "logreg": "logreg.joblib",
    "xgboost": "xgboost.joblib",
    "aexgb": "aexgb.joblib",
}
MODEL_LABELS = {
    "rules": "Rule-based detector (no ML)",
    "logreg": "Logistic Regression baseline",
    "xgboost": "XGBoost classifier",
    "aexgb": "AutoEncoder + XGBoost (AEXB-inspired)",
}


class MLDetector:
    def __init__(self, model_dir: Path, active: str):
        self.model_dir = Path(model_dir)
        self.active = active
        self._models: dict[str, Any] = {}
        self.manifest: dict[str, Any] = {}
        self._lock = threading.Lock()
        self.load()

    def load(self) -> None:
        import joblib

        with self._lock:
            self._models.clear()
            manifest = self.model_dir / "manifest.json"
            self.manifest = json.loads(manifest.read_text()) if manifest.exists() else {}
            for name, fname in MODEL_FILES.items():
                path = self.model_dir / fname
                if path.exists():
                    try:
                        self._models[name] = joblib.load(path)
                    except Exception as exc:  # pragma: no cover - corrupt artifact
                        log.warning("could not load %s: %s", path, exc)
            if self.active != "rules" and self.active not in self._models:
                fallback = next((m for m in ("aexgb", "xgboost", "logreg") if m in self._models), "rules")
                log.info("active model %s unavailable, using %s", self.active, fallback)
                self.active = fallback

    @property
    def available(self) -> list[str]:
        return ["rules", *self._models.keys()]

    @property
    def loaded(self) -> bool:
        return self.active in self._models

    @property
    def version(self) -> str:
        if not self.loaded:
            return "rules-only"
        return f"{self.active}@{self.manifest.get('dataset_version', 'unknown')}"

    def set_active(self, name: str) -> None:
        if name != "rules" and name not in self._models:
            raise ValueError(f"model '{name}' is not trained - run scripts/train_models.ps1")
        self.active = name

    def predict(self, features: dict[str, float]) -> tuple[float | None, float]:
        """Return (probability or None, inference milliseconds)."""
        model = self._models.get(self.active)
        if model is None:
            return None, 0.0
        x = np.asarray([to_vector(features)], dtype=float)
        t0 = time.perf_counter()
        p = float(model.predict_proba(x)[0, 1])
        return p, (time.perf_counter() - t0) * 1000.0

    def status(self) -> dict[str, Any]:
        return {
            "active_model": self.active,
            "active_label": MODEL_LABELS.get(self.active, self.active),
            "loaded": self.loaded,
            "version": self.version,
            "available": self.available,
            "features": FEATURES,
            "trained_at": self.manifest.get("trained_at"),
            "dataset_version": self.manifest.get("dataset_version"),
            "seed": self.manifest.get("seed"),
        }


_detector: MLDetector | None = None


def get_detector() -> MLDetector:
    global _detector
    if _detector is None:
        s = get_settings()
        _detector = MLDetector(s.model_dir, s.active_model)
    return _detector
