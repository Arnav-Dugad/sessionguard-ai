from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import get_settings
from app.containment.pipeline import AuthContext, admin_action, console, deny
from app.database import get_db
from app.detection.ml_detector import MODEL_LABELS, get_detector
from app.models import ModelEvaluation
from app.schemas import ActiveModelIn
from app.security.events import flush_broadcasts, record_event
from app.telemetry.features import FEATURE_DESCRIPTIONS, FEATURES, SYNTHETIC_FEATURES

router = APIRouter(prefix="/api/ml", tags=["ml"])


@router.get("/status")
def status(auth: AuthContext = Depends(console)):
    d = get_detector()
    return {**d.status(), "model_labels": MODEL_LABELS,
            "features": [{"name": f, "description": FEATURE_DESCRIPTIONS.get(f, ""), "synthetic": f in SYNTHETIC_FEATURES}
                         for f in FEATURES]}


@router.get("/models")
def models(auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    d = get_detector()
    latest: dict[str, ModelEvaluation] = {}
    for ev in db.query(ModelEvaluation).filter_by(split="test").order_by(ModelEvaluation.id.desc()).all():
        latest.setdefault(ev.model_name, ev)
    return {"active": d.active, "available": d.available, "models": [
        {"name": name, "label": MODEL_LABELS.get(name, name), "loaded": name in d.available,
         "metrics": None if name not in latest else {
             "accuracy": latest[name].accuracy, "precision": latest[name].precision, "recall": latest[name].recall,
             "f1": latest[name].f1, "roc_auc": latest[name].roc_auc, "fpr": latest[name].false_positive_rate,
             "inference_ms_median": latest[name].inference_ms_median}}
        for name in ("rules", "logreg", "xgboost", "aexgb")]}


@router.get("/evaluations")
def evaluations(auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    rows = db.query(ModelEvaluation).order_by(ModelEvaluation.id.desc()).limit(100).all()
    manifest = get_detector().manifest
    return {
        "dataset": {"version": manifest.get("dataset_version"), "seed": manifest.get("seed"),
                    "class_distribution": manifest.get("class_distribution"), "splits": manifest.get("splits"),
                    "generated_at": manifest.get("generated_at"), "scenarios": manifest.get("scenarios")},
        "evaluations": [
            {"id": r.id, "model": r.model_name, "label": MODEL_LABELS.get(r.model_name, r.model_name), "split": r.split,
             "dataset_version": r.dataset_version, "accuracy": r.accuracy, "precision": r.precision, "recall": r.recall,
             "f1": r.f1, "roc_auc": r.roc_auc, "fpr": r.false_positive_rate, "inference_ms_median": r.inference_ms_median,
             "details": r.details, "timestamp": r.evaluation_timestamp.isoformat() + "Z"} for r in rows],
    }


@router.get("/feature-importance")
def feature_importance(auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    path = get_settings().model_dir / "feature_importance.json"
    if not path.exists():
        return {"available": False, "importances": {}}
    return {"available": True, **json.loads(path.read_text())}


@router.post("/active")
def set_active(body: ActiveModelIn, auth: AuthContext = Depends(admin_action), db: Session = Depends(get_db)):
    d = get_detector()
    try:
        d.set_active(body.model)
    except ValueError as exc:
        raise deny(400, "model_unavailable", str(exc))
    record_event(db, "POLICY_UPDATED", session=auth.session, severity="info",
                 explanation=f"Active detection model switched to {MODEL_LABELS.get(body.model, body.model)}.",
                 detection_method="admin", action_taken="set_active_model", metadata={"model": body.model})
    db.commit()
    flush_broadcasts(db)
    return {"ok": True, "active": d.active, "status": d.status()}


@router.post("/reload")
def reload_models(auth: AuthContext = Depends(admin_action)):
    d = get_detector()
    d.load()
    return {"ok": True, "status": d.status()}
