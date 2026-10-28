from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.containment.pipeline import AuthContext, admin_action, console, deny
from app.database import get_db
from app.risk.policy import DEFAULT_POLICY, Policy, load_policy, save_policy
from app.security.events import flush_broadcasts, record_event

router = APIRouter(prefix="/api/policy", tags=["policy"])

BAND_ACTIONS = {
    "low": {"non_sensitive": "allow", "sensitive": "allow", "monitoring": "baseline"},
    "elevated": {"non_sensitive": "allow", "sensitive": "allow", "monitoring": "increased"},
    "high": {"non_sensitive": "allow", "sensitive": "step-up password challenge", "monitoring": "increased"},
    "critical": {"non_sensitive": "revoke / deny (policy)", "sensitive": "revoke session", "monitoring": "alert"},
}


@router.get("")
def get_policy(auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    p = load_policy(db)
    return {"policy": p.model_dump(), "defaults": DEFAULT_POLICY.model_dump(), "band_matrix": BAND_ACTIONS,
            "evidence_weights_help": {
                "ml": "Weight on the ML anomaly probability",
                "device": "Device profile inconsistency (UA / OS / device type / language / automation)",
                "network": "Network context change (subnet / region)",
                "concurrency": "Same token used from multiple interleaving contexts (replay signature)",
                "behavior": "Abnormal request rate",
                "auth": "Failed logins, denied requests and admin probing",
                "sensitive": "Sensitive or out-of-flow activity",
                "synthetic": "Synthetic BITM / token-exchange indicators (lab only)"}}


@router.put("")
def update_policy(policy: Policy, auth: AuthContext = Depends(admin_action), db: Session = Depends(get_db)):
    before = load_policy(db).model_dump()
    saved = save_policy(db, policy, auth.user.username)
    changed = {k: {"from": before.get(k), "to": v} for k, v in saved.model_dump().items() if before.get(k) != v}
    record_event(db, "POLICY_UPDATED", session=auth.session, severity="medium" if changed else "info",
                 explanation=f"Zero-Trust policy updated by {auth.user.username}. Changed: {', '.join(changed) or 'nothing'}.",
                 detection_method="admin", action_taken="update_policy", metadata={"changes": changed})
    db.commit()
    flush_broadcasts(db)
    return {"ok": True, "policy": saved.model_dump(), "changed": changed}


@router.post("/reset")
def reset_policy(auth: AuthContext = Depends(admin_action), db: Session = Depends(get_db)):
    saved = save_policy(db, Policy(), auth.user.username)
    record_event(db, "POLICY_UPDATED", session=auth.session, explanation=f"Policy reset to defaults by {auth.user.username}.",
                 detection_method="admin", action_taken="reset_policy")
    db.commit()
    flush_broadcasts(db)
    return {"ok": True, "policy": saved.model_dump()}
