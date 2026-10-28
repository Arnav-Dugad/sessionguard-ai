from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload

from app.auth.sessions import ACTIVE_STATUSES, revoke, serialize_session
from app.containment.pipeline import AuthContext, deny, protected
from app.database import get_db
from app.models import RequestLog, RiskAssessment, SecurityEvent, UserSession
from app.security.events import flush_broadcasts, record_event, serialize_event
from app.websocket.hub import hub

router = APIRouter(prefix="/api/sessions", tags=["sessions"])

read_sessions = protected("page", emit_activity=False)
write_sessions = protected("data", emit_activity=False)


def _visible(db: Session, auth: AuthContext, public_id: str) -> UserSession:
    s = db.query(UserSession).options(joinedload(UserSession.user)).filter_by(public_id=public_id).one_or_none()
    if s is None or (auth.user.role != "admin" and s.user_id != auth.user.id):
        raise deny(404, "not_found", "Session not found.")  # same response for "not yours" - no enumeration
    return s


@router.get("")
def list_sessions(
    scope: str = Query("mine", pattern="^(mine|all)$"),
    status: str | None = Query(None),
    include_lab: bool = True,
    limit: int = Query(100, ge=1, le=500),
    auth: AuthContext = Depends(read_sessions),
    db: Session = Depends(get_db),
):
    q = db.query(UserSession).options(joinedload(UserSession.user))
    if scope == "all":
        if auth.user.role != "admin":
            raise deny(403, "forbidden", "Administrator role required.")
    else:
        q = q.filter(UserSession.user_id == auth.user.id)
    if status == "active":
        q = q.filter(UserSession.status.in_(ACTIVE_STATUSES))
    elif status:
        q = q.filter(UserSession.status == status)
    if not include_lab:
        q = q.filter(UserSession.is_lab.is_(False))
    rows = q.order_by(UserSession.last_activity.desc()).limit(limit).all()
    return {"sessions": [serialize_session(s, current_id=auth.session.id) for s in rows]}


@router.get("/{public_id}")
def session_detail(public_id: str, auth: AuthContext = Depends(read_sessions), db: Session = Depends(get_db)):
    s = _visible(db, auth, public_id)
    logs = db.query(RequestLog).filter_by(session_id=s.id).order_by(RequestLog.ts.desc()).limit(100).all()
    risks = db.query(RiskAssessment).filter_by(session_id=s.id).order_by(RiskAssessment.id.desc()).limit(100).all()
    events = db.query(SecurityEvent).filter_by(session_id=s.id).order_by(SecurityEvent.id.desc()).limit(100).all()
    return {
        "session": serialize_session(s, current_id=auth.session.id),
        "requests": [
            {"id": r.id, "ts": r.ts, "method": r.method, "path": r.path, "category": r.category, "status": r.status_code,
             "device": (r.device or {}).get("label"), "network": (r.network or {}).get("network"), "ip": (r.network or {}).get("ip"),
             "region": (r.network or {}).get("region"), "risk": r.risk_score, "decision": r.sessionguard_decision,
             "conventional": r.conventional_decision, "processing_ms": r.processing_ms, "client": r.client_label,
             "features": r.features, "synthetic": r.synthetic}
            for r in logs
        ],
        "risk_history": [
            {"id": a.id, "timestamp": a.timestamp.isoformat() + "Z", "score": a.final_risk_score, "instant": a.instant_risk,
             "probability": a.anomaly_probability, "band": a.band, "decision": a.decision, "model": a.model_version,
             "contributions": a.feature_contributions, "inference_ms": a.inference_ms}
            for a in reversed(risks)
        ],
        "events": [serialize_event(e, s) for e in events],
    }


@router.delete("/{public_id}")
def revoke_session(public_id: str, auth: AuthContext = Depends(write_sessions), db: Session = Depends(get_db)):
    s = _visible(db, auth, public_id)
    if s.status not in ACTIVE_STATUSES:
        return {"ok": True, "session": serialize_session(s, current_id=auth.session.id), "already": True}
    by_admin = auth.user.role == "admin" and s.user_id != auth.user.id
    revoke(s, auth.ctx.now, f"manually revoked by {'admin ' if by_admin else ''}{auth.user.username}")
    record_event(db, "SESSION_REVOKED", session=s, severity="medium",
                 explanation=f"Session {s.public_id} revoked manually by {auth.user.username}.",
                 detection_method="manual", action_taken="manual_revoke", risk_before=s.risk_score, risk_after=s.risk_score,
                 metadata={"actor": auth.user.username}, timestamp=auth.ctx.now)
    db.commit()
    flush_broadcasts(db)
    hub.publish("session", serialize_session(s))
    return {"ok": True, "session": serialize_session(s, current_id=auth.session.id)}


@router.post("/revoke-all")
def revoke_all(
    scope: str = Query("mine", pattern="^(mine|all|lab)$"),
    include_current: bool = False,
    auth: AuthContext = Depends(write_sessions),
    db: Session = Depends(get_db),
):
    q = db.query(UserSession).filter(UserSession.status.in_(ACTIVE_STATUSES))
    if scope == "mine":
        q = q.filter(UserSession.user_id == auth.user.id)
    elif auth.user.role != "admin":
        raise deny(403, "forbidden", "Administrator role required.")
    elif scope == "lab":
        q = q.filter(UserSession.is_lab.is_(True))
    if not include_current:
        q = q.filter(UserSession.id != auth.session.id)
    count = 0
    for s in q.all():
        revoke(s, auth.ctx.now, f"bulk revoke ({scope}) by {auth.user.username}")
        record_event(db, "SESSION_REVOKED", session=s, severity="medium",
                     explanation=f"Session revoked in bulk ({scope}) by {auth.user.username}.", detection_method="manual",
                     action_taken="manual_revoke", risk_before=s.risk_score, risk_after=s.risk_score, timestamp=auth.ctx.now)
        count += 1
    db.commit()
    flush_broadcasts(db)
    return {"ok": True, "revoked": count}
