"""Security event recording and serialisation."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.auth.crypto import new_event_uid
from app.database.base import utcnow
from app.models import SecurityEvent, UserSession
from app.websocket.hub import hub

EVENT_CATEGORIES: dict[str, str] = {
    "USER_LOGIN_SUCCESS": "authentication",
    "USER_LOGIN_FAILED": "authentication",
    "USER_LOGOUT": "authentication",
    "USER_REGISTERED": "authentication",
    "SESSION_CREATED": "session",
    "SESSION_ACTIVITY": "activity",
    "SESSION_ROTATED": "session",
    "SESSION_EXPIRED": "session",
    "DEVICE_PROFILE_CHANGED": "device",
    "IP_CONTEXT_CHANGED": "network",
    "SESSION_REPLAY_SUSPECTED": "replay",
    "ANOMALOUS_BEHAVIOR": "behavior",
    "ML_ANOMALY_DETECTED": "ml",
    "BITM_RELAY_SUSPECTED": "relay",
    "RISK_LEVEL_CHANGED": "risk",
    "REAUTHENTICATION_REQUIRED": "containment",
    "REAUTHENTICATION_SUCCESS": "containment",
    "REAUTHENTICATION_FAILED": "containment",
    "SESSION_REVOKED": "containment",
    "ACCESS_DENIED": "access",
    "CSRF_REJECTED": "access",
    "THREAT_CONTAINED": "containment",
    "SENSITIVE_ACTION": "activity",
    "POLICY_UPDATED": "admin",
}

THREAT_TYPES = {
    "DEVICE_PROFILE_CHANGED",
    "IP_CONTEXT_CHANGED",
    "SESSION_REPLAY_SUSPECTED",
    "ANOMALOUS_BEHAVIOR",
    "ML_ANOMALY_DETECTED",
    "BITM_RELAY_SUSPECTED",
    "THREAT_CONTAINED",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_for_risk(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def record_event(
    db: Session,
    event_type: str,
    *,
    session: UserSession | None = None,
    user_id: int | None = None,
    severity: str = "info",
    explanation: str = "",
    detection_method: str = "none",
    action_taken: str = "none",
    risk_before: float = 0.0,
    risk_after: float = 0.0,
    synthetic: bool = False,
    metadata: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
    simulation_run_id: int | None = None,
) -> SecurityEvent:
    ev = SecurityEvent(
        event_uid=new_event_uid(),
        session_id=session.id if session else None,
        user_id=user_id if user_id is not None else (session.user_id if session else None),
        event_type=event_type,
        category=EVENT_CATEGORIES.get(event_type, "session"),
        severity=severity,
        timestamp=timestamp or utcnow(),
        explanation=explanation,
        detection_method=detection_method,
        action_taken=action_taken,
        risk_before=round(risk_before, 2),
        risk_after=round(risk_after, 2),
        synthetic=synthetic,
        is_lab=bool(session.is_lab) if session else bool((metadata or {}).get("lab")),
        simulation_run_id=simulation_run_id,
        event_metadata=metadata or {},
    )
    db.add(ev)
    db.flush()
    # Stash for broadcast after commit (see ``flush_broadcasts``).
    db.info.setdefault("pending_events", []).append((ev, session))
    return ev


def serialize_event(ev: SecurityEvent, session: UserSession | None = None, username: str | None = None) -> dict[str, Any]:
    s = session if session is not None else ev.session
    return {
        "id": ev.event_uid,
        "timestamp": ev.timestamp.isoformat() + "Z",
        "event_type": ev.event_type,
        "category": ev.category,
        "severity": ev.severity,
        "explanation": ev.explanation,
        "detection_method": ev.detection_method,
        "action_taken": ev.action_taken,
        "risk_before": ev.risk_before,
        "risk_after": ev.risk_after,
        "risk_score": ev.risk_after,
        "synthetic": ev.synthetic,
        "is_lab": ev.is_lab,
        "session_ref": s.public_id if s else None,
        "username": username or (s.user.username if s is not None and s.user is not None else ev.event_metadata.get("username")),
        "simulation_run_id": ev.simulation_run_id,
        "metadata": ev.event_metadata,
    }


def flush_broadcasts(db: Session) -> None:
    """Publish events recorded in this DB session. Call after a successful commit."""
    pending = db.info.pop("pending_events", [])
    for ev, s in pending:
        hub.publish("event", serialize_event(ev, s))
