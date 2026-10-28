"""Security operations console API (admin only). All numbers are computed from stored data."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.auth.sessions import ACTIVE_STATUSES, serialize_session
from app.containment.pipeline import AuthContext, console, deny
from app.database import get_db
from app.database.base import utcnow
from app.detection.ml_detector import get_detector
from app.models import RequestLog, RiskAssessment, SecurityEvent, SimulationRun, User, UserSession
from app.risk.policy import load_policy
from app.security.events import SEVERITY_ORDER, THREAT_TYPES, serialize_event
from app.websocket.hub import hub

router = APIRouter(prefix="/api/security", tags=["security"])

INCIDENT_TYPES = THREAT_TYPES | {"SESSION_REVOKED", "REAUTHENTICATION_REQUIRED", "ACCESS_DENIED", "CSRF_REJECTED"}
ATTACK_LABELS = [
    ("BITM_RELAY_SUSPECTED", "relay", "Browser-in-the-Middle indicators (synthetic)"),
    ("SESSION_REPLAY_SUSPECTED", "replay", "Session token replay"),
    ("ANOMALOUS_BEHAVIOR", "behavior", "Abnormal request behaviour"),
    ("IP_CONTEXT_CHANGED", "network", "Network context anomaly"),
    ("DEVICE_PROFILE_CHANGED", "device", "Device profile anomaly"),
    ("ML_ANOMALY_DETECTED", "ml", "ML-detected anomaly"),
]


def _active_q(db: Session, now: datetime):
    return db.query(UserSession).filter(UserSession.status.in_(ACTIVE_STATUSES), UserSession.expires_at > now)


@router.get("/overview")
def overview(include_lab: bool = True, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    now = utcnow()
    policy = load_policy(db)
    active = _active_q(db, now)
    ev = db.query(SecurityEvent)
    if not include_lab:
        active = active.filter(UserSession.is_lab.is_(False))
        ev = ev.filter(SecurityEvent.is_lab.is_(False))
    active_rows = active.all()
    day_ago = now - timedelta(hours=24)

    logs = (db.query(RequestLog.processing_ms).filter(RequestLog.sessionguard_decision != "deny")
            .order_by(RequestLog.id.desc()).limit(500).all())
    lat = [r[0] for r in logs if r[0]]
    inf = [r[0] for r in db.query(RiskAssessment.inference_ms).order_by(RiskAssessment.id.desc()).limit(500).all() if r[0]]
    runs = db.query(SimulationRun).filter(SimulationRun.containment_latency.isnot(None),
                                          SimulationRun.protection_mode == "sessionguard").all()
    bands = Counter((s.alert_state or {}).get("band", "low") for s in active_rows)
    recent_failures = (ev.filter(SecurityEvent.event_type.in_(["USER_LOGIN_FAILED", "REAUTHENTICATION_FAILED"]))
                       .order_by(SecurityEvent.id.desc()).limit(5).all())

    return {
        "generated_at": now.isoformat() + "Z",
        "active_sessions": len(active_rows),
        "total_users": db.query(User).count(),
        "under_investigation": sum(1 for s in active_rows if s.risk_score >= policy.thresholds.elevated),
        "threats_detected": ev.filter(SecurityEvent.event_type.in_(THREAT_TYPES)).count(),
        "threats_24h": ev.filter(SecurityEvent.event_type.in_(THREAT_TYPES), SecurityEvent.timestamp >= day_ago).count(),
        "auto_revoked": ev.filter(SecurityEvent.event_type == "SESSION_REVOKED",
                                  SecurityEvent.action_taken == "revoke_session").count(),
        "step_up_challenges": ev.filter(SecurityEvent.event_type == "REAUTHENTICATION_REQUIRED").count(),
        "avg_risk": round(statistics.fmean([s.risk_score for s in active_rows]), 2) if active_rows else 0.0,
        "auth_failures_24h": ev.filter(SecurityEvent.event_type.in_(["USER_LOGIN_FAILED", "REAUTHENTICATION_FAILED"]),
                                       SecurityEvent.timestamp >= day_ago).count(),
        "recent_auth_failures": [serialize_event(e) for e in recent_failures],
        "detection_latency_ms": {
            "mean": round(statistics.fmean(lat), 3) if lat else None,
            "p95": round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3) if lat else None,
            "samples": len(lat),
        },
        "inference_ms": {"median": round(statistics.median(inf), 3) if inf else None, "samples": len(inf)},
        "containment_latency_s": round(statistics.fmean([r.containment_latency for r in runs]), 2) if runs else None,
        "events_per_minute": round(ev.filter(SecurityEvent.timestamp >= now - timedelta(minutes=5)).count() / 5, 2),
        "band_distribution": {b: bands.get(b, 0) for b in ("low", "elevated", "high", "critical")},
        "model": get_detector().status(),
        "policy": {"thresholds": policy.thresholds.model_dump(), "enforcement": policy.enforcement,
                   "critical_action": policy.critical_action},
        "websocket_clients": hub.subscriber_count,
    }


@router.get("/sessions")
def all_sessions(
    status: str | None = None, include_lab: bool = True, limit: int = Query(200, ge=1, le=1000),
    auth: AuthContext = Depends(console), db: Session = Depends(get_db),
):
    q = db.query(UserSession).options(joinedload(UserSession.user))
    if status == "active":
        q = q.filter(UserSession.status.in_(ACTIVE_STATUSES))
    elif status:
        q = q.filter(UserSession.status == status)
    if not include_lab:
        q = q.filter(UserSession.is_lab.is_(False))
    rows = q.order_by(UserSession.last_activity.desc()).limit(limit).all()
    return {"sessions": [serialize_session(s, current_id=auth.session.id) for s in rows]}


@router.get("/events")
def events(
    limit: int = Query(100, ge=1, le=1000),
    before_id: str | None = None,
    severity: str | None = Query(None, description="minimum severity"),
    types: str | None = Query(None, description="comma separated event types"),
    category: str | None = None,
    session: str | None = Query(None, description="session public id"),
    q: str | None = None,
    include_activity: bool = False,
    include_lab: bool = True,
    auth: AuthContext = Depends(console),
    db: Session = Depends(get_db),
):
    query = db.query(SecurityEvent).options(joinedload(SecurityEvent.session).joinedload(UserSession.user))
    if before_id:
        anchor = db.query(SecurityEvent.id).filter_by(event_uid=before_id).scalar()
        if anchor:
            query = query.filter(SecurityEvent.id < anchor)
    if severity in SEVERITY_ORDER:
        allowed = [k for k, v in SEVERITY_ORDER.items() if v >= SEVERITY_ORDER[severity]]
        query = query.filter(SecurityEvent.severity.in_(allowed))
    if types:
        query = query.filter(SecurityEvent.event_type.in_([t.strip().upper() for t in types.split(",") if t.strip()]))
    elif not include_activity:
        query = query.filter(SecurityEvent.event_type != "SESSION_ACTIVITY")
    if category:
        query = query.filter(SecurityEvent.category == category)
    if session:
        sid = db.query(UserSession.id).filter_by(public_id=session).scalar()
        query = query.filter(SecurityEvent.session_id == (sid or -1))
    if q:
        like = f"%{q[:64]}%"
        query = query.filter(SecurityEvent.explanation.ilike(like) | SecurityEvent.event_type.ilike(like))
    if not include_lab:
        query = query.filter(SecurityEvent.is_lab.is_(False))
    rows = query.order_by(SecurityEvent.id.desc()).limit(limit).all()
    return {"events": [serialize_event(e) for e in rows], "has_more": len(rows) == limit}


def _incident_kind(types: set[str]) -> tuple[str, str]:
    for t, key, label in ATTACK_LABELS:
        if t in types:
            return key, label
    if "ACCESS_DENIED" in types or "CSRF_REJECTED" in types:
        return "access", "Access policy violation"
    return "other", "Suspicious session"


def _incident_status(s: UserSession, types: set[str]) -> str:
    if s.status == "revoked" and "THREAT_CONTAINED" in types:
        return "contained"
    if s.status == "revoked":
        return "revoked"
    if s.status == "step_up" or "REAUTHENTICATION_REQUIRED" in types:
        return "challenged"
    if s.status in ACTIVE_STATUSES:
        return "open"
    return "closed"


@router.get("/alerts")
def alerts(limit: int = Query(100, ge=1, le=500), include_lab: bool = True, auth: AuthContext = Depends(console),
           db: Session = Depends(get_db)):
    q = db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(INCIDENT_TYPES), SecurityEvent.session_id.isnot(None),
                                       SecurityEvent.severity.in_(["low", "medium", "high", "critical"]))
    if not include_lab:
        q = q.filter(SecurityEvent.is_lab.is_(False))
    rows = q.order_by(SecurityEvent.id.desc()).limit(4000).all()
    grouped: dict[int, list[SecurityEvent]] = defaultdict(list)
    for e in rows:
        grouped[e.session_id].append(e)
    sessions = {s.id: s for s in db.query(UserSession).options(joinedload(UserSession.user))
                .filter(UserSession.id.in_(list(grouped))).all()}
    incidents = []
    for sid, evs in grouped.items():
        s = sessions.get(sid)
        if s is None:
            continue
        types = {e.event_type for e in evs}
        kind, label = _incident_kind(types)
        worst = max(evs, key=lambda e: SEVERITY_ORDER.get(e.severity, 0))
        incidents.append({
            "id": s.public_id, "session": serialize_session(s), "kind": kind, "title": label,
            "severity": worst.severity, "status": _incident_status(s, types), "alert_count": len(evs),
            "first_seen": min(e.timestamp for e in evs).isoformat() + "Z", "last_seen": max(e.timestamp for e in evs).isoformat() + "Z",
            "peak_risk": s.peak_risk, "event_types": sorted(types), "synthetic": any(e.synthetic for e in evs),
            "latest": serialize_event(evs[0], s),
        })
    incidents.sort(key=lambda i: i["last_seen"], reverse=True)
    return {"incidents": incidents[:limit]}


@router.get("/alerts/{public_id}")
def alert_detail(public_id: str, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    s = db.query(UserSession).options(joinedload(UserSession.user)).filter_by(public_id=public_id).one_or_none()
    if s is None:
        raise deny(404, "not_found", "Incident not found.")
    evs = db.query(SecurityEvent).filter_by(session_id=s.id).order_by(SecurityEvent.id.asc()).all()
    types = {e.event_type for e in evs}
    kind, label = _incident_kind(types)
    peak = (db.query(RiskAssessment).filter_by(session_id=s.id)
            .order_by(RiskAssessment.final_risk_score.desc(), RiskAssessment.id.desc()).first())
    logs = db.query(RequestLog).filter_by(session_id=s.id).order_by(RequestLog.ts.asc()).limit(300).all()
    first_threat = next((e for e in evs if e.event_type in THREAT_TYPES), None)
    contained = next((e for e in evs if e.event_type in ("THREAT_CONTAINED", "SESSION_REVOKED")), None)
    denied_after = sum(1 for e in evs if e.event_type == "ACCESS_DENIED" and contained and e.id > contained.id)
    return {
        "id": s.public_id, "kind": kind, "title": label, "status": _incident_status(s, types),
        "session": serialize_session(s),
        "timeline": [serialize_event(e, s) for e in evs],
        "peak_assessment": None if peak is None else {
            "score": peak.final_risk_score, "instant": peak.instant_risk, "probability": peak.anomaly_probability,
            "band": peak.band, "decision": peak.decision, "model": peak.model_version,
            "contributions": peak.feature_contributions, "signals": peak.signals,
            "timestamp": peak.timestamp.isoformat() + "Z", "inference_ms": peak.inference_ms,
            "features": next((r.features for r in logs if r.id == peak.request_log_id), {}),
        },
        "requests": [{"ts": r.ts, "method": r.method, "path": r.path, "status": r.status_code, "risk": r.risk_score,
                      "decision": r.sessionguard_decision, "client": r.client_label, "device": (r.device or {}).get("label"),
                      "network": (r.network or {}).get("network"), "region": (r.network or {}).get("region"),
                      "ip": (r.network or {}).get("ip")} for r in logs],
        "outcome": {
            "detected_at": first_threat.timestamp.isoformat() + "Z" if first_threat else None,
            "contained_at": contained.timestamp.isoformat() + "Z" if contained else None,
            "time_to_contain_s": (contained.timestamp - first_threat.timestamp).total_seconds()
            if contained and first_threat else None,
            "denied_after_containment": denied_after,
            "final_status": s.status,
        },
    }


@router.get("/risk/{public_id}")
def risk_history(public_id: str, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    s = db.query(UserSession).filter_by(public_id=public_id).one_or_none()
    if s is None:
        raise deny(404, "not_found", "Session not found.")
    rows = db.query(RiskAssessment).filter_by(session_id=s.id).order_by(RiskAssessment.id.asc()).limit(500).all()
    return {
        "session": serialize_session(s),
        "points": [{"timestamp": a.timestamp.isoformat() + "Z", "score": a.final_risk_score, "instant": a.instant_risk,
                    "probability": a.anomaly_probability, "band": a.band, "decision": a.decision,
                    "contributions": a.feature_contributions} for a in rows],
    }


@router.get("/metrics")
def metrics(window_minutes: int = Query(60, ge=5, le=7 * 24 * 60), buckets: int = Query(30, ge=6, le=120),
            include_lab: bool = True, auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    now = utcnow() + timedelta(minutes=2)  # lab traffic uses a virtual clock that can run slightly ahead
    start = now - timedelta(minutes=window_minutes)
    step = (now - start) / buckets

    def bucket(t: datetime) -> int:
        return min(buckets - 1, max(0, int((t - start) / step)))

    aq = db.query(RiskAssessment, UserSession.is_lab).join(UserSession, UserSession.id == RiskAssessment.session_id) \
        .filter(RiskAssessment.timestamp >= start)
    eq = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= start)
    if not include_lab:
        aq = aq.filter(UserSession.is_lab.is_(False))
        eq = eq.filter(SecurityEvent.is_lab.is_(False))
    assessments = [a for a, _ in aq.limit(20000).all()]
    evs = eq.limit(20000).all()

    series = [{"t": (start + step * i).isoformat() + "Z", "risk_avg": None, "risk_max": None, "normal": 0, "suspicious": 0,
               "auth_failures": 0, "events": 0, "threats": 0, "inference_ms": None, "active_sessions": 0}
              for i in range(buckets)]
    risk_acc: dict[int, list[float]] = defaultdict(list)
    inf_acc: dict[int, list[float]] = defaultdict(list)
    for a in assessments:
        b = bucket(a.timestamp)
        risk_acc[b].append(a.final_risk_score)
        if a.inference_ms:
            inf_acc[b].append(a.inference_ms)
        series[b]["normal" if a.band == "low" else "suspicious"] += 1
    for b, vals in risk_acc.items():
        series[b]["risk_avg"] = round(statistics.fmean(vals), 2)
        series[b]["risk_max"] = round(max(vals), 2)
    for b, vals in inf_acc.items():
        series[b]["inference_ms"] = round(statistics.fmean(vals), 3)
    threat_cats: Counter[str] = Counter()
    for e in evs:
        b = bucket(e.timestamp)
        series[b]["events"] += 1
        if e.event_type in ("USER_LOGIN_FAILED", "REAUTHENTICATION_FAILED"):
            series[b]["auth_failures"] += 1
        if e.event_type in THREAT_TYPES:
            series[b]["threats"] += 1
            threat_cats[e.category] += 1

    sq = db.query(UserSession.created_at, UserSession.revoked_at, UserSession.last_activity, UserSession.expires_at) \
        .filter(UserSession.created_at <= now)
    if not include_lab:
        sq = sq.filter(UserSession.is_lab.is_(False))
    for created, revoked, last, expires in sq.filter((UserSession.revoked_at.is_(None)) | (UserSession.revoked_at >= start)).all():
        end = min(x for x in (revoked, expires, last + timedelta(minutes=30), now) if x is not None)
        for i in range(buckets):
            t = start + step * (i + 1)
            if created <= t and end >= start + step * i:
                series[i]["active_sessions"] += 1

    decisions = Counter(a.decision for a in assessments)
    hist = [0] * 10
    for a in assessments:
        hist[min(9, int(a.final_risk_score // 10))] += 1

    return {
        "window_minutes": window_minutes,
        "series": series,
        "threats_by_category": [{"category": k, "count": v} for k, v in threat_cats.most_common()],
        "detection_outcomes": [{"decision": k, "count": v} for k, v in decisions.most_common()],
        "risk_distribution": [{"range": f"{i * 10}-{i * 10 + 9}", "count": hist[i]} for i in range(10)],
        "totals": {
            "assessments": len(assessments),
            "events": len(evs),
            "suspicious_share": round(sum(1 for a in assessments if a.band != "low") / len(assessments), 4) if assessments else 0,
        },
        "event_type_counts": dict(Counter(e.event_type for e in evs)),
    }


@router.get("/map")
def network_map(auth: AuthContext = Depends(console), db: Session = Depends(get_db)):
    """Network contexts observed in the last 24 h (fictional regions only)."""
    since = utcnow() - timedelta(hours=24)
    rows = (db.query(RequestLog.network, func.count(RequestLog.id), func.max(RequestLog.risk_score))
            .filter(RequestLog.ts >= since.timestamp() - 86400).group_by(RequestLog.network).all())
    agg: dict[str, dict] = {}
    for net, count, max_risk in rows:
        if not net:
            continue
        key = net.get("network", "unknown")
        cur = agg.setdefault(key, {**net, "requests": 0, "max_risk": 0.0})
        cur["requests"] += count
        cur["max_risk"] = max(cur["max_risk"], max_risk or 0.0)
    return {"points": list(agg.values())}
