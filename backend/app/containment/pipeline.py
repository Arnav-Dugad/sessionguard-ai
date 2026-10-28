"""The four-stage pipeline executed on every protected request.

    validate (conventional)  ->  Stage 1 telemetry  ->  Stage 2 detection (rules + ML)
      ->  Stage 3 risk scoring  ->  Stage 4 Zero-Trust containment

Use ``Depends(protected("<category>"))`` on a route to put it behind the pipeline.
Categories: page | data | sensitive | admin | console (admin read-only polling).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.auth.crypto import constant_time_equals
from app.auth.sessions import ACTIVE_STATUSES, csrf_for, expiry_reason, find_by_token, revoke, serialize_session
from app.config import get_settings
from app.database import get_db
from app.detection.ml_detector import get_detector
from app.detection.rules import context_change_strength
from app.models import AuthAttempt, RequestLog, RiskAssessment, User, UserSession
from app.risk.engine import RiskResult, assess
from app.risk.policy import Policy, load_policy
from app.security.events import flush_broadcasts, record_event, severity_for_risk
from app.telemetry.context import RequestContext, build_context
from app.telemetry.features import Baseline, Obs, extract_features, json_safe
from app.websocket.hub import hub

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
HISTORY_WINDOW_S = 900
HISTORY_LIMIT = 200


@dataclass
class AuthContext:
    user: User
    session: UserSession
    ctx: RequestContext
    risk: float = 0.0
    band: str = "low"
    decision: str = "allow"
    assessment: dict[str, Any] = field(default_factory=dict)


def deny(status: int, code: str, message: str, headers: dict[str, str] | None = None, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, **extra}, headers=headers)


def _harness_headers(ctx: RequestContext, risk: float | None, band: str, decision: str, log_id: int | None) -> dict[str, str]:
    """Pipeline internals are exposed to the lab harness only - telling a real client its risk
    score would help an attacker tune evasion."""
    if not ctx.is_harness:
        return {}
    h = {"X-SG-Band": band, "X-SG-Decision": decision}
    if risk is not None:
        h["X-SG-Risk"] = f"{risk:.2f}"
    if log_id is not None:
        h["X-SG-Request-Log"] = str(log_id)
    return h


def _log_request(db: Session, s: UserSession, ctx: RequestContext, request: Request, category: str, status: int,
                 conventional: str, decision: str, **kw: Any) -> RequestLog:
    row = RequestLog(
        session_id=s.id, ts=ctx.ts, method=request.method, path=request.url.path[:255], category=category,
        status_code=status, ua_hash=ctx.device["ua_hash"], device=ctx.device, network=ctx.network,
        synthetic=ctx.synthetic, conventional_decision=conventional, sessionguard_decision=decision,
        client_label=ctx.client_label, **kw,
    )
    db.add(row)
    db.flush()
    return row


def _meta(ctx: RequestContext, request: Request, **extra: Any) -> dict[str, Any]:
    return {
        "method": request.method,
        "path": request.url.path,
        "client": ctx.client_label,
        "ip": ctx.ip,
        "region": ctx.network.get("region"),
        "network": ctx.network.get("network"),
        "device": ctx.device.get("label"),
        "virtual_clock": ctx.is_harness,
        **extra,
    }


def _history(db: Session, s: UserSession, ctx: RequestContext) -> list[Obs]:
    since = max(ctx.ts - HISTORY_WINDOW_S, s.baseline_ts - 1e-6)
    rows = (
        db.query(RequestLog)
        .filter(RequestLog.session_id == s.id, RequestLog.ts >= since, RequestLog.ts <= ctx.ts)
        .order_by(RequestLog.ts.desc(), RequestLog.id.desc())
        .limit(HISTORY_LIMIT)
        .all()
    )
    rows.reverse()
    return [Obs(r.ts, r.category, r.status_code, r.ua_hash, r.device or {}, r.network or {}, r.synthetic or {}) for r in rows]


def decide(risk: RiskResult, features: dict[str, float], category: str, s: UserSession, ctx: RequestContext,
           policy: Policy) -> str:
    step_up_valid = s.step_up_until is not None and s.step_up_until > ctx.now
    if risk.band == "critical":
        if policy.critical_action == "revoke":
            return "revoke"
        return "deny_sensitive" if category in ("sensitive", "admin") else "monitor"
    if category == "sensitive" and not step_up_valid:
        if risk.band == "high":
            return "step_up"
        if policy.step_up_on_context_change and context_change_strength(features) >= policy.context_change_threshold:
            return "step_up"
    if risk.band in ("elevated", "high"):
        return "monitor"
    return "allow"


def _emit_detection_events(db: Session, s: UserSession, ctx: RequestContext, request: Request, risk: RiskResult,
                           prob: float | None, history: list[Obs], prev_risk: float, model_version: str) -> list[str]:
    state = dict(s.alert_state or {})
    emitted: dict[str, float] = dict(state.get("emitted", {}))
    fired: list[str] = []
    ev_by_key = {e.key: e for e in risk.evidence}
    meta = _meta(ctx, request)
    common = dict(session=s, risk_before=prev_risk, risk_after=risk.score, timestamp=ctx.now, simulation_run_id=ctx.run_id)

    def once(kind: str, level: float, step: float, **kw: Any) -> None:
        if level > emitted.get(kind, -1.0) + (step if kind in emitted else 0.0):
            emitted[kind] = level
            record_event(db, kind, **common, **kw)
            fired.append(kind)

    prev = history[-1] if history else None
    prev_ua = prev.ua_hash if prev else (s.baseline_device or {}).get("ua_hash")
    prev_subnet = prev.network.get("subnet") if prev else (s.baseline_network or {}).get("subnet")

    if "device" in ev_by_key and ctx.device["ua_hash"] != prev_ua:
        e = ev_by_key["device"]
        record_event(db, "DEVICE_PROFILE_CHANGED", **common, severity="medium" if e.strength >= 0.5 else "low",
                     explanation=f"Device changed to {ctx.device.get('label')} (baseline {(s.baseline_device or {}).get('label')}): "
                                 f"{e.detail}. A device change alone is not proof of hijacking.",
                     detection_method="rule:device", action_taken="score_updated", metadata=meta)
        fired.append("DEVICE_PROFILE_CHANGED")
    if "network" in ev_by_key and ctx.network.get("subnet") != prev_subnet:
        e = ev_by_key["network"]
        record_event(db, "IP_CONTEXT_CHANGED", **common, severity="medium" if e.strength >= 1 else "low",
                     explanation=f"Network moved to {ctx.network.get('network')} ({ctx.network.get('region')}) from baseline "
                                 f"{(s.baseline_network or {}).get('network')} ({(s.baseline_network or {}).get('region')}): {e.detail}.",
                     detection_method="rule:network", action_taken="score_updated",
                     metadata={**meta, "previous": s.baseline_network, "contribution": risk.contributions.get("network", {}).get("points")})
        fired.append("IP_CONTEXT_CHANGED")
    if "concurrency" in ev_by_key:
        e = ev_by_key["concurrency"]
        once("SESSION_REPLAY_SUSPECTED", e.strength, 0.3, severity=severity_for_risk(max(risk.score, 50)),
             explanation=f"The same session token is being used from multiple client contexts: {e.detail}. "
                         "This interleaving pattern is characteristic of token replay, although shared devices or "
                         "multiple tabs behind different networks can also produce it.",
             detection_method="rule:concurrency", action_taken="score_updated", metadata=meta)
    for key in ("behavior", "auth", "sensitive"):
        e = ev_by_key.get(key)
        if e and e.strength >= 0.5:
            once("ANOMALOUS_BEHAVIOR", e.strength, 0.25, severity=severity_for_risk(risk.score),
                 explanation=f"{e.label}: {e.detail}.", detection_method=f"rule:{key}", action_taken="score_updated",
                 metadata={**meta, "signal": key})
    if prob is not None and prob >= 0.5:
        once("ML_ANOMALY_DETECTED", prob, 0.2, severity=severity_for_risk(risk.score),
             explanation=f"{model_version} classified this request as anomalous with probability {prob:.2f}.",
             detection_method=f"ml:{model_version}", action_taken="score_updated", metadata={**meta, "probability": prob})
    syn = ev_by_key.get("synthetic")
    if syn and syn.strength >= 0.5:
        once("BITM_RELAY_SUSPECTED", syn.strength, 0.25, severity=severity_for_risk(risk.score), synthetic=True,
             explanation=f"SYNTHETIC TELEMETRY: {syn.detail}. These indicators are injected by the lab harness to "
                         "model Browser-in-the-Middle relay timing; they are not real browser observations.",
             detection_method="rule:synthetic", action_taken="score_updated", metadata=meta)

    if state.get("band", "low") != risk.band:
        record_event(db, "RISK_LEVEL_CHANGED", **common, severity=severity_for_risk(risk.score) if risk.band != "low" else "info",
                     explanation=f"Session risk moved from {state.get('band', 'low')} to {risk.band} ({prev_risk:.1f} -> {risk.score:.1f}).",
                     detection_method="risk_engine", action_taken="band_changed",
                     metadata={**meta, "from": state.get("band", "low"), "to": risk.band})
        fired.append("RISK_LEVEL_CHANGED")

    state["emitted"] = emitted
    state["band"] = risk.band
    s.alert_state = state
    return fired


def run_pipeline(db: Session, request: Request, response: Response, *, category: str, require_admin: bool,
                 telemetry: bool, emit_activity: bool) -> AuthContext:
    settings = get_settings()
    ctx = build_context(request)
    t0 = time.perf_counter()

    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise deny(401, "not_authenticated", "Sign in required.")
    s = find_by_token(db, token)
    if s is None:
        raise deny(401, "invalid_session", "Session token is not recognised (expired, rotated or never issued).")

    # --- Conventional validation: exists / not revoked / not expired -------------------
    if s.status not in ACTIVE_STATUSES:
        record_event(db, "ACCESS_DENIED", session=s, severity="high" if s.status == "revoked" else "low",
                     explanation=f"A request presented a {s.status.replace('_', ' ')} session token and was rejected by the server. "
                                 "Server-side revocation means the token cannot regain access.",
                     detection_method="session_validation", action_taken="deny_401", risk_before=s.risk_score,
                     risk_after=s.risk_score, metadata=_meta(ctx, request, session_status=s.status), timestamp=ctx.now,
                     simulation_run_id=ctx.run_id)
        _log_request(db, s, ctx, request, category, 401, "reject", "deny", risk_score=s.risk_score)
        db.commit()
        flush_broadcasts(db)
        code = "session_revoked" if s.status == "revoked" else f"session_{s.status}"
        raise deny(401, code, f"This session is {s.status.replace('_', ' ')}. Please sign in again.",
                   headers=_harness_headers(ctx, s.risk_score, "n/a", "deny", None))

    reason = expiry_reason(s, ctx.now)
    if reason:
        revoke(s, ctx.now, reason, status="expired")
        record_event(db, "SESSION_EXPIRED", session=s, explanation=f"Session expired ({reason}).",
                     detection_method="session_validation", action_taken="expire", timestamp=ctx.now, simulation_run_id=ctx.run_id)
        db.commit()
        flush_broadcasts(db)
        raise deny(401, "session_expired", f"Session expired ({reason}). Please sign in again.")

    if request.method in UNSAFE_METHODS:
        supplied = request.headers.get(settings.csrf_header_name, "")
        if not supplied or not constant_time_equals(supplied, csrf_for(s)):
            record_event(db, "CSRF_REJECTED", session=s, severity="medium",
                         explanation="State-changing request without a valid session-bound CSRF token was blocked.",
                         detection_method="csrf", action_taken="deny_403", risk_before=s.risk_score, risk_after=s.risk_score,
                         metadata=_meta(ctx, request), timestamp=ctx.now, simulation_run_id=ctx.run_id)
            _log_request(db, s, ctx, request, category, 403, "accept", "deny_csrf", risk_score=s.risk_score)
            db.commit()
            flush_broadcasts(db)
            raise deny(403, "csrf_failed", "Missing or invalid CSRF token.")

    user = s.user
    forbidden = require_admin and user.role != "admin"

    # Admin-console polling: fully validated, but excluded from behavioural telemetry so the
    # console's own refresh traffic does not look like a request burst.
    if not telemetry and not forbidden:
        if (ctx.now - s.last_activity).total_seconds() > 15:
            s.last_activity = ctx.now
            db.commit()
        return AuthContext(user=user, session=s, ctx=ctx, risk=s.risk_score, band=(s.alert_state or {}).get("band", "low"))

    if forbidden:
        category = "admin"

    # --- Traditional mode (lab comparison only): conventional checks and nothing else -----
    if s.protection_mode == "traditional":
        row = _log_request(db, s, ctx, request, category, 403 if forbidden else 200, "accept",
                           "deny_forbidden" if forbidden else "allow", processing_ms=(time.perf_counter() - t0) * 1000)
        s.last_activity, s.last_ts, s.request_count = ctx.now, ctx.ts, s.request_count + 1
        s.device_profile, s.network_context = ctx.device, ctx.network
        db.commit()
        hdrs = _harness_headers(ctx, None, "n/a", "allow", row.id)
        if forbidden:
            raise deny(403, "forbidden", "Administrator role required.", headers=hdrs)
        response.headers.update(hdrs)
        return AuthContext(user=user, session=s, ctx=ctx, decision="allow", band="n/a")

    # --- Stage 1: telemetry ---------------------------------------------------------------
    policy = load_policy(db)
    history = _history(db, s, ctx)
    current = Obs(ctx.ts, category, 200, ctx.device["ua_hash"], ctx.device, ctx.network, ctx.synthetic)
    baseline = Baseline(s.baseline_ts, (s.baseline_device or {}).get("ua_hash", ""), s.baseline_device or {}, s.baseline_network or {})
    failed = db.query(AuthAttempt).filter(AuthAttempt.user_id == user.id, AuthAttempt.success.is_(False),
                                          AuthAttempt.ts >= ctx.ts - 900, AuthAttempt.ts <= ctx.ts).count()
    features = extract_features(history, current, baseline, failed_auth_15m=failed, is_admin=user.role == "admin")

    # --- Stage 2: detection -----------------------------------------------------------------
    detector = get_detector()
    prob, inference_ms = detector.predict(features) if policy.ml_enabled else (None, 0.0)

    # --- Stage 3: risk ------------------------------------------------------------------------
    prev_risk = s.risk_score
    risk = assess(features, prob, policy, previous_score=prev_risk, seconds_since_previous=max(0.0, ctx.ts - s.last_ts))

    # --- Stage 4: containment -----------------------------------------------------------------
    intended = "forbidden" if forbidden else decide(risk, features, category, s, ctx, policy)
    decision = intended
    if policy.enforcement == "monitor" and intended in ("revoke", "step_up", "deny_sensitive"):
        decision = "monitor"
    processing_ms = (time.perf_counter() - t0) * 1000

    status_code = {"revoke": 401, "step_up": 403, "deny_sensitive": 403, "forbidden": 403}.get(decision, 200)
    row = _log_request(db, s, ctx, request, category, status_code, "accept", decision, features=json_safe(features),
                       risk_score=risk.score, processing_ms=processing_ms)
    assessment = RiskAssessment(
        session_id=s.id, request_log_id=row.id, model_version=detector.version if policy.ml_enabled else "rules-only",
        anomaly_probability=prob, instant_risk=risk.instant, final_risk_score=risk.score,
        feature_contributions=risk.contributions, signals=[e.key for e in risk.evidence], decision=decision,
        band=risk.band, inference_ms=inference_ms, timestamp=ctx.now,
    )
    db.add(assessment)

    fired = _emit_detection_events(db, s, ctx, request, risk, prob, history, prev_risk, detector.version)

    s.risk_score = risk.score
    s.peak_risk = max(s.peak_risk, risk.score)
    s.device_profile, s.network_context = ctx.device, ctx.network
    s.last_activity, s.last_ts, s.request_count = ctx.now, ctx.ts, s.request_count + 1

    meta = _meta(ctx, request, features=json_safe(features), contributions=risk.contributions, probability=prob,
                 intended_decision=intended, processing_ms=round(processing_ms, 3))
    method = "rules+ml" if prob is not None else "rules"
    common = dict(session=s, risk_before=prev_risk, risk_after=risk.score, timestamp=ctx.now, simulation_run_id=ctx.run_id)

    if emit_activity:
        record_event(db, "SESSION_ACTIVITY", **common, severity="info",
                     explanation=f"{request.method} {request.url.path} -> {decision} (risk {risk.score:.1f}, {risk.band}).",
                     detection_method=method, action_taken=decision, metadata=meta)
    if intended != decision:
        record_event(db, "RISK_LEVEL_CHANGED", **common, severity="medium",
                     explanation=f"Monitor-only mode: policy would have applied '{intended}' but enforcement is disabled.",
                     detection_method=method, action_taken="monitor_only", metadata=meta)

    if decision == "step_up":
        s.status = "step_up"
        record_event(db, "REAUTHENTICATION_REQUIRED", **common, severity="high",
                     explanation=f"Sensitive operation {request.url.path} requires a fresh password challenge: risk {risk.score:.1f} "
                                 f"({risk.band}), context change {context_change_strength(features):.2f}.",
                     detection_method=method, action_taken="step_up_required", metadata=meta)
    elif decision == "revoke":
        revoke(s, ctx.now, f"auto-revoked: critical risk {risk.score:.1f}")
        record_event(db, "SESSION_REVOKED", **common, severity="critical",
                     explanation=f"Containment engine revoked the session server-side at risk {risk.score:.1f}. "
                                 "Every client holding this token is now rejected.",
                     detection_method=method, action_taken="revoke_session", metadata=meta)
        record_event(db, "THREAT_CONTAINED", **common, severity="critical",
                     explanation=f"Threat contained {processing_ms:.1f} ms after the request arrived. Triggering signals: "
                                 + ", ".join(f"{v['label']} (+{v['points']:.1f})" for v in risk.contributions.values()),
                     detection_method=method, action_taken="revoke_session", metadata={**meta, "fired": fired})
    elif decision in ("deny_sensitive", "forbidden"):
        record_event(db, "ACCESS_DENIED", **common, severity="high" if decision == "deny_sensitive" else "medium",
                     explanation=("Critical-risk session blocked from a sensitive operation by policy."
                                  if decision == "deny_sensitive" else f"Non-admin attempted admin endpoint {request.url.path}."),
                     detection_method=method if decision == "deny_sensitive" else "rbac",
                     action_taken="deny_403", metadata=meta)

    db.commit()
    flush_broadcasts(db)
    hub.publish("session", serialize_session(s))

    hdrs = _harness_headers(ctx, risk.score, risk.band, decision, row.id)
    if decision == "revoke":
        raise deny(401, "session_revoked_risk", "Session revoked by SessionGuard: critical risk. Sign in again.", headers=hdrs)
    if decision == "step_up":
        raise deny(403, "step_up_required", "Please confirm your password to continue with this sensitive action.",
                   headers=hdrs, risk_band=risk.band)
    if decision == "deny_sensitive":
        raise deny(403, "denied_by_policy", "This operation is blocked for the current session.", headers=hdrs)
    if decision == "forbidden":
        raise deny(403, "forbidden", "Administrator role required.", headers=hdrs)

    response.headers.update(hdrs)
    return AuthContext(user=user, session=s, ctx=ctx, risk=risk.score, band=risk.band, decision=decision,
                       assessment={"probability": prob, "contributions": risk.contributions})


def protected(category: str = "data", *, admin: bool = False, telemetry: bool = True, emit_activity: bool = True):
    def dependency(request: Request, response: Response, db: Session = Depends(get_db)) -> AuthContext:
        return run_pipeline(db, request, response, category=category, require_admin=admin, telemetry=telemetry,
                            emit_activity=emit_activity)

    return dependency


# Common dependencies
console = protected("console", admin=True, telemetry=False)
admin_action = protected("admin", admin=True, emit_activity=False)
