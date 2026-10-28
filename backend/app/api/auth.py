from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.auth.crypto import hash_password, token_fingerprint, verify_password
from app.auth.sessions import (
    ACTIVE_STATUSES, clear_cookies, create_session, csrf_for, find_by_token, revoke, rotate, serialize_session, set_cookies,
)
from app.config import get_settings
from app.auth.crypto import constant_time_equals
from app.containment.pipeline import AuthContext, deny, protected
from app.database import get_db
from app.models import AuthAttempt, User
from app.schemas import LoginIn, ReauthIn, RegisterIn
from app.security.events import flush_broadcasts, record_event
from app.telemetry.context import build_context

router = APIRouter(prefix="/api/auth", tags=["auth"])


def serialize_user(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "email": u.email, "display_name": u.display_name or u.username,
        "role": u.role, "is_demo": u.is_demo, "created_at": u.created_at.isoformat() + "Z",
    }


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == body.username) | (User.email == body.email)).first():
        raise deny(409, "already_exists", "That username or email is already registered.")
    ctx = build_context(request)
    user = User(username=body.username, email=body.email, display_name=body.display_name or body.username,
                password_hash=hash_password(body.password), role="user")
    db.add(user)
    db.flush()
    record_event(db, "USER_REGISTERED", user_id=user.id, explanation=f"New account '{user.username}' registered.",
                 metadata={"username": user.username, "ip": ctx.ip}, timestamp=ctx.now)
    db.commit()
    flush_broadcasts(db)
    return {"user": serialize_user(user)}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    settings = get_settings()
    ctx = build_context(request)
    username = body.username.strip().lower()

    recent_failures = db.query(AuthAttempt).filter(
        AuthAttempt.username == username, AuthAttempt.success.is_(False), AuthAttempt.ts >= ctx.ts - 600,
    ).count()
    if recent_failures >= settings.login_rate_limit_per_10min:
        raise deny(429, "rate_limited", "Too many failed attempts. Try again in a few minutes.")

    user = db.query(User).filter((User.username == username) | (User.email == username)).one_or_none()
    ok = verify_password(user.password_hash if user else None, body.password)
    db.add(AuthAttempt(username=username, user_id=user.id if user else None, success=ok, ip=ctx.ip, ts=ctx.ts,
                       kind="login", timestamp=ctx.now))
    meta = {"username": username, "ip": ctx.ip, "region": ctx.network.get("region"), "device": ctx.device.get("label"),
            "client": ctx.client_label, "lab": ctx.is_harness}
    if not ok:
        record_event(db, "USER_LOGIN_FAILED", user_id=user.id if user else None, severity="low",
                     explanation=f"Failed sign-in for '{username}' from {ctx.network.get('network')}.",
                     detection_method="authentication", action_taken="deny_401", metadata=meta, timestamp=ctx.now,
                     simulation_run_id=ctx.run_id)
        db.commit()
        flush_broadcasts(db)
        raise deny(401, "invalid_credentials", "Incorrect username or password.")

    # Session fixation defence: any session presented with the login request is retired and a
    # brand-new token is issued.
    previous = find_by_token(db, request.cookies.get(settings.session_cookie_name))
    if previous is not None and previous.status in ACTIVE_STATUSES:
        revoke(previous, ctx.now, "replaced by new sign-in", status="rotated")

    s, token = create_session(db, user, ctx, is_lab=ctx.is_harness)
    if previous is not None:
        s.rotated_from_id = previous.id
    record_event(db, "USER_LOGIN_SUCCESS", session=s, explanation=f"'{user.username}' signed in from {ctx.device.get('label')} "
                 f"on {ctx.network.get('network')}.", detection_method="authentication", action_taken="allow",
                 metadata=meta, timestamp=ctx.now, simulation_run_id=ctx.run_id)
    record_event(db, "SESSION_CREATED", session=s, explanation=f"Server-side session {s.public_id} created; token stored as "
                 f"HMAC-SHA256 hash (fingerprint {token_fingerprint(s.token_hash)}). Trust baseline initialised.",
                 detection_method="session_manager", action_taken="issue_token", metadata=meta, timestamp=ctx.now,
                 simulation_run_id=ctx.run_id)
    db.commit()
    flush_broadcasts(db)
    set_cookies(response, token, s)
    return {"user": serialize_user(user), "session": serialize_session(s, current_id=s.id), "csrf_token": csrf_for(s)}


@router.post("/logout")
def logout(response: Response, auth: AuthContext = Depends(protected("page", emit_activity=False)), db: Session = Depends(get_db)):
    s = auth.session
    revoke(s, auth.ctx.now, "user signed out", status="logged_out")
    record_event(db, "USER_LOGOUT", session=s, explanation=f"'{auth.user.username}' signed out; session invalidated server-side.",
                 detection_method="session_manager", action_taken="logout", timestamp=auth.ctx.now,
                 simulation_run_id=auth.ctx.run_id)
    db.commit()
    flush_broadcasts(db)
    clear_cookies(response)
    return {"ok": True}


@router.post("/reauthenticate")
def reauthenticate(body: ReauthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Step-up: a fresh password challenge (explicitly not MFA). Rotates the token on success."""
    settings = get_settings()
    ctx = build_context(request)
    s = find_by_token(db, request.cookies.get(settings.session_cookie_name))
    if s is None or s.status not in ACTIVE_STATUSES:
        raise deny(401, "not_authenticated", "Session is not active. Please sign in again.")
    supplied = request.headers.get(settings.csrf_header_name, "")
    if not supplied or not constant_time_equals(supplied, csrf_for(s)):
        raise deny(403, "csrf_failed", "Missing or invalid CSRF token.")

    user = s.user
    ok = verify_password(user.password_hash, body.password)
    db.add(AuthAttempt(username=user.username, user_id=user.id, success=ok, ip=ctx.ip, ts=ctx.ts, kind="step_up",
                       timestamp=ctx.now))
    meta = {"ip": ctx.ip, "device": ctx.device.get("label"), "region": ctx.network.get("region"), "client": ctx.client_label}
    if not ok:
        failures = db.query(AuthAttempt).filter(AuthAttempt.user_id == user.id, AuthAttempt.kind == "step_up",
                                                AuthAttempt.success.is_(False), AuthAttempt.ts >= s.baseline_ts).count() + 1
        record_event(db, "REAUTHENTICATION_FAILED", session=s, severity="high",
                     explanation=f"Step-up password challenge failed ({failures}/3).", detection_method="step_up",
                     action_taken="deny_401", risk_before=s.risk_score, risk_after=s.risk_score, metadata=meta,
                     timestamp=ctx.now, simulation_run_id=ctx.run_id)
        if failures >= 3:
            revoke(s, ctx.now, "3 failed step-up challenges")
            record_event(db, "SESSION_REVOKED", session=s, severity="critical",
                         explanation="Session revoked after three failed step-up challenges.", detection_method="step_up",
                         action_taken="revoke_session", risk_before=s.risk_score, risk_after=s.risk_score, metadata=meta,
                         timestamp=ctx.now, simulation_run_id=ctx.run_id)
        db.commit()
        flush_broadcasts(db)
        raise deny(401, "invalid_credentials", "Password challenge failed.")

    old_fp = token_fingerprint(s.token_hash)
    before = s.risk_score
    token = rotate(s)
    s.status = "active"
    s.baseline_device, s.baseline_network, s.baseline_ts = ctx.device, ctx.network, ctx.ts
    s.risk_score = 0.0
    s.alert_state = {"band": "low", "emitted": {}}
    s.step_up_until = ctx.now + timedelta(minutes=settings.step_up_valid_min)
    record_event(db, "REAUTHENTICATION_SUCCESS", session=s, severity="info",
                 explanation=f"Fresh password challenge passed. Trust re-established for {ctx.device.get('label')} on "
                             f"{ctx.network.get('network')}; sensitive actions allowed for {settings.step_up_valid_min} min.",
                 detection_method="step_up", action_taken="re_baseline", risk_before=before, risk_after=0.0, metadata=meta,
                 timestamp=ctx.now, simulation_run_id=ctx.run_id)
    record_event(db, "SESSION_ROTATED", session=s, explanation=f"Session token rotated after step-up ({old_fp} -> "
                 f"{token_fingerprint(s.token_hash)}); the previous token no longer works.", detection_method="session_manager",
                 action_taken="rotate_token", metadata=meta, timestamp=ctx.now, simulation_run_id=ctx.run_id)
    db.commit()
    flush_broadcasts(db)
    set_cookies(response, token, s)
    return {"ok": True, "session": serialize_session(s, current_id=s.id), "csrf_token": csrf_for(s)}


@router.get("/me")
def me(auth: AuthContext = Depends(protected("page", emit_activity=False))):
    return {"user": serialize_user(auth.user), "session": serialize_session(auth.session, current_id=auth.session.id),
            "csrf_token": csrf_for(auth.session)}


@router.get("/csrf")
def csrf(request: Request, db: Session = Depends(get_db)):
    s = find_by_token(db, request.cookies.get(get_settings().session_cookie_name))
    if s is None or s.status not in ACTIVE_STATUSES:
        raise HTTPException(401, detail={"code": "not_authenticated", "message": "Sign in required."})
    return {"csrf_token": csrf_for(s)}
