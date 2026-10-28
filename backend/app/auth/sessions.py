"""Server-side session lifecycle: creation, lookup, rotation, revocation, cookies."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import User, UserSession
from app.telemetry.context import RequestContext

from .crypto import csrf_token_for, hash_token, new_csrf_secret, new_public_id, new_session_token, token_fingerprint

ACTIVE_STATUSES = ("active", "step_up")


def create_session(db: Session, user: User, ctx: RequestContext, *, is_lab: bool = False) -> tuple[UserSession, str]:
    settings = get_settings()
    token = new_session_token()
    s = UserSession(
        public_id=new_public_id(),
        user_id=user.id,
        token_hash=hash_token(token),
        created_at=ctx.now,
        last_activity=ctx.now,
        expires_at=ctx.now + timedelta(minutes=settings.session_absolute_timeout_min),
        device_profile=ctx.device,
        network_context=ctx.network,
        baseline_device=ctx.device,
        baseline_network=ctx.network,
        baseline_ts=ctx.ts,
        last_ts=ctx.ts,
        risk_score=0.0,
        status="active",
        is_lab=is_lab,
        csrf_secret=new_csrf_secret(),
        alert_state={},
    )
    db.add(s)
    db.flush()
    return s, token


def find_by_token(db: Session, token: str | None) -> UserSession | None:
    if not token or len(token) > 128:
        return None
    return db.query(UserSession).filter_by(token_hash=hash_token(token)).one_or_none()


def csrf_for(s: UserSession) -> str:
    return csrf_token_for(s.csrf_secret, s.token_hash)


def set_cookies(response: Response, token: str, s: UserSession) -> None:
    settings = get_settings()
    max_age = settings.session_absolute_timeout_min * 60
    response.set_cookie(
        settings.session_cookie_name, token, max_age=max_age, httponly=True,
        secure=settings.cookie_secure, samesite="strict", path="/",
    )
    # Readable by the SPA so it can echo it in the X-CSRF-Token header (double submit, bound to the session).
    response.set_cookie(
        settings.csrf_cookie_name, csrf_for(s), max_age=max_age, httponly=False,
        secure=settings.cookie_secure, samesite="strict", path="/",
    )


def clear_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


def rotate(s: UserSession) -> str:
    """Issue a fresh token for the same server-side session; the old token stops working immediately."""
    token = new_session_token()
    s.token_hash = hash_token(token)
    s.csrf_secret = new_csrf_secret()
    return token


def revoke(s: UserSession, now: datetime, reason: str, status: str = "revoked") -> None:
    if s.status in ACTIVE_STATUSES:
        s.status = status
        s.revoked_at = now
        s.revoked_reason = reason


def expiry_reason(s: UserSession, now: datetime) -> str | None:
    settings = get_settings()
    if now >= s.expires_at:
        return "absolute timeout"
    if now - s.last_activity > timedelta(minutes=settings.session_idle_timeout_min):
        return "idle timeout"
    return None


def band_of(score: float) -> str:
    return "critical" if score >= 75 else "high" if score >= 50 else "elevated" if score >= 25 else "low"


def serialize_session(s: UserSession, *, current_id: int | None = None) -> dict[str, Any]:
    return {
        "id": s.public_id,
        "fingerprint": token_fingerprint(s.token_hash),
        "username": s.user.username if s.user else None,
        "user_role": s.user.role if s.user else None,
        "created_at": s.created_at.isoformat() + "Z",
        "last_activity": s.last_activity.isoformat() + "Z",
        "expires_at": s.expires_at.isoformat() + "Z",
        "revoked_at": s.revoked_at.isoformat() + "Z" if s.revoked_at else None,
        "revoked_reason": s.revoked_reason,
        "device": s.device_profile,
        "network": s.network_context,
        "baseline_device": s.baseline_device,
        "baseline_network": s.baseline_network,
        "risk_score": round(s.risk_score, 2),
        "peak_risk": round(s.peak_risk, 2),
        "band": (s.alert_state or {}).get("band") or band_of(s.risk_score),
        "status": s.status,
        "protection_mode": s.protection_mode,
        "is_lab": s.is_lab,
        "request_count": s.request_count,
        "step_up_until": s.step_up_until.isoformat() + "Z" if s.step_up_until else None,
        "is_current": current_id is not None and s.id == current_id,
    }
