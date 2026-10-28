from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import joinedload

from app.auth.sessions import ACTIVE_STATUSES, find_by_token
from app.config import get_settings
from app.database import SessionLocal
from app.models import SecurityEvent, UserSession
from app.security.events import serialize_event
from app.websocket.hub import hub

router = APIRouter(tags=["live"])


def _authorize(token: str | None) -> bool:
    """WebSocket consumers must present an admin session cookie. Tokens are validated against
    server-side state exactly like REST requests - no token value is ever sent over the socket."""
    if not token:
        return False
    db = SessionLocal()
    try:
        s = find_by_token(db, token)
        return bool(s and s.status in ACTIVE_STATUSES and s.user and s.user.role == "admin")
    finally:
        db.close()


@router.websocket("/ws/security-events")
async def security_events(ws: WebSocket):
    token = ws.cookies.get(get_settings().session_cookie_name)
    if not _authorize(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    queue = hub.subscribe()

    db = SessionLocal()
    try:
        recent = (db.query(SecurityEvent).options(joinedload(SecurityEvent.session).joinedload(UserSession.user))
                  .filter(SecurityEvent.event_type != "SESSION_ACTIVITY").order_by(SecurityEvent.id.desc()).limit(25).all())
        for ev in reversed(recent):
            await ws.send_json({"type": "event", "data": serialize_event(ev)})
    finally:
        db.close()
    await ws.send_json({"type": "ready", "data": {"subscribers": hub.subscriber_count}})

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=20)
                await ws.send_text(msg)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping", "data": {}})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(queue)
