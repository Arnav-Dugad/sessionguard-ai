"""Protected resources of the fictional demo application ("Helios Vault").

These are the endpoints an attacker holding a stolen session token would want. Each one is
tagged with an endpoint category that the pipeline uses for sensitivity-aware containment.
All data is fictional and derived deterministically from the user id.
"""
from __future__ import annotations

import hashlib
import random

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.containment.pipeline import AuthContext, deny, protected
from app.database import get_db
from app.models import SecurityEvent, User
from app.schemas import ChangeEmailIn, TransferIn
from app.security.events import flush_broadcasts, record_event, serialize_event

router = APIRouter(prefix="/api/portal", tags=["portal"])

_DOCS = [
    ("Q3 Infrastructure Review", "report", "internal"), ("Vendor Contract — Orbit Logistics", "contract", "confidential"),
    ("Incident Postmortem #142", "postmortem", "internal"), ("Payroll Export (sample)", "finance", "restricted"),
    ("Roadmap 2027 Draft", "strategy", "confidential"), ("On-call Handbook", "guide", "internal"),
]


def _rng(user_id: int) -> random.Random:
    return random.Random(int(hashlib.sha256(f"helios:{user_id}".encode()).hexdigest()[:8], 16))


def _balance(db: Session, user: User) -> float:
    base = round(_rng(user.id).uniform(8_000, 25_000), 2)
    sent = sum(float((e.event_metadata or {}).get("amount", 0)) for e in db.query(SecurityEvent).filter_by(
        user_id=user.id, event_type="SENSITIVE_ACTION").all() if (e.event_metadata or {}).get("action") == "transfer")
    return round(base - sent, 2)


@router.get("/dashboard")
def dashboard(auth: AuthContext = Depends(protected("page")), db: Session = Depends(get_db)):
    r = _rng(auth.user.id)
    return {
        "workspace": "Helios Vault (fictional demo app)",
        "greeting": f"Welcome back, {auth.user.display_name or auth.user.username}",
        "balance": _balance(db, auth.user),
        "projects": [{"name": n, "progress": r.randint(20, 95)} for n in ("Atlas Migration", "Beacon API", "Comet Analytics")],
        "storage_used_gb": round(r.uniform(4, 60), 1),
    }


@router.get("/documents")
def documents(auth: AuthContext = Depends(protected("data"))):
    r = _rng(auth.user.id)
    return {"documents": [{"id": i + 1, "title": t, "kind": k, "classification": c, "size_kb": r.randint(40, 4200)}
                          for i, (t, k, c) in enumerate(_DOCS)]}


@router.get("/documents/{doc_id}")
def document(doc_id: int, auth: AuthContext = Depends(protected("data"))):
    if not 1 <= doc_id <= len(_DOCS):
        raise deny(404, "not_found", "Document not found.")
    t, k, c = _DOCS[doc_id - 1]
    return {"id": doc_id, "title": t, "kind": k, "classification": c,
            "excerpt": f"[Fictional content] {t} — prepared for {auth.user.display_name or auth.user.username}."}


@router.get("/profile")
def profile(auth: AuthContext = Depends(protected("page"))):
    u = auth.user
    return {"username": u.username, "email": u.email, "display_name": u.display_name, "role": u.role,
            "member_since": u.created_at.isoformat() + "Z"}


@router.get("/activity")
def activity(auth: AuthContext = Depends(protected("page", emit_activity=False)), db: Session = Depends(get_db)):
    rows = (db.query(SecurityEvent).filter(SecurityEvent.user_id == auth.user.id, SecurityEvent.event_type != "SESSION_ACTIVITY")
            .order_by(SecurityEvent.id.desc()).limit(60).all())
    return {"events": [serialize_event(e) for e in rows]}


def _sensitive_event(db: Session, auth: AuthContext, action: str, explanation: str, **meta) -> None:
    record_event(db, "SENSITIVE_ACTION", session=auth.session, severity="info", explanation=explanation,
                 detection_method="none", action_taken="allow", risk_before=auth.risk, risk_after=auth.risk,
                 metadata={"action": action, **meta}, timestamp=auth.ctx.now, simulation_run_id=auth.ctx.run_id)
    db.commit()
    flush_broadcasts(db)


@router.post("/export")
def export_data(auth: AuthContext = Depends(protected("sensitive")), db: Session = Depends(get_db)):
    _sensitive_event(db, auth, "export", f"{auth.user.username} exported workspace data ({len(_DOCS)} documents).")
    return {"ok": True, "export_id": f"exp_{auth.ctx.ts:.0f}", "documents": len(_DOCS),
            "note": "Fictional export — no real data leaves the system."}


@router.post("/transfer")
def transfer(body: TransferIn, auth: AuthContext = Depends(protected("sensitive")), db: Session = Depends(get_db)):
    balance = _balance(db, auth.user)
    if body.amount > balance:
        raise deny(400, "insufficient_funds", "Amount exceeds the (fictional) balance.")
    _sensitive_event(db, auth, "transfer", f"{auth.user.username} sent {body.amount:.2f} credits to {body.recipient}.",
                     amount=body.amount, recipient=body.recipient, memo=body.memo)
    return {"ok": True, "receipt": f"txn_{auth.ctx.ts:.0f}", "new_balance": round(balance - body.amount, 2)}


@router.post("/change-email")
def change_email(body: ChangeEmailIn, auth: AuthContext = Depends(protected("sensitive")), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email, User.id != auth.user.id).first():
        raise deny(409, "already_exists", "That email is in use.")
    old = auth.user.email
    auth.user.email = body.email
    _sensitive_event(db, auth, "change_email", f"{auth.user.username} changed account email.", old=old, new=body.email)
    return {"ok": True, "email": body.email}
