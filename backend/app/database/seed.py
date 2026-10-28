"""Idempotent seeding of demonstration accounts and the default policy.

All identities are fictional. Passwords are intentionally printed here and in the docs because
this is a local demonstration system - never reuse this pattern for anything real.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.auth.crypto import hash_password
from app.models import PolicyConfig, User
from app.risk.policy import Policy

DEMO_ACCOUNTS = [
    {"username": "ada", "email": "ada@helios.example", "display_name": "Ada Lovelace", "password": "Demo-User!2027",
     "role": "user"},
    {"username": "grace", "email": "grace@helios.example", "display_name": "Grace Hopper", "password": "Demo-User!2027",
     "role": "user"},
    {"username": "admin", "email": "admin@helios.example", "display_name": "SOC Administrator", "password": "Admin-SOC!2027",
     "role": "admin"},
]


def seed(db: Session) -> dict[str, int]:
    created = 0
    for acc in DEMO_ACCOUNTS:
        if not db.query(User).filter_by(username=acc["username"]).first():
            db.add(User(username=acc["username"], email=acc["email"], display_name=acc["display_name"],
                        password_hash=hash_password(acc["password"]), role=acc["role"], is_demo=True))
            created += 1
    if not db.query(PolicyConfig).filter_by(name="active").first():
        db.add(PolicyConfig(name="active", config=Policy().model_dump(), updated_by="seed"))
    db.commit()
    return {"created": created, "total": db.query(User).count()}
