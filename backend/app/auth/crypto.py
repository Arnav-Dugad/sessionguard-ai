"""Password hashing, session tokens and CSRF tokens."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import get_settings

# Argon2id with OWASP-recommended baseline parameters (m=19 MiB, t=2, p=1).
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
_DUMMY_HASH = _hasher.hash("timing-equaliser")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-ish time verification: a missing user still pays the Argon2 cost."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def new_session_token() -> str:
    """256 bits from the OS CSPRNG. Only ever sent to the client; never stored."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """HMAC-SHA256 with a server pepper, so a leaked database cannot be used to forge cookies."""
    pepper = get_settings().token_pepper.encode()
    return hmac.new(pepper, token.encode(), hashlib.sha256).hexdigest()


def token_fingerprint(token_hash: str) -> str:
    """Short non-secret identifier for display (first 8 hex chars of the at-rest hash)."""
    return token_hash[:8]


def new_public_id() -> str:
    return "ses_" + secrets.token_hex(6)


def new_event_uid() -> str:
    return "evt_" + secrets.token_hex(6)


def new_csrf_secret() -> str:
    return secrets.token_hex(16)


def csrf_token_for(csrf_secret: str, token_hash: str) -> str:
    """CSRF token bound to the session: rotating the session rotates the CSRF token."""
    pepper = get_settings().token_pepper.encode()
    return hmac.new(pepper, f"csrf:{csrf_secret}:{token_hash}".encode(), hashlib.sha256).hexdigest()[:48]


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
