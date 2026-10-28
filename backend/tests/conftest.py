from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

# Isolated temp DB per test session, and a fixed pepper so hashing is stable.
_tmp = tempfile.mkdtemp(prefix="sg_tests_")
os.environ["SG_DATABASE_URL"] = f"sqlite:///{Path(_tmp, 'test.db').as_posix()}"
os.environ["SG_TOKEN_PEPPER"] = "test-pepper-constant"
os.environ["SG_ACTIVE_MODEL"] = os.environ.get("SG_ACTIVE_MODEL", "aexgb")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402

DEMO_PW = "Demo-User!2027"
ADMIN_PW = "Admin-SOC!2027"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


class Session:
    """A browser-like wrapper that echoes the CSRF cookie as the header, as the SPA does."""

    # A realistic desktop browser UA so parsed telemetry is in-distribution for the ML model,
    # exactly as a real Chrome session on the dev server would be.
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")

    def __init__(self, base: TestClient):
        from starlette.testclient import TestClient as TC
        self.c = TC(base.app, headers={"User-Agent": self.UA, "Accept-Language": "en-US,en;q=0.9"})
        self.csrf = None

    def _h(self, headers):
        h = dict(headers or {})
        if self.csrf:
            h.setdefault(get_settings().csrf_header_name, self.csrf)
        return h

    def login(self, username, password):
        r = self.c.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r

    def get(self, path, **kw):
        return self.c.get(path, headers=self._h(kw.pop("headers", None)), **kw)

    def post(self, path, **kw):
        r = self.c.post(path, headers=self._h(kw.pop("headers", None)), **kw)
        if path in ("/api/auth/reauthenticate",) and r.status_code == 200:
            self.csrf = r.json().get("csrf_token", self.csrf)
        return r

    def delete(self, path, **kw):
        return self.c.delete(path, headers=self._h(kw.pop("headers", None)), **kw)

    @property
    def cookies(self):
        return self.c.cookies


@pytest.fixture
def user(client):
    s = Session(client)
    assert s.login("ada", DEMO_PW).status_code == 200
    return s


@pytest.fixture
def admin(client):
    s = Session(client)
    assert s.login("admin", ADMIN_PW).status_code == 200
    return s
