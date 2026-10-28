from conftest import DEMO_PW, Session


def test_session_rotation_on_login(client):
    s = Session(client)
    s.login("ada", DEMO_PW)
    first = s.cookies.get("sg_session")
    # A second login on the same client retires the first token.
    s.login("ada", DEMO_PW)
    second = s.cookies.get("sg_session")
    assert first != second
    from starlette.testclient import TestClient
    from app.main import app
    raw = TestClient(app)
    raw.cookies.set("sg_session", first)
    assert raw.get("/api/portal/dashboard").status_code == 401


def test_csrf_required_for_state_change(user):
    # Strip the CSRF header by calling the raw client directly.
    r = user.c.post("/api/portal/export")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_csrf_present_allows_state_change(user):
    r = user.post("/api/portal/export")
    assert r.status_code == 200


def test_list_own_sessions(user):
    r = user.get("/api/sessions")
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) >= 1
    assert any(s["is_current"] for s in sessions)
    # No session secret is ever exposed.
    assert all("token" not in str(k).lower() or k == "fingerprint" for s in sessions for k in s)


def test_user_cannot_see_others_sessions(user):
    r = user.get("/api/sessions?scope=all")
    assert r.status_code == 403


def test_revoke_specific_session(client):
    victim = Session(client)
    victim.login("grace", DEMO_PW)
    token = victim.cookies.get("sg_session")
    pid = victim.get("/api/auth/me").json()["session"]["id"]

    controller = Session(client)
    controller.login("grace", DEMO_PW)
    assert controller.delete(f"/api/sessions/{pid}").status_code == 200

    from starlette.testclient import TestClient
    from app.main import app
    raw = TestClient(app)
    raw.cookies.set("sg_session", token)
    assert raw.get("/api/portal/dashboard").status_code == 401


def test_session_isolation_404_for_other_user(user, client):
    grace = Session(client)
    grace.login("grace", DEMO_PW)
    grace_pid = grace.get("/api/auth/me").json()["session"]["id"]
    # ada tries to view grace's session detail -> 404 (no enumeration)
    assert user.get(f"/api/sessions/{grace_pid}").status_code == 404
