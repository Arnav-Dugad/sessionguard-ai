from conftest import ADMIN_PW, DEMO_PW, Session


def test_login_success(user):
    r = user.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "ada"


def test_invalid_password(client):
    # Uses 'grace' (not 'ada') so the recorded failed attempt does not pollute the
    # failed_auth_15m feature for ada, which the risk/e2e tests depend on.
    s = Session(client)
    r = s.login("grace", "wrong-password")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"


def test_unknown_user_same_error(client):
    s = Session(client)
    r = s.login("nobody", "whatever123")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"


def test_unauthenticated_access_denied(client):
    s = Session(client)
    assert s.get("/api/portal/dashboard").status_code == 401


def test_logout_invalidates_session(user):
    token = user.cookies.get("sg_session")
    assert user.post("/api/auth/logout").status_code == 200
    # Re-present the old token directly: server must reject it.
    from starlette.testclient import TestClient
    from app.main import app
    raw = TestClient(app)
    raw.cookies.set("sg_session", token)
    assert raw.get("/api/portal/dashboard").status_code == 401


def test_role_gate_blocks_normal_user(user):
    r = user.get("/api/security/overview")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_admin_can_reach_console(admin):
    assert admin.get("/api/security/overview").status_code == 200


def test_registration_and_login(client):
    s = Session(client)
    r = s.c.post("/api/auth/register", json={"username": "newbie", "email": "new@helios.example",
                                             "password": "Str0ng-Pass!", "display_name": "New Bie"})
    assert r.status_code == 201
    assert s.login("newbie", "Str0ng-Pass!").status_code == 200


def test_weak_password_rejected(client):
    s = Session(client)
    r = s.c.post("/api/auth/register", json={"username": "weak", "email": "weak@helios.example", "password": "alllowercase"})
    assert r.status_code == 422


def test_rate_limit_after_many_failures(client):
    # Use a throwaway username so this does not rate-limit a real demo account other tests use.
    s = Session(client)
    codes = [s.login("ratelimit-probe", "bad-password-x").status_code for _ in range(25)]
    assert 429 in codes
