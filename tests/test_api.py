import datetime

import jwt

from app.models import User


def test_login_ok(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"


def test_login_wrong_password(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "invalid credentials"}


def test_login_unknown_user_same_answer(client):
    resp = client.post("/auth/login", json={"username": "nobody", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "invalid credentials"}


def test_login_no_json(client):
    resp = client.post("/auth/login", data="username=admin")
    assert resp.status_code == 400


def test_login_sqli_attempt(client):
    resp = client.post("/auth/login", json={"username": "admin' OR '1'='1' --", "password": "x"})
    assert resp.status_code == 401


def test_data_without_token(client):
    resp = client.get("/api/data")
    assert resp.status_code == 401


def test_data_bad_token(client):
    resp = client.get("/api/data", headers={"Authorization": "Bearer abc.def.ghi"})
    assert resp.status_code == 401


def test_data_expired_token(client, app):
    with app.app_context():
        now = datetime.datetime.now(datetime.timezone.utc)
        token = jwt.encode(
            {"sub": "1", "iat": now - datetime.timedelta(hours=2), "exp": now - datetime.timedelta(hours=1)},
            app.config["JWT_SECRET"],
            algorithm="HS256",
        )
    resp = client.get("/api/data", headers={"Authorization": "Bearer " + token})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "token expired"


def test_data_with_token(client, token):
    resp = client.get("/api/data", headers={"Authorization": "Bearer " + token})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 3
    assert data["data"][0]["author"] == "admin"


def test_xss_escaped(client, token):
    resp = client.get("/api/data", headers={"Authorization": "Bearer " + token})
    text = resp.get_data(as_text=True)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "<img" not in text


def test_me(client, token):
    resp = client.get("/api/me", headers={"Authorization": "Bearer " + token})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "admin"


def test_password_hashed(app):
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        assert user.password_hash != "admin123"
        assert user.password_hash.startswith("$2b$")


def test_security_headers(client):
    resp = client.get("/api/data")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
