import pytest

from app import create_app
from app.config import TestConfig
from app.models import db


@pytest.fixture
def app():
    app = create_app(TestConfig)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def token(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    return resp.get_json()["access_token"]
