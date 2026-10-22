
import pytest

from backend.app import create_app
from backend.extensions import db


@pytest.fixture()
def app():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_health_endpoint_returns_success(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "service": "TrustVault",
    }


def test_registration_stores_password_hash_not_plaintext(client, app):
    password = "Correct-Horse-Battery-12"

    response = client.post("/register", json={
        "email": "student@example.com",
        "password": password,
    })

    assert response.status_code == 201

    with app.app_context():
        from backend.models import User

        user = db.session.execute(
            db.select(User).filter_by(email="student@example.com")
        ).scalar_one()

        assert user.password_hash != password
        assert user.check_password(password)
        assert user.role == "viewer"


def test_duplicate_registration_is_rejected(client):
    account = {
        "email": "student@example.com",
        "password": "Correct-Horse-Battery-12",
    }

    assert client.post("/register", json=account).status_code == 201
    assert client.post("/register", json=account).status_code == 409


def test_login_and_logout(client):
    client.post("/register", json={
        "email": "student@example.com",
        "password": "Correct-Horse-Battery-12",
    })

    response = client.post("/login", json={
        "email": "student@example.com",
        "password": "Correct-Horse-Battery-12",
    })

    assert response.status_code == 200
    assert client.get("/me").status_code == 200
    assert client.post("/logout").status_code == 200
    assert client.get("/me").status_code == 401


def test_wrong_password_is_rejected(client):
    client.post("/register", json={
        "email": "student@example.com",
        "password": "Correct-Horse-Battery-12",
    })

    response = client.post("/login", json={
        "email": "student@example.com",
        "password": "Wrong-Password-123",
    })

    assert response.status_code == 401


def test_unauthenticated_user_cannot_access_profile(client):
    response = client.get("/me")

    assert response.status_code == 401
