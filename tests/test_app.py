
import pytest

from backend.app import create_app
from backend.extensions import db
from backend.models import User


@pytest.fixture()
def app():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-for-tests-only",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def get_csrf_headers(client):
    response = client.get("/csrf-token")
    assert response.status_code == 200

    token = response.get_json()["csrf_token"]
    return {"X-CSRFToken": token}


def register_user(client, email="student@example.com"):
    return client.post(
        "/register",
        json={
            "email": email,
            "password": "Correct-Horse-Battery-12",
        },
        headers=get_csrf_headers(client),
    )


def test_health_endpoint_returns_success(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "service": "TrustVault",
    }


def test_registration_stores_password_hash_not_plaintext(client, app):
    password = "Correct-Horse-Battery-12"

    response = client.post(
        "/register",
        json={
            "email": "student@example.com",
            "password": password,
        },
        headers=get_csrf_headers(client),
    )

    assert response.status_code == 201

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="student@example.com")
        ).scalar_one()

        assert user.password_hash != password
        assert user.check_password(password)
        assert user.role == "viewer"


def test_duplicate_registration_is_rejected(client):
    assert register_user(client).status_code == 201
    assert register_user(client).status_code == 409


def test_login_and_logout(client):
    assert register_user(client).status_code == 201

    login_response = client.post(
        "/login",
        json={
            "email": "student@example.com",
            "password": "Correct-Horse-Battery-12",
        },
        headers=get_csrf_headers(client),
    )

    assert login_response.status_code == 200
    assert client.get("/me").status_code == 200

    logout_response = client.post(
        "/logout",
        headers=get_csrf_headers(client),
    )

    assert logout_response.status_code == 200
    assert client.get("/me").status_code == 401


def test_wrong_password_is_rejected(client):
    assert register_user(client).status_code == 201

    response = client.post(
        "/login",
        json={
            "email": "student@example.com",
            "password": "Wrong-Password-123",
        },
        headers=get_csrf_headers(client),
    )

    assert response.status_code == 401


def test_unauthenticated_user_cannot_access_profile(client):
    response = client.get("/me")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Authentication required"


def test_state_changing_request_requires_csrf_token(client):
    response = client.post(
        "/register",
        json={
            "email": "student@example.com",
            "password": "Correct-Horse-Battery-12",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "CSRF validation failed"


def test_app_requires_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
        create_app()
