
import pytest

from backend.app import create_app
from backend.extensions import db
from backend.audit import log_audit_event, verify_audit_chain
from backend.models import AuditLog, User


PASSWORD = "Correct-Horse-Battery-12"



@pytest.fixture()
def app():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-for-tests-only",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
        "REMEMBER_COOKIE_SECURE": False,
    })

    # Create tables inside a temporary application context.
    with app.app_context():
        db.create_all()

    # IMPORTANT: Do not keep an application context open
    # while the test client sends requests.
    yield app

    # Clean up after the test in a separate context.
    with app.app_context():
        db.session.remove()
        db.drop_all()



@pytest.fixture()
def client(app):
    return app.test_client()



def csrf_headers(client):
    response = client.get("/csrf-token")

    assert response.status_code == 200, (
        f"CSRF endpoint failed: {response.get_json()}"
    )

    token = response.get_json().get("csrf_token")

    assert token, "CSRF token was not returned."

    return {"X-CSRFToken": token}


def register(client, email):
    return client.post(
        "/register",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )


def login(client, email):
    return client.post(
        "/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )


def register_and_login(client, email):
    response = register(client, email)

    assert response.status_code == 201, (
        f"Registration failed for {email}: "
        f"status={response.status_code}, "
        f"body={response.get_json()}"
    )

    response = login(client, email)

    assert response.status_code == 200, (
        f"Login failed for {email}: "
        f"status={response.status_code}, "
        f"body={response.get_json()}"
    )


def create_document(client, title="Project Plan"):
    return client.post(
        "/documents",
        json={
            "title": title,
            "category": "Projects",
            "description": "A test document",
        },
        headers=csrf_headers(client),
    )


def grant_permission(client, document_id, email, level):
    return client.post(
        f"/documents/{document_id}/permissions",
        json={
            "email": email,
            "permission_level": level,
        },
        headers=csrf_headers(client),
    )


def test_health_endpoint_returns_success(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "service": "TrustVault",
    }


def test_registration_stores_password_hash_not_plaintext(client, app):
    response = register(client, "student@example.com")

    assert response.status_code == 201

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="student@example.com")
        ).scalar_one()

        assert user.password_hash != PASSWORD
        assert user.check_password(PASSWORD)
        assert user.role == "viewer"


def test_duplicate_registration_is_rejected(client):
    assert register(client, "student@example.com").status_code == 201
    assert register(client, "student@example.com").status_code == 409


def test_login_and_logout(client):
    register_and_login(client, "student@example.com")

    assert client.get("/me").status_code == 200

    response = client.post(
        "/logout",
        headers=csrf_headers(client),
    )

    assert response.status_code == 200
    assert client.get("/me").status_code == 401


def test_wrong_password_is_rejected(client):
    assert register(client, "student@example.com").status_code == 201

    response = client.post(
        "/login",
        json={
            "email": "student@example.com",
            "password": "Wrong-Password-123",
        },
        headers=csrf_headers(client),
    )

    assert response.status_code == 401


def test_unauthenticated_user_cannot_access_profile(client):
    response = client.get("/me")

    assert response.status_code == 401


def test_state_changing_request_requires_csrf_token():
    csrf_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-test-secret-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
        "REMEMBER_COOKIE_SECURE": False,
    })

    csrf_client = csrf_app.test_client()

    response = csrf_client.post(
        "/register",
        json={
            "email": "student@example.com",
            "password": PASSWORD,
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "CSRF validation failed"


def test_app_requires_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
        create_app()


def test_owner_can_create_and_read_document(client):
    register_and_login(client, "owner@example.com")

    response = create_document(client)

    assert response.status_code == 201
    document_id = response.get_json()["id"]

    response = client.get(f"/documents/{document_id}")

    assert response.status_code == 200
    assert response.get_json()["access"] == "OWNER"


def test_document_is_not_visible_to_an_ungranted_user(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    response = create_document(owner)
    document_id = response.get_json()["id"]

    response = viewer.get(f"/documents/{document_id}")

    assert response.status_code == 403

    response = viewer.get("/documents")

    assert response.status_code == 200
    assert response.get_json()["documents"] == []


def test_read_permission_allows_reading_but_not_editing(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    grant = grant_permission(
        owner,
        document_id,
        "viewer@example.com",
        "READ",
    )

    assert grant.status_code == 200

    response = viewer.get(f"/documents/{document_id}")

    assert response.status_code == 200
    assert response.get_json()["access"] == "READ"

    response = viewer.patch(
        f"/documents/{document_id}",
        json={"title": "Changed by viewer"},
        headers=csrf_headers(viewer),
    )

    assert response.status_code == 403


def test_edit_permission_allows_reading_and_editing(app):
    owner = app.test_client()
    editor = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(editor, "editor@example.com")

    document_id = create_document(owner).get_json()["id"]

    grant = grant_permission(
        owner,
        document_id,
        "editor@example.com",
        "EDIT",
    )

    assert grant.status_code == 200
    assert editor.get(f"/documents/{document_id}").status_code == 200

    response = editor.patch(
        f"/documents/{document_id}",
        json={"title": "Updated by editor"},
        headers=csrf_headers(editor),
    )

    assert response.status_code == 200
    assert response.get_json()["title"] == "Updated by editor"


def test_revoking_permission_blocks_subsequent_requests(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    grant = grant_permission(
        owner,
        document_id,
        "viewer@example.com",
        "READ",
    )

    assert grant.status_code == 200
    user_id = grant.get_json()["user_id"]

    assert viewer.get(f"/documents/{document_id}").status_code == 200

    response = owner.delete(
        f"/documents/{document_id}/permissions/{user_id}",
        headers=csrf_headers(owner),
    )

    assert response.status_code == 200
    assert viewer.get(f"/documents/{document_id}").status_code == 403


def test_non_owner_cannot_grant_permissions(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    response = grant_permission(
        viewer,
        document_id,
        "owner@example.com",
        "EDIT",
    )

    assert response.status_code == 403



def test_audit_events_form_a_valid_hash_chain(app):
    with app.app_context():
        first = log_audit_event(
            action="DOCUMENT_CREATED",
            outcome="SUCCESS",
            actor_email="owner@example.com",
            document_id=1,
            details={"category": "Projects"},
        )

        second = log_audit_event(
            action="PERMISSION_GRANTED",
            outcome="SUCCESS",
            actor_email="owner@example.com",
            document_id=1,
            target_user_id=2,
            details={"permission_level": "READ"},
        )

        assert first.previous_hash == "0" * 64
        assert second.previous_hash == first.event_hash
        assert verify_audit_chain() is True


def test_audit_chain_detects_modified_event(app):
    with app.app_context():
        log_audit_event(
            action="DOCUMENT_CREATED",
            outcome="SUCCESS",
            actor_email="owner@example.com",
            document_id=1,
            details={"category": "Projects"},
        )

        assert verify_audit_chain() is True

        event = db.session.execute(
            db.select(AuditLog).order_by(AuditLog.id.asc())
        ).scalars().first()

        event.details = {"category": "Tampered"}
        db.session.commit()

        assert verify_audit_chain() is False



def test_document_creation_and_update_are_audited(app):
    client = app.test_client()
    register_and_login(client, "owner@example.com")

    response = create_document(client)
    assert response.status_code == 201
    document_id = response.get_json()["id"]

    response = client.patch(
        f"/documents/{document_id}",
        json={"title": "Updated Project Plan"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200

    with app.app_context():
        events = db.session.execute(
            db.select(AuditLog)
            .where(AuditLog.document_id == document_id)
            .order_by(AuditLog.id.asc())
        ).scalars().all()

        assert [
            (event.action, event.outcome)
            for event in events
        ] == [
            ("DOCUMENT_CREATED", "SUCCESS"),
            ("DOCUMENT_UPDATED", "SUCCESS"),
        ]

        assert events[1].details["fields_changed"] == ["title"]
        assert verify_audit_chain() is True


def test_denied_document_read_and_edit_are_audited(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    response = viewer.get(f"/documents/{document_id}")
    assert response.status_code == 403

    response = viewer.patch(
        f"/documents/{document_id}",
        json={"title": "Unauthorized change"},
        headers=csrf_headers(viewer),
    )
    assert response.status_code == 403

    with app.app_context():
        events = db.session.execute(
            db.select(AuditLog)
            .where(
                AuditLog.document_id == document_id,
                AuditLog.outcome == "DENIED",
            )
            .order_by(AuditLog.id.asc())
        ).scalars().all()

        assert [
            event.action for event in events
        ] == [
            "DOCUMENT_READ",
            "DOCUMENT_UPDATE",
        ]

        assert all(
            event.actor_email == "viewer@example.com"
            for event in events
        )

        assert verify_audit_chain() is True


def test_permission_grant_change_and_revoke_are_audited(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    # Grant READ permission.
    response = grant_permission(
        owner, document_id, "viewer@example.com", "READ"
    )
    assert response.status_code == 200
    user_id = response.get_json()["user_id"]

    # Change READ permission to EDIT.
    response = grant_permission(
        owner, document_id, "viewer@example.com", "EDIT"
    )
    assert response.status_code == 200

    # Revoke the permission.
    response = owner.delete(
        f"/documents/{document_id}/permissions/{user_id}",
        headers=csrf_headers(owner),
    )
    assert response.status_code == 200

    with app.app_context():
        events = db.session.execute(
            db.select(AuditLog)
            .where(AuditLog.document_id == document_id)
            .order_by(AuditLog.id.asc())
        ).scalars().all()

        permission_events = [
            event for event in events
            if event.action.startswith("PERMISSION_")
        ]

        assert [
            (event.action, event.outcome)
            for event in permission_events
        ] == [
            ("PERMISSION_GRANTED", "SUCCESS"),
            ("PERMISSION_CHANGED", "SUCCESS"),
            ("PERMISSION_REVOKED", "SUCCESS"),
        ]

        assert all(
            event.target_user_id == user_id
            for event in permission_events
        )

        assert permission_events[0].details["permission_level"] == "READ"
        assert permission_events[1].details["permission_level"] == "EDIT"
        assert permission_events[2].details["permission_level"] == "EDIT"

        assert verify_audit_chain() is True


def test_denied_permission_grant_is_audited(app):
    owner = app.test_client()
    viewer = app.test_client()

    register_and_login(owner, "owner@example.com")
    register_and_login(viewer, "viewer@example.com")

    document_id = create_document(owner).get_json()["id"]

    response = grant_permission(
        viewer, document_id, "owner@example.com", "EDIT"
    )
    assert response.status_code == 403

    with app.app_context():
        event = db.session.execute(
            db.select(AuditLog)
            .where(
                AuditLog.document_id == document_id,
                AuditLog.action == "PERMISSION_GRANT",
                AuditLog.outcome == "DENIED",
            )
        ).scalar_one()

        assert event.actor_email == "viewer@example.com"
        assert event.details["reason"] == "not_document_owner"
        assert verify_audit_chain() is True



def test_admin_audit_endpoint_requires_authentication(client):
    response = client.get("/admin/audit-logs")

    assert response.status_code == 401


def test_viewer_cannot_access_admin_audit_endpoint(client):
    register_and_login(client, "viewer@example.com")

    response = client.get("/admin/audit-logs")

    assert response.status_code == 403


def test_admin_can_view_paginated_audit_events(app):
    admin = app.test_client()

    register_and_login(admin, "admin@example.com")

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="admin@example.com")
        ).scalar_one()
        user.role = "admin"
        db.session.commit()

    # Log in again so the test uses the administrator's session.
    response = login(admin, "admin@example.com")
    assert response.status_code == 200

    response = create_document(admin, title="Admin Test Document")
    assert response.status_code == 201

    response = admin.get("/admin/audit-logs?page=1&per_page=1")

    assert response.status_code == 200

    data = response.get_json()
    assert data["page"] == 1
    assert data["per_page"] == 1
    assert data["total"] >= 1
    assert len(data["events"]) == 1

    event = data["events"][0]
    assert "action" in event
    assert "outcome" in event
    assert "event_hash" in event
    assert "previous_hash" in event


def test_admin_audit_endpoint_rejects_invalid_pagination(client):
    register_and_login(client, "viewer@example.com")

    with client.application.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="viewer@example.com")
        ).scalar_one()
        user.role = "admin"
        db.session.commit()

    # Log in again after changing the role.
    login(client, "viewer@example.com")

    response = client.get("/admin/audit-logs?page=0")

    assert response.status_code == 400

    response = client.get("/admin/audit-logs?per_page=101")

    assert response.status_code == 400



def test_admin_cannot_read_document_without_permission(app):
    owner_client = app.test_client()
    register_and_login(owner_client, "owner@example.com")

    response = create_document(
        owner_client,
        title="Private Owner Document",
    )
    assert response.status_code == 201
    document_id = response.get_json()["id"]

    admin_client = app.test_client()
    register_and_login(admin_client, "admin@example.com")

    with app.app_context():
        admin = db.session.execute(
            db.select(User).filter_by(email="admin@example.com")
        ).scalar_one()
        admin.role = "admin"
        db.session.commit()

    login_response = login(admin_client, "admin@example.com")
    assert login_response.status_code == 200

    response = admin_client.get(f"/documents/{document_id}")

    assert response.status_code == 403