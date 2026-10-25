
import pytest

from backend.app import create_app
from backend.extensions import db
from backend.audit import log_audit_event, verify_audit_chain
from backend.models import AuditLog, Company, CompanyMembership, User, WorkspaceInvitation, WorkspaceJoinRequest, LoginOTP

from backend.email_service import send_email


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


def register(client, email, company_name=None, requested_role=None):
    if company_name is None:
        company_name = f"{email.split('@')[0]}'s Workspace"

    payload = {
        "email": email,
        "password": PASSWORD,
        "company_name": company_name,
    }
    if requested_role is not None:
        payload["requested_role"] = requested_role

    return client.post(
        "/register",
        json=payload,
        headers=csrf_headers(client),
    )


def login(client, email):
    response = client.post(
        "/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    if response.status_code != 200:
        return response
    payload = response.get_json() or {}
    if "challenge_id" in payload:
        return client.post(
            "/login/verify-otp",
            json={"challenge_id": payload["challenge_id"], "otp": payload.get("test_otp", "")},
            headers=csrf_headers(client),
        )
    return response


def register_and_login(client, email, company_name=None):
    response = register(client, email, company_name)

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


def put_user_in_same_company(app, owner_email, member_email):
    """Move a test user into the owner's workspace as a regular member."""
    with app.app_context():
        owner = db.session.execute(
            db.select(User).filter_by(email=owner_email)
        ).scalar_one()
        member = db.session.execute(
            db.select(User).filter_by(email=member_email)
        ).scalar_one()

        owner_membership = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=owner.id)
        ).scalar_one()
        member_membership = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=member.id)
        ).scalar_one()

        member_membership.company_id = owner_membership.company_id
        member_membership.role = "member"
        db.session.commit()


def set_company_membership_role(app, email, role):
    """Set a test user's workspace role explicitly."""
    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one()
        membership = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=user.id)
        ).scalar_one()
        membership.role = role
        db.session.commit()


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
    put_user_in_same_company(app, "owner@example.com", "viewer@example.com")

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
    put_user_in_same_company(app, "owner@example.com", "editor@example.com")

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
    put_user_in_same_company(app, "owner@example.com", "viewer@example.com")

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
    put_user_in_same_company(app, "owner@example.com", "viewer@example.com")

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
    set_company_membership_role(app=client.application, email="viewer@example.com", role="member")

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



def test_email_service_suppresses_sending_in_development(app, monkeypatch):
    import backend.email_service as email_service

    def unexpected_smtp(*args, **kwargs):
        raise AssertionError("SMTP must not be called")

    monkeypatch.setattr(email_service.smtplib, "SMTP", unexpected_smtp)
    monkeypatch.setattr(email_service.smtplib, "SMTP_SSL", unexpected_smtp)

    with app.app_context():
        app.config["MAIL_SUPPRESS_SEND"] = True

        send_email(
            "test@example.com",
            "Test email",
            "This email must not be delivered.",
        )


def test_email_service_requires_server_configuration(app):
    with app.app_context():
        app.config["MAIL_SUPPRESS_SEND"] = False
        app.config["MAIL_SERVER"] = ""
        app.config["MAIL_DEFAULT_SENDER"] = ""

        try:
            send_email(
                "test@example.com",
                "Test email",
                "Test body",
            )
        except RuntimeError as error:
            assert "MAIL_SERVER" in str(error)
        else:
            raise AssertionError("Missing SMTP configuration must fail")


def test_multi_workspace_user_must_select_active_workspace_and_is_isolated(app):
    owner_a = app.test_client()
    owner_b = app.test_client()
    shared = app.test_client()

    register_and_login(owner_a, "owner-a@example.com")
    register_and_login(owner_b, "owner-b@example.com")
    register_and_login(shared, "shared@example.com")

    doc_a = create_document(owner_a, title="Company A Secret").get_json()["id"]
    doc_b = create_document(owner_b, title="Company B Secret").get_json()["id"]

    with app.app_context():
        owner_a_user = db.session.execute(
            db.select(User).filter_by(email="owner-a@example.com")
        ).scalar_one()
        owner_b_user = db.session.execute(
            db.select(User).filter_by(email="owner-b@example.com")
        ).scalar_one()
        shared_user = db.session.execute(
            db.select(User).filter_by(email="shared@example.com")
        ).scalar_one()
        membership_a = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=owner_a_user.id)
        ).scalar_one()
        membership_b = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=owner_b_user.id)
        ).scalar_one()
        shared_membership = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=shared_user.id)
        ).scalar_one()

        # Put the account into two workspaces. This models two separate
        # invitations accepted by the same registered account.
        shared_membership.company_id = membership_a.company_id
        shared_membership.role = "member"
        db.session.add(CompanyMembership(
            company_id=membership_b.company_id,
            user_id=shared_user.id,
            role="member",
        ))
        db.session.commit()
        company_a_id = membership_a.company_id
        company_b_id = membership_b.company_id

    # Workspace membership alone must not expose every document. Grant this
    # shared account explicit READ access to one document in each workspace,
    # then verify that switching workspaces scopes the listing correctly.
    grant_a = grant_permission(owner_a, doc_a, "shared@example.com", "READ")
    grant_b = grant_permission(owner_b, doc_b, "shared@example.com", "READ")
    assert grant_a.status_code == 200, grant_a.get_json()
    assert grant_b.status_code == 200, grant_b.get_json()

    # Re-login so the session is initialized for a multi-workspace account.
    assert login(shared, "shared@example.com").status_code == 200
    assert shared.get("/documents").status_code == 403

    response = shared.get("/companies")
    assert response.status_code == 200
    assert len(response.get_json()["companies"]) == 2

    response = shared.post(
        "/companies/active",
        json={"company_id": company_a_id},
        headers=csrf_headers(shared),
    )
    assert response.status_code == 200
    listing = shared.get("/documents").get_json()["documents"]
    assert [item["id"] for item in listing] == [doc_a]
    assert shared.get(f"/documents/{doc_b}").status_code == 403

    response = shared.post(
        "/companies/active",
        json={"company_id": company_b_id},
        headers=csrf_headers(shared),
    )
    assert response.status_code == 200
    listing = shared.get("/documents").get_json()["documents"]
    assert [item["id"] for item in listing] == [doc_b]
    assert shared.get(f"/documents/{doc_a}").status_code == 403


def test_user_cannot_switch_to_unjoined_workspace(app):
    member = app.test_client()
    other = app.test_client()
    register_and_login(member, "member@example.com")
    register_and_login(other, "other@example.com")

    with app.app_context():
        other_user = db.session.execute(
            db.select(User).filter_by(email="other@example.com")
        ).scalar_one()
        other_membership = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=other_user.id)
        ).scalar_one()
        other_company_id = other_membership.company_id

    response = member.post(
        "/companies/active",
        json={"company_id": other_company_id},
        headers=csrf_headers(member),
    )
    assert response.status_code == 403
    assert member.get("/documents").get_json()["documents"] == []


def test_audit_logs_are_scoped_to_active_workspace_and_deleted_doc_history_remains(app):
    owner_a = app.test_client()
    owner_b = app.test_client()
    register_and_login(owner_a, "audit-a@example.com")
    register_and_login(owner_b, "audit-b@example.com")

    doc_a_response = create_document(owner_a, title="Audit A")
    doc_b_response = create_document(owner_b, title="Audit B")
    doc_a = doc_a_response.get_json()["id"]
    doc_b = doc_b_response.get_json()["id"]

    with app.app_context():
        user_a = db.session.execute(
            db.select(User).filter_by(email="audit-a@example.com")
        ).scalar_one()
        membership_a = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=user_a.id)
        ).scalar_one()
        company_a_id = membership_a.company_id

    # Delete A's document. Its audit row should remain queryable in A's workspace.
    response = owner_a.delete(f"/documents/{doc_a}", headers=csrf_headers(owner_a))
    assert response.status_code == 200

    events_a = owner_a.get("/admin/audit-logs?per_page=100").get_json()["events"]
    assert any(
        event["document_id"] == doc_a and event["action"] == "DOCUMENT_DELETED"
        for event in events_a
    )
    assert not any(event["document_id"] == doc_b for event in events_a)

    # A workspace switch audit event is scoped to the selected company.
    with app.app_context():
        rows = db.session.execute(
            db.select(AuditLog).where(AuditLog.company_id == company_a_id)
        ).scalars().all()
        assert rows


def test_workspace_admin_can_add_account_already_in_another_workspace(app):
    admin = app.test_client()
    member = app.test_client()
    register_and_login(admin, "workspace-admin@example.com", "Workspace A")
    register_and_login(member, "existing-member@example.com", "Workspace B")

    response = admin.post(
        "/admin/members",
        json={"email": "existing-member@example.com"},
        headers=csrf_headers(admin),
    )
    assert response.status_code == 201
    assert response.get_json()["workspace_role"] == "member"

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="existing-member@example.com")
        ).scalar_one()
        memberships = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=user.id)
        ).scalars().all()
        assert len(memberships) == 2

    # The account can now choose either workspace without changing the other.
    assert login(member, "existing-member@example.com").status_code == 200
    companies = member.get("/companies").get_json()["companies"]
    assert len(companies) == 2



def test_existing_company_signup_requires_admin_approval_and_creates_no_duplicate(app, monkeypatch):
    import re
    import backend.app as app_module

    sent = []
    app.config["MAIL_SUPPRESS_SEND"] = False
    monkeypatch.setattr(app_module, "send_email", lambda to, subject, body: sent.append((to, subject, body)))
    admin = app.test_client()
    register_and_login(admin, "company-admin@example.com", "Acme Research")

    applicant = app.test_client()
    response = register(applicant, "new-admin@example.com", "  acme   research ", requested_role="admin")
    assert response.status_code == 202
    assert response.get_json()["status"] == "pending"

    with app.app_context():
        assert db.session.execute(db.select(db.func.count(Company.id))).scalar_one() == 1
        assert db.session.execute(db.select(User).filter_by(email="new-admin@example.com")).scalar_one_or_none() is None

    requests_response = admin.get("/admin/join-requests")
    assert requests_response.status_code == 200
    request_id = requests_response.get_json()["requests"][0]["id"]
    decision = admin.post(
        f"/admin/join-requests/{request_id}/decision",
        json={"decision": "approve"},
        headers=csrf_headers(admin),
    )
    assert decision.status_code == 200
    assert sent
    token_match = re.search(r"\?token=([^\s]+)", sent[-1][2])
    assert token_match
    token = token_match.group(1)

    validate = applicant.get(f"/invites/validate?token={token}")
    assert validate.status_code == 200
    accept = applicant.post(
        "/invites/accept",
        json={"token": token, "password": PASSWORD},
        headers=csrf_headers(applicant),
    )
    assert accept.status_code == 200
    me = applicant.get("/me")
    assert me.status_code == 200
    assert me.get_json()["companies"][0]["role"] == "admin"
    with app.app_context():
        assert db.session.execute(db.select(db.func.count(Company.id))).scalar_one() == 1


def test_admin_can_invite_viewer_and_remove_workspace_membership(app, monkeypatch):
    import re
    import backend.app as app_module

    sent = []
    app.config["MAIL_SUPPRESS_SEND"] = False
    monkeypatch.setattr(app_module, "send_email", lambda to, subject, body: sent.append((to, subject, body)))
    admin = app.test_client()
    register_and_login(admin, "invite-admin@example.com", "Invite Workspace")
    response = admin.post(
        "/admin/members",
        json={"email": "invited-viewer@example.com", "role": "viewer"},
        headers=csrf_headers(admin),
    )
    assert response.status_code == 201
    token = re.search(r"\?token=([^\s]+)", sent[-1][2]).group(1)
    viewer = app.test_client()
    accepted = viewer.post(
        "/invites/accept",
        json={"token": token, "password": PASSWORD},
        headers=csrf_headers(viewer),
    )
    assert accepted.status_code == 200
    assert viewer.post(
        "/documents",
        json={"title": "Should be blocked", "category": "Test", "description": ""},
        headers=csrf_headers(viewer),
    ).status_code == 403
    with app.app_context():
        viewer_user_id = db.session.execute(db.select(User.id).filter_by(email="invited-viewer@example.com")).scalar_one()
        assert db.session.execute(db.select(CompanyMembership).filter_by(user_id=viewer_user_id)).scalar_one().role == "viewer"
    removed = admin.delete(f"/admin/members/{viewer_user_id}", json={}, headers=csrf_headers(admin))
    assert removed.status_code == 200
    with app.app_context():
        assert db.session.execute(db.select(CompanyMembership).filter_by(user_id=viewer_user_id)).scalar_one_or_none() is None


def test_google_login_reports_missing_configuration(app):
    app.config["GOOGLE_CLIENT_ID"] = ""
    app.config["GOOGLE_CLIENT_SECRET"] = ""
    response = app.test_client().get("/auth/google")
    assert response.status_code == 302
    assert "oauth_error=not_configured" in response.headers["Location"]


def test_invitation_tokens_expire_and_are_single_use(app, monkeypatch):
    import re
    import backend.app as app_module

    sent = []
    app.config["MAIL_SUPPRESS_SEND"] = False
    monkeypatch.setattr(app_module, "send_email", lambda to, subject, body: sent.append((to, subject, body)))
    admin = app.test_client()
    register_and_login(admin, "expiry-admin@example.com", "Expiry Workspace")
    response = admin.post("/admin/members", json={"email": "once@example.com"}, headers=csrf_headers(admin))
    assert response.status_code == 201
    token = re.search(r"\?token=([^\s]+)", sent[-1][2]).group(1)
    client = app.test_client()
    assert client.get(f"/invites/validate?token={token}").status_code == 200
    assert client.post("/invites/accept", json={"token": token, "password": PASSWORD}, headers=csrf_headers(client)).status_code == 200
    assert client.get(f"/invites/validate?token={token}").status_code == 410


def test_direct_login_authenticates_without_otp(client):
    assert register(client, "otp-user@example.com").status_code == 201
    response = client.post("/login", json={"email": "otp-user@example.com", "password": PASSWORD}, headers=csrf_headers(client))
    assert response.status_code == 200
    payload = response.get_json()
    assert payload.get("email") == "otp-user@example.com"
    assert client.get("/me").status_code == 200


def test_forgot_password_response_does_not_reveal_account_existence(client):
    existing = register(client, "reset-user@example.com")
    assert existing.status_code == 201
    a = client.post("/forgot-password", json={"email": "reset-user@example.com"}, headers=csrf_headers(client))
    b = client.post("/forgot-password", json={"email": "missing@example.com"}, headers=csrf_headers(client))
    assert a.status_code == b.status_code == 200
    assert a.get_json()["message"] == b.get_json()["message"]



def test_password_reset_changes_password(client):
    assert register(client, "reset-flow@example.com").status_code == 201
    requested = client.post("/forgot-password", json={"email": "reset-flow@example.com"}, headers=csrf_headers(client))
    payload = requested.get_json()
    assert requested.status_code == 200 and payload.get("test_otp")
    reset = client.post("/reset-password", json={"challenge_id": payload["challenge_id"], "otp": payload["test_otp"], "new_password": "Another-Correct-Horse-99"}, headers=csrf_headers(client))
    assert reset.status_code == 200
    old_login = client.post("/login", json={"email": "reset-flow@example.com", "password": PASSWORD}, headers=csrf_headers(client))
    assert old_login.status_code == 401
    new_login = client.post("/login", json={"email": "reset-flow@example.com", "password": "Another-Correct-Horse-99"}, headers=csrf_headers(client))
    assert new_login.status_code == 200


def test_normalize_url_and_allowed_origin_helpers():
    from backend.app import _normalize_url, _is_allowed_origin

    assert _normalize_url("trustvault-frontend-lemon.vercel.app") == "https://trustvault-frontend-lemon.vercel.app"
    assert _normalize_url("http://localhost:5173/") == "http://localhost:5173"
    assert _normalize_url("https://trustvault-backend-hfpk.onrender.com/") == "https://trustvault-backend-hfpk.onrender.com"
    assert _normalize_url("") == ""

    allowed_fe = "https://trustvault-frontend-lemon.vercel.app"
    assert _is_allowed_origin("https://trustvault-frontend-lemon.vercel.app", allowed_fe) is True
    assert _is_allowed_origin("https://trustvault-frontend-n135yxdoq-dasari-chaitanya-sai-ganesh.vercel.app", allowed_fe) is True
    assert _is_allowed_origin("http://localhost:5173", allowed_fe) is True
    assert _is_allowed_origin("https://malicious-attacker.com", allowed_fe) is False
    assert _is_allowed_origin("https://random-app.vercel.app", allowed_fe) is False


def test_cors_options_preflight_and_origin_headers():
    prod_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-key-prod",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "FRONTEND_URL": "https://trustvault-frontend-lemon.vercel.app",
        "BACKEND_URL": "https://trustvault-backend-hfpk.onrender.com",
    })
    client = prod_app.test_client()

    # Preflight OPTIONS request
    preflight = client.open(
        "/companies",
        method="OPTIONS",
        headers={
            "Origin": "https://trustvault-frontend-lemon.vercel.app",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-CSRFToken, Content-Type",
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers.get("Access-Control-Allow-Origin") == "https://trustvault-frontend-lemon.vercel.app"
    assert preflight.headers.get("Access-Control-Allow-Credentials") == "true"
    assert "POST" in preflight.headers.get("Access-Control-Allow-Methods", "")

    # GET request with allowed origin
    res = client.get("/health", headers={"Origin": "https://trustvault-frontend-lemon.vercel.app"})
    assert res.status_code == 200
    assert res.headers.get("Access-Control-Allow-Origin") == "https://trustvault-frontend-lemon.vercel.app"
    assert res.headers.get("Access-Control-Allow-Credentials") == "true"

    # GET request with untrusted origin
    evil_res = client.get("/health", headers={"Origin": "https://malicious-attacker.com"})
    assert evil_res.status_code == 200
    assert "Access-Control-Allow-Origin" not in evil_res.headers


def test_cross_origin_csrf_validation_with_vercel_origin():
    csrf_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-test-key-cross-origin",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
        "FRONTEND_URL": "https://trustvault-frontend-lemon.vercel.app",
        "BACKEND_URL": "https://trustvault-backend-hfpk.onrender.com",
    })
    with csrf_app.app_context():
        db.create_all()
    client = csrf_app.test_client()

    # Fetch CSRF token
    token_res = client.get("/csrf-token", headers={"Origin": "https://trustvault-frontend-lemon.vercel.app"})
    assert token_res.status_code == 200
    token = token_res.get_json()["csrf_token"]

    # Post from allowed Vercel frontend with CSRF token should succeed (not fail with referrer mismatch)
    register_res = client.post(
        "/register",
        json={
            "email": "crossorigin@example.com",
            "password": PASSWORD,
            "company_name": "Cross Origin Workspace",
        },
        headers={
            "X-CSRFToken": token,
            "Origin": "https://trustvault-frontend-lemon.vercel.app",
            "Referer": "https://trustvault-frontend-lemon.vercel.app/",
        },
    )
    assert register_res.status_code == 201

    # Post with invalid CSRF token should be rejected
    bad_token_res = client.post(
        "/register",
        json={
            "email": "fail@example.com",
            "password": PASSWORD,
            "company_name": "Fail Workspace",
        },
        headers={
            "X-CSRFToken": "invalid-csrf-token",
            "Origin": "https://trustvault-frontend-lemon.vercel.app",
        },
    )
    assert bad_token_res.status_code == 400
    assert bad_token_res.get_json()["error"] == "CSRF validation failed"


def test_untrusted_origin_csrf_is_blocked():
    csrf_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-test-key-untrusted",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
        "FRONTEND_URL": "https://trustvault-frontend-lemon.vercel.app",
    })
    client = csrf_app.test_client()
    token = client.get("/csrf-token").get_json()["csrf_token"]

    res = client.post(
        "/forgot-password",
        json={"email": "victim@example.com"},
        headers={
            "X-CSRFToken": token,
            "Origin": "https://malicious-site.com",
        },
    )
    assert res.status_code == 400
    assert res.get_json()["error"] == "CSRF validation failed"


def test_oauth_unconfigured_error_redirects_are_absolute():
    oauth_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "oauth-test-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "FRONTEND_URL": "trustvault-frontend-lemon.vercel.app",  # provided without scheme
        "BACKEND_URL": "trustvault-backend-hfpk.onrender.com",
        "GOOGLE_CLIENT_ID": "",
        "GOOGLE_CLIENT_SECRET": "",
    })
    client = oauth_app.test_client()

    # /auth/google should redirect to absolute frontend URL
    res = client.get("/auth/google")
    assert res.status_code == 302
    assert res.headers["Location"] == "https://trustvault-frontend-lemon.vercel.app/?oauth_error=not_configured"

    # /auth/google/callback should redirect to absolute frontend URL
    cb_res = client.get("/auth/google/callback")
    assert cb_res.status_code == 302
    assert cb_res.headers["Location"] == "https://trustvault-frontend-lemon.vercel.app/?oauth_error=not_configured"


def test_oauth_failure_redirect_does_not_create_malformed_url(monkeypatch):
    oauth_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "oauth-test-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "FRONTEND_URL": "trustvault-frontend-n135yxdoq-dasari-chaitanya-sai-ganesh.vercel.app",
        "BACKEND_URL": "https://trustvault-backend-hfpk.onrender.com",
        "GOOGLE_CLIENT_ID": "dummy-client-id",
        "GOOGLE_CLIENT_SECRET": "dummy-client-secret",
    })
    client = oauth_app.test_client()

    # Even when authorize_access_token throws, redirect must be valid absolute URL
    cb_res = client.get("/auth/google/callback")
    assert cb_res.status_code == 302
    location = cb_res.headers["Location"]
    assert location.startswith("https://trustvault-frontend-n135yxdoq-dasari-chaitanya-sai-ganesh.vercel.app/")
    assert "oauth_error=" in location
    # Verify no malformed duplicate paths
    assert "/auth/google/trustvault" not in location


def test_cookie_attributes_in_production_https_mode():
    prod_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "cookie-test-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "FRONTEND_URL": "https://trustvault-frontend-lemon.vercel.app",
        "BACKEND_URL": "https://trustvault-backend-hfpk.onrender.com",
    })
    assert prod_app.config["SESSION_COOKIE_SAMESITE"] == "None"
    assert prod_app.config["SESSION_COOKIE_SECURE"] is True
    assert prod_app.config["REMEMBER_COOKIE_SECURE"] is True
    assert prod_app.config["WTF_CSRF_SSL_STRICT"] is False


def test_oauth_session_token_exchange_establishes_authenticated_session(client):
    from backend.models import db, User, LoginOTP
    from datetime import datetime, timedelta
    import secrets
    import hashlib

    # Create a user
    with client.application.app_context():
        user = User(email="oauth-user@example.com", role="viewer")
        db.session.add(user)
        db.session.commit()
        user_id = user.id

        raw_token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        otp = LoginOTP(
            user_id=user_id,
            challenge_hash=digest,
            otp_hash="oauth",
            purpose="oauth",
            expires_at=datetime.utcnow() + timedelta(minutes=2),
            attempts=0,
        )
        db.session.add(otp)
        db.session.commit()

    # Before exchange, /me is unauthorized
    assert client.get("/me").status_code == 401

    # Exchange token
    res = client.post("/auth/session", json={"token": raw_token})
    assert res.status_code == 200
    data = res.get_json()
    assert data["email"] == "oauth-user@example.com"
    assert data["id"] == user_id

    # After exchange, /me is now authorized and returns 200
    me_res = client.get("/me")
    assert me_res.status_code == 200
    assert me_res.get_json()["email"] == "oauth-user@example.com"

    # Token is single-use and cannot be exchanged again
    reuse_res = client.post("/auth/session", json={"token": raw_token})
    assert reuse_res.status_code == 400


def test_invalid_oauth_session_token_fails(client):
    res = client.post("/auth/session", json={"token": "completely-invalid-token"})
    assert res.status_code == 400
    assert res.get_json()["error"] == "Invalid or expired session token"


def test_oauth_state_persistence_without_session_cookie(app):
    from backend.app import DatabaseStateFlaskIntegration
    from backend.models import OAuthState
    import json

    integration = DatabaseStateFlaskIntegration("google")

    with app.test_request_context("/auth/google"):
        from flask import session
        session["oauth_frontend_url"] = "https://trustvault-frontend-lemon.vercel.app"
        test_state = "test-random-state-12345"
        test_payload = {"redirect_uri": "https://trustvault-backend-hfpk.onrender.com/auth/google/callback", "nonce": "abc"}

        # Store state
        integration.set_state_data(session, test_state, test_payload)

        # Check in DB
        row = OAuthState.query.filter_by(state=test_state).first()
        assert row is not None
        assert row.frontend_url == "https://trustvault-frontend-lemon.vercel.app"
        assert json.loads(row.data)["nonce"] == "abc"

    # In a completely separate request with an EMPTY session (simulating dropped session cookie)
    with app.test_request_context(f"/auth/google/callback?state={test_state}"):
        from flask import session
        assert dict(session) == {}

        # get_state_data recovers state from DB!
        recovered = integration.get_state_data(session, test_state)
        assert recovered is not None
        assert recovered["nonce"] == "abc"
        assert recovered["redirect_uri"] == "https://trustvault-backend-hfpk.onrender.com/auth/google/callback"

        # clear_state_data removes from DB
        integration.clear_state_data(session, test_state)
        assert OAuthState.query.filter_by(state=test_state).first() is None


def test_registration_with_full_name_and_me_profile(client):
    res = client.post(
        "/register",
        json={
            "full_name": "Alice Wonderland",
            "email": "alice_test@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "company_name": "Wonderland Corp",
        },
        headers=csrf_headers(client),
    )
    assert res.status_code == 201
    data = res.get_json()
    assert data["full_name"] == "Alice Wonderland"
    assert data["email"] == "alice_test@example.com"

    me = client.get("/me").get_json()
    assert me["full_name"] == "Alice Wonderland"
    assert me["email"] == "alice_test@example.com"
    assert len(me["companies"]) == 1
    assert me["companies"][0]["name"] == "Wonderland Corp"
    assert me["companies"][0]["is_owner"] is True


def test_company_details_and_member_lifecycle(app):
    owner_client = app.test_client()
    member_client = app.test_client()

    # Register Owner
    owner_res = owner_client.post(
        "/register",
        json={
            "full_name": "Owner Person",
            "email": "owner_lifecycle@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "company_name": "Lifecycle Inc",
        },
        headers=csrf_headers(owner_client),
    )
    assert owner_res.status_code == 201

    # Register Member (without company)
    member_res = member_client.post(
        "/register",
        json={
            "full_name": "Bob Member",
            "email": "bob_lifecycle@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
        headers=csrf_headers(member_client),
    )
    assert member_res.status_code == 201

    # Check /company/details for owner
    details_res = owner_client.get("/company/details")
    assert details_res.status_code == 200
    details = details_res.get_json()
    assert details["name"] == "Lifecycle Inc"
    assert details["is_owner"] is True
    assert details["current_user_role"] == "admin"
    assert details["member_count"] == 1

    # Search for bob
    search_res = owner_client.get("/users/search?q=bob")
    assert search_res.status_code == 200
    users = search_res.get_json()["users"]
    assert any(u["email"] == "bob_lifecycle@example.com" for u in users)

    # Add Bob as viewer
    add_res = owner_client.post(
        "/admin/members",
        json={"email": "bob_lifecycle@example.com", "role": "viewer"},
        headers=csrf_headers(owner_client),
    )
    assert add_res.status_code in (200, 201)

    # Verify members list
    members_res = owner_client.get("/admin/members")
    assert members_res.status_code == 200
    m_list = members_res.get_json()["members"]
    bob_entry = next((m for m in m_list if m["email"] == "bob_lifecycle@example.com"), None)
    assert bob_entry is not None
    assert bob_entry["workspace_role"] == "viewer"
    assert bob_entry["full_name"] == "Bob Member"

    # Update Bob's role to member
    patch_res = owner_client.patch(
        f"/admin/members/{bob_entry['user_id']}",
        json={"role": "member"},
        headers=csrf_headers(owner_client),
    )
    assert patch_res.status_code == 200

    # Bob switches to Lifecycle Inc
    bob_me = member_client.get("/me").get_json()
    comp_id = details["id"]
    switch_res = member_client.post(
        "/companies/active",
        json={"company_id": comp_id},
        headers=csrf_headers(member_client),
    )
    assert switch_res.status_code == 200

    # Bob leaves the company
    leave_res = member_client.post(
        "/company/leave",
        json={},
        headers=csrf_headers(member_client),
    )
    assert leave_res.status_code == 200

    # Bob me profile has 0 companies
    bob_me_after = member_client.get("/me").get_json()
    assert len(bob_me_after["companies"]) == 0


def test_duplicate_workspace_creation_is_rejected(client, app):
    # Register first user with "Alpha Beta Corp"
    res1 = client.post(
        "/register",
        json={
            "full_name": "First Creator",
            "email": "creator1@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "company_name": "Alpha Beta Corp",
        },
        headers=csrf_headers(client),
    )
    assert res1.status_code == 201

    # Check-name endpoint confirms "Alpha Beta Corp" is taken
    check_res = client.get("/companies/check-name?name=Alpha+Beta+Corp")
    assert check_res.status_code == 200
    assert check_res.get_json()["available"] is False
    assert check_res.get_json()["exists"] is True

    # Check-name endpoint confirms unused name is available
    check_free = client.get("/companies/check-name?name=Gamma+Delta+Corp")
    assert check_free.status_code == 200
    assert check_free.get_json()["available"] is True

    # Second user attempts to register creating duplicate workspace with same name
    client2 = app.test_client()
    res2 = client2.post(
        "/register",
        json={
            "full_name": "Second Creator",
            "email": "creator2@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "company_name": "  alpha   beta   corp  ",
        },
        headers=csrf_headers(client2),
    )
    assert res2.status_code == 409
    assert "already exists" in res2.get_json()["error"]

    # Logged in user attempts to create workspace with same name via POST /companies
    # Register creator2 without workspace first
    res_reg = client2.post(
        "/register",
        json={
            "full_name": "Second Creator",
            "email": "creator2@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
        headers=csrf_headers(client2),
    )
    assert res_reg.status_code == 201

    # Try creating workspace with same name
    create_dup = client2.post(
        "/companies",
        json={"name": "Alpha Beta Corp"},
        headers=csrf_headers(client2),
    )
    assert create_dup.status_code == 409
    assert "already exists" in create_dup.get_json()["error"]





def test_demo_reset_seed_endpoint_is_removed(client):
    res_get = client.get("/demo/reset-seed")
    assert res_get.status_code == 404
    res_post = client.post("/demo/reset-seed", json={})
    assert res_post.status_code == 404


def test_demo_account_and_showcase_protections(app):
    from backend.extensions import db
    from backend.models import User, Company, CompanyMembership, Document

    with app.app_context():
        # Setup showcase entities in test database
        evaluator = User(full_name="Alex Morgan", email="evaluator@trustvault.local", role="admin")
        evaluator.set_password(PASSWORD)
        marcus = User(full_name="Dr. Marcus Vance", email="marcus.vance@trustvault.local", role="viewer")
        marcus.set_password(PASSWORD)
        normal = User(full_name="Normal User", email="normal_test@example.com", role="viewer")
        normal.set_password(PASSWORD)
        db.session.add_all([evaluator, marcus, normal])
        db.session.flush()

        workspace = Company(name="Acme Global Security Vault", owner_user_id=evaluator.id)
        db.session.add(workspace)
        db.session.flush()

        m_evaluator = CompanyMembership(company_id=workspace.id, user_id=evaluator.id, role="admin")
        m_marcus = CompanyMembership(company_id=workspace.id, user_id=marcus.id, role="member")
        m_normal = CompanyMembership(company_id=workspace.id, user_id=normal.id, role="member")
        db.session.add_all([m_evaluator, m_marcus, m_normal])

        doc = Document(
            company=workspace,
            owner=evaluator,
            title="Enterprise SOC-2 Type II Security Assessment",
            category="Compliance",
            description="Showcase security assessment",
        )
        db.session.add(doc)
        db.session.commit()

        evaluator_id = evaluator.id
        marcus_id = marcus.id
        normal_id = normal.id
        doc_id = doc.id
        workspace_id = workspace.id

    admin_client = app.test_client()
    login(admin_client, "evaluator@trustvault.local")
    admin_client.post("/companies/active", json={"company_id": workspace_id}, headers=csrf_headers(admin_client))

    # 1. Attempt to remove protected demo persona (Dr. Marcus) -> 403
    del_demo = admin_client.delete(f"/admin/members/{marcus_id}", headers=csrf_headers(admin_client))
    assert del_demo.status_code == 403
    assert "protected" in del_demo.get_json()["error"].lower()

    # 2. Attempt to demote demo workspace owner Alex Morgan -> 403
    demote_res = admin_client.patch(f"/admin/members/{evaluator_id}", json={"role": "viewer"}, headers=csrf_headers(admin_client))
    assert demote_res.status_code == 403

    # 3. Attempt to delete showcase document -> 403
    del_doc = admin_client.delete(f"/documents/{doc_id}", headers=csrf_headers(admin_client))
    assert del_doc.status_code == 403
    assert "protected" in del_doc.get_json()["error"].lower()

    # 4. Attempt to permanently delete showcase company -> 403
    del_comp = admin_client.delete(
        "/company",
        json={"confirm_name": "Acme Global Security Vault"},
        headers=csrf_headers(admin_client),
    )
    assert del_comp.status_code == 403
    assert "protected" in del_comp.get_json()["error"].lower()

    # 5. Protected demo persona cannot leave showcase workspace -> 403
    marcus_client = app.test_client()
    login(marcus_client, "marcus.vance@trustvault.local")
    marcus_client.post("/companies/active", json={"company_id": workspace_id}, headers=csrf_headers(marcus_client))
    leave_res = marcus_client.post("/company/leave", headers=csrf_headers(marcus_client))
    assert leave_res.status_code == 403
    assert "protected" in leave_res.get_json()["error"].lower()

    # 6. Non-demo member CAN be updated and removed normally -> 200
    update_normal = admin_client.patch(f"/admin/members/{normal_id}", json={"role": "viewer"}, headers=csrf_headers(admin_client))
    assert update_normal.status_code == 200

    del_normal = admin_client.delete(f"/admin/members/{normal_id}", headers=csrf_headers(admin_client))
    assert del_normal.status_code == 200
