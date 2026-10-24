
import pytest

from backend.app import create_app
from backend.extensions import db
from backend.audit import log_audit_event, verify_audit_chain
from backend.models import AuditLog, Company, CompanyMembership, User, WorkspaceInvitation, WorkspaceJoinRequest

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


def register(client, email, company_name=None):
    if company_name is None:
        company_name = f"{email.split('@')[0]}'s Workspace"

    return client.post(
        "/register",
        json={
            "email": email,
            "password": PASSWORD,
            "company_name": company_name,
        },
        headers=csrf_headers(client),
    )


def login(client, email):
    return client.post(
        "/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )


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
    response = register(applicant, "new-admin@example.com", "  acme   research ")
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
