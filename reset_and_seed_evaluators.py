import os
import sys

from backend.app import create_app
from backend.audit import log_audit_event, verify_audit_chain
from backend.extensions import db
from backend.models import (
    AuditLog,
    Company,
    CompanyMembership,
    Document,
    DocumentPermission,
    LoginOTP,
    OAuthState,
    User,
    WorkspaceInvitation,
    WorkspaceJoinRequest,
)

app = create_app()

with app.app_context():
    print("Clearing all existing user records and workspace data...")
    # Delete in child-to-parent order to respect foreign keys
    db.session.query(DocumentPermission).delete()
    db.session.query(Document).delete()
    db.session.query(CompanyMembership).delete()
    db.session.query(WorkspaceJoinRequest).delete()
    db.session.query(WorkspaceInvitation).delete()
    db.session.query(LoginOTP).delete()
    db.session.query(OAuthState).delete()
    db.session.query(AuditLog).delete()
    db.session.query(Company).delete()
    db.session.query(User).delete()
    db.session.commit()
    print("Database cleared cleanly.")

    # 1. Create Main Evaluator (Admin & Workspace Owner)
    evaluator = User(
        full_name="Alex Morgan",
        email="evaluator@trustvault.local",
        role="admin",
    )
    evaluator.set_password("Password12345!")
    db.session.add(evaluator)

    # 2. Create Collaborator Member
    collab = User(
        full_name="Dr. Marcus Vance",
        email="marcus.vance@trustvault.local",
        role="viewer",
    )
    collab.set_password("Password12345!")
    db.session.add(collab)

    # 3. Create Compliance Auditor (Viewer)
    auditor = User(
        full_name="Elena Rostova",
        email="elena.compliance@trustvault.local",
        role="viewer",
    )
    auditor.set_password("Password12345!")
    db.session.add(auditor)

    db.session.flush()

    # 4. Create Presentation Showcase Workspace
    workspace = Company(
        name="Acme Global Security Vault",
        owner_user_id=evaluator.id,
    )
    db.session.add(workspace)
    db.session.flush()

    # 5. Memberships
    m_evaluator = CompanyMembership(
        company=workspace,
        user=evaluator,
        role="admin",
    )
    m_collab = CompanyMembership(
        company=workspace,
        user=collab,
        role="member",
    )
    m_auditor = CompanyMembership(
        company=workspace,
        user=auditor,
        role="viewer",
    )
    db.session.add_all([m_evaluator, m_collab, m_auditor])
    db.session.commit()

    # 6. Create Showcase Documents
    doc1 = Document(
        company=workspace,
        owner=evaluator,
        title="Enterprise SOC-2 Type II Security Assessment",
        category="Compliance",
        description="Comprehensive architecture audit, cryptographic verification report, zero-trust workspace isolation validation, and formal penetration testing readiness.",
    )
    doc2 = Document(
        company=workspace,
        owner=evaluator,
        title="Zero-Trust Tenant Isolation Architecture Blueprint",
        category="Architecture",
        description="System specifications detailing SHA-256 chained audit logs, strict CSRF defense, role enforcement boundaries, and cross-workspace access prevention.",
    )
    doc3 = Document(
        company=workspace,
        owner=evaluator,
        title="Confidential Q4 2026 Financial Risk & Tooling Budget",
        category="Finance",
        description="Executive budget allocation, cybersecurity infrastructure roadmap, cyber insurance underwriting disclosures, and private financial forecasts.",
    )
    db.session.add_all([doc1, doc2, doc3])
    db.session.commit()

    # 7. Document Permissions
    # Doc 1: Marcus has EDIT, Elena has READ
    perm1 = DocumentPermission(document_id=doc1.id, user_id=collab.id, permission_level="EDIT")
    perm2 = DocumentPermission(document_id=doc1.id, user_id=auditor.id, permission_level="READ")
    # Doc 2: Marcus has READ
    perm3 = DocumentPermission(document_id=doc2.id, user_id=collab.id, permission_level="READ")
    # Doc 3: Private to Evaluator (Demonstrates strict unauthorized access prevention)
    db.session.add_all([perm1, perm2, perm3])
    db.session.commit()

    # 8. Cryptographic Hash-Chained Audit Trail
    log_audit_event(
        action="ACCOUNT_REGISTERED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        company_id=workspace.id,
        details={"full_name": evaluator.full_name},
    )
    log_audit_event(
        action="WORKSPACE_CREATED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        company_id=workspace.id,
        details={"workspace_name": workspace.name},
    )
    log_audit_event(
        action="WORKSPACE_MEMBER_ADDED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        target_user_id=collab.id,
        company_id=workspace.id,
        details={"target_email": collab.email, "role": "member"},
    )
    log_audit_event(
        action="WORKSPACE_MEMBER_ADDED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        target_user_id=auditor.id,
        company_id=workspace.id,
        details={"target_email": auditor.email, "role": "viewer"},
    )
    log_audit_event(
        action="DOCUMENT_CREATED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc1.id,
        company_id=workspace.id,
        details={"title": doc1.title, "category": doc1.category},
    )
    log_audit_event(
        action="PERMISSION_GRANTED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc1.id,
        target_user_id=collab.id,
        company_id=workspace.id,
        details={"target_email": collab.email, "level": "EDIT"},
    )
    log_audit_event(
        action="PERMISSION_GRANTED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc1.id,
        target_user_id=auditor.id,
        company_id=workspace.id,
        details={"target_email": auditor.email, "level": "READ"},
    )
    log_audit_event(
        action="DOCUMENT_CREATED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc2.id,
        company_id=workspace.id,
        details={"title": doc2.title, "category": doc2.category},
    )
    log_audit_event(
        action="PERMISSION_GRANTED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc2.id,
        target_user_id=collab.id,
        company_id=workspace.id,
        details={"target_email": collab.email, "level": "READ"},
    )
    log_audit_event(
        action="DOCUMENT_CREATED",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        document_id=doc3.id,
        company_id=workspace.id,
        details={"title": doc3.title, "category": doc3.category},
    )
    log_audit_event(
        action="DOCUMENT_READ",
        outcome="DENIED",
        actor_user_id=auditor.id,
        actor_email=auditor.email,
        document_id=doc3.id,
        company_id=workspace.id,
        details={"reason": "unauthorized_role_isolation"},
    )
    log_audit_event(
        action="LOGIN_PASSWORD_CHECK",
        outcome="SUCCESS",
        actor_user_id=evaluator.id,
        actor_email=evaluator.email,
        company_id=workspace.id,
        details={"method": "direct_database_auth"},
    )

    valid_chain = verify_audit_chain()
    print(f"Audit chain verification: {'VALID' if valid_chain else 'INVALID'}")
    print("Seed completed successfully!")
