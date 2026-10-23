
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from backend.extensions import db, login_manager


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")

    memberships = db.relationship(
        "CompanyMembership",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Company(db.Model):
    __tablename__ = "company"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    memberships = db.relationship(
        "CompanyMembership",
        back_populates="company",
        cascade="all, delete-orphan",
    )



class CompanyMembership(db.Model):
    __tablename__ = "company_membership"

    __table_args__ = (
        db.UniqueConstraint(
            "company_id",
            "user_id",
            name="uq_company_membership_user",
        ),
        db.CheckConstraint(
            "role IN ('admin', 'member')",
            name="ck_company_membership_role",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)

    company_id = db.Column(
        db.Integer,
        db.ForeignKey("company.id"),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="member",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    company = db.relationship(
        "Company",
        back_populates="memberships",
    )

    user = db.relationship(
        "User",
        back_populates="memberships",
    )



class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("company.id"),
        nullable=True,
        index=True,
    )
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False, default="General")
    description = db.Column(db.Text, nullable=False, default="")
    company = db.relationship("Company", backref="documents")
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    owner = db.relationship("User", backref="owned_documents")


class DocumentPermission(db.Model):
    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_permission_user",
        ),
        db.CheckConstraint(
            "permission_level IN ('READ', 'EDIT')",
            name="ck_document_permission_level",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    permission_level = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    document = db.relationship(
        "Document",
        backref=db.backref("permissions", cascade="all, delete-orphan"),
    )
    user = db.relationship("User", backref="document_permissions")


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None



class AuditLog(db.Model):
    """Stores security events in a tamper-evident hash chain."""

    __tablename__ = "audit_log"

    __table_args__ = (
        db.CheckConstraint(
            "outcome IN ('SUCCESS', 'DENIED')",
            name="ck_audit_log_outcome",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)

    # Snapshots preserve historical references even if users/documents
    # are eventually removed.
    actor_user_id = db.Column(db.Integer, nullable=True, index=True)
    actor_email = db.Column(db.String(255), nullable=True)

    action = db.Column(db.String(80), nullable=False, index=True)
    outcome = db.Column(db.String(20), nullable=False, index=True)

    document_id = db.Column(db.Integer, nullable=True, index=True)
    target_user_id = db.Column(db.Integer, nullable=True)

    # Store safe metadata, never document contents, passwords, or tokens.
    details = db.Column(db.JSON, nullable=False, default=dict)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    previous_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False, unique=True)
