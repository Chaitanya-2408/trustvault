
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFError, generate_csrf
from sqlalchemy.exc import IntegrityError

from backend.audit import log_audit_event
from backend.extensions import csrf, db, login_manager
from backend.models import Document, DocumentPermission, User

load_dotenv()


def create_app(test_config=None):
    app = Flask(__name__)

    cookie_secure = (
        os.environ.get("COOKIE_SECURE", "false").lower() == "true"
    )

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            "sqlite:///trustvault.db",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=cookie_secure,
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY must be set in the environment or test configuration."
        )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"error": "Authentication required"}), 401

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return jsonify({
            "error": "CSRF validation failed",
            "description": error.description,
        }), 400

    @app.cli.command("init-db")
    def init_db():
        """Create database tables for local development."""
        db.create_all()
        print("TrustVault database tables created.")

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "TrustVault",
        }), 200

    @app.get("/csrf-token")
    def csrf_token():
        return jsonify({"csrf_token": generate_csrf()}), 200

    # ---------------- Authentication ----------------

    @app.post("/register")
    def register():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400

        email = data.get("email", "")
        password = data.get("password", "")

        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({
                "error": "Email and password must be strings"
            }), 400

        email = email.strip().lower()

        if (
            not email
            or len(email) > 255
            or "@" not in email
            or email.startswith("@")
            or email.endswith("@")
        ):
            return jsonify({"error": "A valid email is required"}), 400

        if len(password) < 12:
            return jsonify({
                "error": "Password must be at least 12 characters"
            }), 400

        user = User(email=email, role="viewer")
        user.set_password(password)
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({
                "error": "An account with that email already exists"
            }), 409

        return jsonify({"message": "Account created"}), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "Invalid email or password"
            }), 400

        email = data.get("email", "")
        password = data.get("password", "")

        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({
                "error": "Invalid email or password"
            }), 400

        user = db.session.execute(
            db.select(User).filter_by(email=email.strip().lower())
        ).scalar_one_or_none()

        if user is None or not user.check_password(password):
            return jsonify({
                "error": "Invalid email or password"
            }), 401

        login_user(user)

        return jsonify({
            "message": "Logged in",
            "role": user.role,
        }), 200

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return jsonify({"message": "Logged out"}), 200

    @app.get("/me")
    @login_required
    def me():
        return jsonify({
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role,
        }), 200

    # ---------------- Authorization helpers ----------------

    def get_document_access(document):
        """Check the current user's access against the database."""
        if document.owner_id == current_user.id:
            return "OWNER"

        grant = db.session.execute(
            db.select(DocumentPermission).filter_by(
                document_id=document.id,
                user_id=current_user.id,
            )
        ).scalar_one_or_none()

        return grant.permission_level if grant else None

    def document_or_404(document_id):
        return db.session.get(Document, document_id)

    def serialize_document(document, access):
        return {
            "id": document.id,
            "title": document.title,
            "category": document.category,
            "description": document.description,
            "owner_id": document.owner_id,
            "access": access,
            "created_at": document.created_at.isoformat(),
            "updated_at": document.updated_at.isoformat(),
        }

    def valid_text(value, maximum, allow_empty=False):
        if not isinstance(value, str):
            return False
        if len(value) > maximum:
            return False
        if not allow_empty and not value.strip():
            return False
        return True

    # ---------------- Document metadata ----------------

    @app.post("/documents")
    @login_required
    def create_document():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400

        title = data.get("title")
        category = data.get("category", "General")
        description = data.get("description", "")

        if not valid_text(title, 255):
            return jsonify({"error": "A valid title is required"}), 400

        if not valid_text(category, 100):
            return jsonify({"error": "A valid category is required"}), 400

        if not valid_text(description, 5000, allow_empty=True):
            return jsonify({"error": "Invalid description"}), 400

        document = Document(
            title=title.strip(),
            category=category.strip(),
            description=description,
            owner_id=current_user.id,
        )

        db.session.add(document)
        db.session.flush()

        log_audit_event(
            action="DOCUMENT_CREATED",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document.id,
            details={"category": document.category},
            commit=False,
        )

        db.session.commit()

        return jsonify(serialize_document(document, "OWNER")), 201

    @app.get("/documents")
    @login_required
    def list_documents():
        documents = db.session.execute(
            db.select(Document)
            .outerjoin(
                DocumentPermission,
                DocumentPermission.document_id == Document.id,
            )
            .where(
                db.or_(
                    Document.owner_id == current_user.id,
                    DocumentPermission.user_id == current_user.id,
                )
            )
            .distinct()
            .order_by(Document.created_at.desc())
        ).scalars().all()

        results = [
            serialize_document(document, get_document_access(document))
            for document in documents
        ]

        return jsonify({"documents": results}), 200

    @app.get("/documents/<int:document_id>")
    @login_required
    def get_document(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        access = get_document_access(document)

        if access not in ("OWNER", "READ", "EDIT"):
            log_audit_event(
                action="DOCUMENT_READ",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "missing_permission"},
            )

            return jsonify({"error": "Document access denied"}), 403

        return jsonify(serialize_document(document, access)), 200

    @app.patch("/documents/<int:document_id>")
    @login_required
    def update_document(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        access = get_document_access(document)

        if access not in ("OWNER", "EDIT"):
            log_audit_event(
                action="DOCUMENT_UPDATE",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "edit_permission_required"},
            )

            return jsonify({"error": "Edit permission required"}), 403

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data:
            return jsonify({"error": "A JSON object is required"}), 400

        if "title" in data:
            if not valid_text(data["title"], 255):
                return jsonify({"error": "Invalid title"}), 400
            document.title = data["title"].strip()

        if "category" in data:
            if not valid_text(data["category"], 100):
                return jsonify({"error": "Invalid category"}), 400
            document.category = data["category"].strip()

        if "description" in data:
            if not valid_text(
                data["description"], 5000, allow_empty=True
            ):
                return jsonify({"error": "Invalid description"}), 400
            document.description = data["description"]

        log_audit_event(
            action="DOCUMENT_UPDATED",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document.id,
            details={
                "fields_changed": [
                    field
                    for field in ("title", "category", "description")
                    if field in data
                ]
            },
            commit=False,
        )

        db.session.commit()

        return jsonify(serialize_document(document, access)), 200

    # ---------------- Owner-controlled permissions ----------------

    @app.post("/documents/<int:document_id>/permissions")
    @login_required
    def grant_permission(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        if document.owner_id != current_user.id:
            log_audit_event(
                action="PERMISSION_GRANT",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "not_document_owner"},
            )

            return jsonify({
                "error": "Only the document owner can grant permissions"
            }), 403

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400

        email = data.get("email")
        level = data.get("permission_level")

        if not isinstance(email, str) or level not in ("READ", "EDIT"):
            return jsonify({
                "error": "Provide an email and READ or EDIT permission"
            }), 400

        target = db.session.execute(
            db.select(User).filter_by(email=email.strip().lower())
        ).scalar_one_or_none()

        if target is None:
            return jsonify({"error": "User not found"}), 404

        if target.id == current_user.id:
            return jsonify({
                "error": "The owner already has full document access"
            }), 400

        grant = db.session.execute(
            db.select(DocumentPermission).filter_by(
                document_id=document.id,
                user_id=target.id,
            )
        ).scalar_one_or_none()

        is_new_grant = grant is None

        if grant is None:
            grant = DocumentPermission(
                document_id=document.id,
                user_id=target.id,
                permission_level=level,
            )
            db.session.add(grant)
        else:
            grant.permission_level = level

        log_audit_event(
            action=(
                "PERMISSION_GRANTED"
                if is_new_grant
                else "PERMISSION_CHANGED"
            ),
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document.id,
            target_user_id=target.id,
            details={"permission_level": level},
            commit=False,
        )

        db.session.commit()

        return jsonify({
            "message": "Permission granted",
            "document_id": document.id,
            "user_id": target.id,
            "permission_level": level,
        }), 200

    @app.delete(
        "/documents/<int:document_id>/permissions/<int:user_id>"
    )
    @login_required
    def revoke_permission(document_id, user_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        if document.owner_id != current_user.id:
            log_audit_event(
                action="PERMISSION_REVOKE",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                target_user_id=user_id,
                details={"reason": "not_document_owner"},
            )

            return jsonify({
                "error": "Only the document owner can revoke permissions"
            }), 403

        grant = db.session.execute(
            db.select(DocumentPermission).filter_by(
                document_id=document.id,
                user_id=user_id,
            )
        ).scalar_one_or_none()

        if grant is None:
            return jsonify({"error": "Permission grant not found"}), 404

        revoked_level = grant.permission_level
        db.session.delete(grant)

        log_audit_event(
            action="PERMISSION_REVOKED",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document.id,
            target_user_id=user_id,
            details={"permission_level": revoked_level},
            commit=False,
        )

        db.session.commit()

        return jsonify({"message": "Permission revoked"}), 200

    return app
