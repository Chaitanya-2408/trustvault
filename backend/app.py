import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from urllib.parse import urlencode
from pathlib import Path

from flask import send_file, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, request, session
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFError, generate_csrf
from sqlalchemy.exc import IntegrityError
from authlib.integrations.flask_client import OAuth

from backend.audit import log_audit_event
from backend.email_service import send_email
from backend.extensions import csrf, db, login_manager, migrate
from backend.models import (
    AuditLog,
    Company,
    CompanyMembership,
    Document,
    DocumentPermission,
    User,
    WorkspaceInvitation,
    WorkspaceJoinRequest,
    LoginOTP,
)

load_dotenv()


def create_app(test_config=None):
    app = Flask(__name__)

    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
    app.config["UPLOAD_FOLDER"] = os.path.join(
        app.instance_path,
        "private_uploads",
    )
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Cross-site session cookies must be Secure when the frontend is HTTPS.
    # COOKIE_SECURE can explicitly override this default in the environment.
    frontend_url_env = os.environ.get("FRONTEND_URL", "http://localhost:5173")
    default_cookie_secure = "true" if frontend_url_env.startswith("https://") else "false"
    cookie_secure = os.environ.get("COOKIE_SECURE", default_cookie_secure).lower() == "true"

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            "sqlite:///trustvault.db",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.environ.get(
            "SESSION_COOKIE_SAMESITE",
            "None" if os.environ.get("FRONTEND_URL", "").startswith("https://") else "Lax",
        ),
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=cookie_secure,


        MAIL_SERVER=os.environ.get("MAIL_SERVER", ""),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USE_TLS=os.environ.get(
            "MAIL_USE_TLS", "true"
        ).lower() == "true",
        MAIL_USE_SSL=os.environ.get(
            "MAIL_USE_SSL", "false"
        ).lower() == "true",
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME", ""),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD", ""),
        MAIL_DEFAULT_SENDER=os.environ.get(
            "MAIL_DEFAULT_SENDER", ""
        ),
        MAIL_SUPPRESS_SEND=os.environ.get(
            "MAIL_SUPPRESS_SEND", "false"
        ).lower() == "true",
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", ""),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        FRONTEND_URL=os.environ.get("FRONTEND_URL", "http://localhost:5173"),
        BACKEND_URL=os.environ.get("BACKEND_URL", "http://localhost:5000"),
        INVITATION_TTL_HOURS=int(os.environ.get("INVITATION_TTL_HOURS", "48")),
        JOIN_REQUEST_TTL_HOURS=int(os.environ.get("JOIN_REQUEST_TTL_HOURS", "72")),

    )

    if test_config:
        app.config.update(test_config)
        if app.config.get("TESTING") and "MAIL_SUPPRESS_SEND" not in test_config:
            app.config["MAIL_SUPPRESS_SEND"] = True

    # Cross-origin browser requests from the deployed frontend.
    # Keep the allowlist limited to the configured frontend origin.
    frontend_origin = app.config.get("FRONTEND_URL", "").rstrip("/")
    if frontend_origin:
        app.config["WTF_CSRF_TRUSTED_ORIGINS"] = list(
            dict.fromkeys(
                list(app.config.get("WTF_CSRF_TRUSTED_ORIGINS", []))
                + [frontend_origin]
            )
        )

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        allowed_origin = app.config.get("FRONTEND_URL", "").rstrip("/")

        if origin and allowed_origin and origin.rstrip("/") == allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            )
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, X-CSRFToken, X-CSRF-Token"
            )
            response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
            response.headers["Vary"] = "Origin"

        return response

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY must be set in the environment or test configuration."
        )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    oauth = OAuth(app)
    if app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"):
        oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"error": "Authentication required"}), 401

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return jsonify({
            "error": "CSRF validation failed",
            "description": error.description,
        }), 400

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(error):
        return jsonify({"error": "Request exceeds the 10 MB limit"}), 413

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


    def _normalized_company_name(value):
        return " ".join((value or "").split()).casefold()

    def _find_company_by_name(name):
        normalized = _normalized_company_name(name)
        if not normalized:
            return None
        # The unique normalized_name index is the final concurrency-safe guard.
        # Older duplicate records are retained but their normalized_name values are
        # disambiguated by the migration; new requests resolve to the canonical row.
        return db.session.execute(
            db.select(Company).filter_by(normalized_name=normalized).order_by(Company.id.asc())
        ).scalars().first()

    def _token_digest(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _new_token():
        return secrets.token_urlsafe(32)

    def _frontend_link(path, token=None):
        base = app.config.get("FRONTEND_URL", "http://localhost:5173").rstrip("/")
        query = urlencode({"token": token}) if token else ""
        return f"{base}/{path.lstrip('/')}" + (f"?{query}" if query else "")

    
    def _send_email_safely(to_address, subject, body):
        if app.config.get("MAIL_SUPPRESS_SEND"):
            app.logger.error(
                "Email sending skipped: MAIL_SUPPRESS_SEND is enabled."
            )
            return False

        try:
            send_email(to_address, subject, body)
            app.logger.info("Email sent successfully to %s", to_address)
            return True
        except Exception:
            app.logger.exception(
                "TrustVault email delivery failed. Check the traceback above."
            )
            return False


    def _notify_company_admins(company, subject, body):
        rows = db.session.execute(
            db.select(User.email)
            .join(CompanyMembership, CompanyMembership.user_id == User.id)
            .where(CompanyMembership.company_id == company.id, CompanyMembership.role == "admin")
        ).scalars().all()
        delivered = True
        for admin_email in set(rows):
            delivered = _send_email_safely(admin_email, subject, body) and delivered
        return delivered

    def _create_join_request(company, email, requested_role="member"):
        request_row = db.session.execute(
            db.select(WorkspaceJoinRequest).where(
                WorkspaceJoinRequest.company_id == company.id,
                db.func.lower(WorkspaceJoinRequest.requester_email) == email,
                WorkspaceJoinRequest.status == "pending",
                WorkspaceJoinRequest.expires_at > datetime.utcnow(),
            )
        ).scalar_one_or_none()
        if request_row is None:
            request_row = WorkspaceJoinRequest(
                company_id=company.id,
                requester_email=email,
                requested_role=requested_role,
                expires_at=datetime.utcnow() + timedelta(hours=app.config["JOIN_REQUEST_TTL_HOURS"]),
            )
            db.session.add(request_row)
            db.session.flush()
            log_audit_event(
                action="WORKSPACE_ADMIN_REQUESTED",
                outcome="SUCCESS",
                actor_user_id=None,
                actor_email=email,
                company_id=company.id,
                details={"request_id": request_row.id, "requested_role": requested_role},
                commit=False,
            )
            db.session.commit()
        else:
            request_row.requested_role = requested_role
            db.session.commit()
        # Retrying the same pending request also retries the notification, which is
        # useful if SMTP was not configured when the applicant first submitted it.
        link = _frontend_link("/")
        body = (
            f"{email} requested to join {company.name} as {request_row.requested_role}.\n\n"
            f"Sign in to TrustVault as a workspace administrator and review pending workspace access requests.\n\n"
            f"Request ID: {request_row.id}\nReview: {link}\n\n"
            "If you did not expect this request, you can reject it. Company names alone do not grant access."
        )
        sent = _notify_company_admins(company, "TrustVault workspace access requested", body)
        return request_row, sent

    @app.post("/register")
    def register():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400
        email = data.get("email", "")
        password = data.get("password", "")
        company_name = data.get("company_name", "")
        requested_role = data.get("requested_role", "member")
        if not all(isinstance(v, str) for v in (email, password, company_name, requested_role)):
            return jsonify({"error": "Email, password, and company name must be strings"}), 400
        email = email.strip().lower()
        company_name = " ".join(company_name.split())
        if not email or len(email) > 255 or "@" not in email or email.startswith("@") or email.endswith("@"):
            return jsonify({"error": "A valid email is required"}), 400
        if len(password) < 12:
            return jsonify({"error": "Password must be at least 12 characters"}), 400
        if not company_name or len(company_name) > 200:
            return jsonify({"error": "Company name must be between 1 and 200 characters"}), 400
        if requested_role not in ("admin", "member", "viewer"):
            return jsonify({"error": "Role must be admin, member, or viewer"}), 400
        existing_user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if existing_user is not None:
            return jsonify({"error": "An account with that email already exists. Sign in with that account (or reset its password), then use Workspace Setup to create a new company or request access to an existing one. Your existing account and other workspace memberships are preserved."}), 409
        company = _find_company_by_name(company_name)
        if company is not None:
            try:
                join_request = db.session.execute(
                    db.select(WorkspaceJoinRequest).where(
                        WorkspaceJoinRequest.company_id == company.id,
                        db.func.lower(WorkspaceJoinRequest.requester_email) == email,
                        WorkspaceJoinRequest.status == "pending",
                        WorkspaceJoinRequest.expires_at > datetime.utcnow(),
                    )
                ).scalar_one_or_none()
                if join_request is None:
                    join_request = WorkspaceJoinRequest(
                        company_id=company.id,
                        requester_email=email,
                        requested_role=requested_role,
                        expires_at=datetime.utcnow() + timedelta(hours=app.config["JOIN_REQUEST_TTL_HOURS"]),
                    )
                    db.session.add(join_request)
                    db.session.flush()
                    log_audit_event(action="WORKSPACE_JOIN_REQUESTED", outcome="SUCCESS",
                        actor_user_id=None, actor_email=email, company_id=company.id,
                        details={"request_id": join_request.id, "requested_role": requested_role}, commit=False)
                    db.session.commit()
                else:
                    join_request.requested_role = requested_role
                    db.session.commit()
                body = (f"{email} requested to join {company.name} as {requested_role}. "
                        "Sign in to TrustVault and review pending join requests.")
                email_sent = _notify_company_admins(company, "TrustVault workspace access requested", body)
            except Exception:
                db.session.rollback()
                app.logger.exception("Could not create workspace administrator request")
                return jsonify({"error": "Could not submit the administrator request"}), 500
            return jsonify({
                "message": f"This company already exists. Its administrators must approve your request for {requested_role} access before you can join.",
                "request_id": join_request.id,
                "status": "pending",
                "notification_sent": bool(email_sent),
            }), 202
        user = User(email=email, role="viewer")
        user.set_password(password)
        company = Company(name=company_name)
        db.session.add_all([user, company])
        db.session.flush()
        company.owner_user_id = user.id
        membership = CompanyMembership(company=company, user=user, role="admin")
        db.session.add(membership)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "An account or workspace with that information already exists; please try again."}), 409
        return jsonify({"message": "Account created", "workspace_role": "admin"}), 201

    def _otp_digest(challenge_token, code):
        secret = str(app.config["SECRET_KEY"]).encode("utf-8")
        return hmac.new(secret, f"{challenge_token}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()

    def _issue_otp(user, purpose):
        now = datetime.utcnow()
        # Invalidate any older unconsumed challenge of the same purpose.
        LoginOTP.query.filter_by(user_id=user.id, purpose=purpose, consumed_at=None).update({"consumed_at": now})
        challenge_token = secrets.token_urlsafe(32)
        code = f"{secrets.randbelow(1_000_000):06d}"
        row = LoginOTP(
            user_id=user.id,
            challenge_hash=hashlib.sha256(challenge_token.encode("utf-8")).hexdigest(),
            otp_hash=_otp_digest(challenge_token, code),
            purpose=purpose,
            expires_at=now + timedelta(minutes=5),
            attempts=0,
        )
        db.session.add(row)
        db.session.commit()
        label = "sign-in" if purpose == "login" else "password reset"
        send_email(user.email, f"TrustVault {label} verification code", f"Your TrustVault {label} code is {code}. It expires in 5 minutes. If you did not request this, you can ignore this email.")
        result = {"message": "Verification code sent to your email.", "challenge_id": challenge_token, "expires_in": 300}
        # Test-only convenience; never return a code in a real environment.
        if app.testing:
            result["test_otp"] = code
        return result

    def _find_challenge(challenge_id, purpose):
        if not isinstance(challenge_id, str) or not challenge_id or len(challenge_id) > 200:
            return None
        digest = hashlib.sha256(challenge_id.encode("utf-8")).hexdigest()
        return LoginOTP.query.filter_by(challenge_hash=digest, purpose=purpose).first()

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid email or password"}), 400
        email, password = data.get("email", ""), data.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "Invalid email or password"}), 400
        user = db.session.execute(db.select(User).filter_by(email=email.strip().lower())).scalar_one_or_none()
        if user is None or not user.check_password(password):
            log_audit_event(action="LOGIN_PASSWORD_CHECK", outcome="DENIED", actor_email=email.strip().lower()[:255], details={"reason": "invalid_credentials"})
            return jsonify({"error": "Invalid email or password"}), 401
        try:
            payload = _issue_otp(user, "login")
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not issue login OTP")
            return jsonify({"error": "Could not send a verification code. Please try again later."}), 503
        return jsonify(payload), 200

    @app.post("/login/verify-otp")
    def verify_login_otp():
        data = request.get_json(silent=True) or {}
        challenge_id, code = data.get("challenge_id"), data.get("otp")
        row = _find_challenge(challenge_id, "login")
        now = datetime.utcnow()
        if row is None or row.consumed_at is not None or row.expires_at <= now or row.attempts >= 5:
            return jsonify({"error": "This code is invalid or expired. Please sign in again."}), 400
        if not isinstance(code, str) or not hmac.compare_digest(row.otp_hash, _otp_digest(challenge_id, code)):
            row.attempts += 1
            if row.attempts >= 5:
                row.consumed_at = now
            db.session.commit()
            return jsonify({"error": "Incorrect verification code."}), 400
        row.consumed_at = now
        user = db.session.get(User, row.user_id)
        if user is None:
            db.session.commit()
            return jsonify({"error": "Account not found."}), 400
        # Rotate any pre-existing authenticated session and clear workspace selection.
        logout_user()
        session.clear()
        login_user(user)
        memberships = db.session.execute(db.select(CompanyMembership).filter_by(user_id=user.id)).scalars().all()
        if len(memberships) == 1:
            session["active_company_id"] = memberships[0].company_id
        log_audit_event(action="LOGIN_OTP_VERIFIED", outcome="SUCCESS", actor_user_id=user.id, actor_email=user.email, details={"method": "email_otp"})
        return jsonify({"message": "Logged in", "role": user.role, "active_company_id": session.get("active_company_id")}), 200

    @app.post("/login/resend-otp")
    def resend_login_otp():
        data = request.get_json(silent=True) or {}
        old = _find_challenge(data.get("challenge_id"), "login")
        now = datetime.utcnow()
        if old is None or old.consumed_at is not None or old.expires_at <= now:
            return jsonify({"error": "Please sign in again to request a new code."}), 400
        if old.created_at > now - timedelta(seconds=60):
            return jsonify({"error": "Please wait 60 seconds before requesting another code."}), 429
        user = db.session.get(User, old.user_id)
        if user is None:
            return jsonify({"error": "Please sign in again."}), 400
        try:
            payload = _issue_otp(user, "login")
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not resend login OTP")
            return jsonify({"error": "Could not send a verification code. Please try again later."}), 503
        return jsonify(payload), 200

    @app.post("/forgot-password")
    def forgot_password():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "")
        if not isinstance(email, str) or not email.strip() or len(email) > 255:
            return jsonify({"error": "Enter a valid email address."}), 400
        user = db.session.execute(db.select(User).filter_by(email=email.strip().lower())).scalar_one_or_none()
        # Always return a random challenge handle so the response shape does not
        # disclose whether the email belongs to an account.
        challenge_id = secrets.token_urlsafe(32)
        if user is not None:
            try:
                issued = _issue_otp(user, "reset")
                challenge_id = issued["challenge_id"]
            except Exception:
                db.session.rollback()
                app.logger.exception("Could not issue password reset code")
        result = {"message": "If an account exists for that email, a password reset code has been sent.", "challenge_id": challenge_id, "expires_in": 300}
        if app.testing and user is not None:
            # Only test clients receive this value; production never exposes OTPs.
            row = _find_challenge(challenge_id, "reset")
            # _issue_otp returns the test code in its result, so use it when available.
            result["test_otp"] = issued.get("test_otp")
        return jsonify(result), 200

    @app.post("/reset-password")
    def reset_password():
        data = request.get_json(silent=True) or {}
        challenge_id, code, new_password = data.get("challenge_id"), data.get("otp"), data.get("new_password")
        if not isinstance(new_password, str) or len(new_password) < 12:
            return jsonify({"error": "New password must be at least 12 characters."}), 400
        row = _find_challenge(challenge_id, "reset")
        now = datetime.utcnow()
        if row is None or row.consumed_at is not None or row.expires_at <= now or row.attempts >= 5:
            return jsonify({"error": "This code is invalid or expired. Request a new password reset code."}), 400
        if not isinstance(code, str) or not hmac.compare_digest(row.otp_hash, _otp_digest(challenge_id, code)):
            row.attempts += 1
            if row.attempts >= 5:
                row.consumed_at = now
            db.session.commit()
            return jsonify({"error": "Incorrect verification code."}), 400
        user = db.session.get(User, row.user_id)
        if user is None:
            row.consumed_at = now
            db.session.commit()
            return jsonify({"error": "Account not found."}), 400
        user.set_password(new_password)
        row.consumed_at = now
        # Invalidate every other active OTP for this account, including login challenges.
        LoginOTP.query.filter(LoginOTP.user_id == user.id, LoginOTP.consumed_at.is_(None)).update({"consumed_at": now})
        db.session.commit()
        log_audit_event(action="PASSWORD_RESET", outcome="SUCCESS", actor_user_id=user.id, actor_email=user.email, details={"method": "email_otp"})
        return jsonify({"message": "Password updated. You can now sign in with your new password."}), 200
    
    @app.get("/auth/google")
    def google_login():
        if (
        not app.config.get("GOOGLE_CLIENT_ID")
        or not app.config.get("GOOGLE_CLIENT_SECRET")
        ):
            return redirect(
            app.config["FRONTEND_URL"].rstrip("/")
            + "/?oauth_error=not_configured"
            )

        google = oauth.create_client("google")
        if google is None:
            return redirect(
            app.config["FRONTEND_URL"].rstrip("/")
            + "/?oauth_error=not_configured"
            )

        callback = (
            app.config["BACKEND_URL"].rstrip("/")
            + "/auth/google/callback"
        )
        return google.authorize_redirect(callback)


    @app.get("/auth/google/callback")
    def google_callback():
        google = oauth.create_client("google")
        if google is None:
            return redirect(app.config["FRONTEND_URL"].rstrip("/") + "/?oauth_error=not_configured")
        try:
            token = google.authorize_access_token()
            info = token.get("userinfo")
            if not info:
                userinfo_response = google.userinfo()
                info = userinfo_response.json() if hasattr(userinfo_response, "json") else userinfo_response
        except Exception:
            app.logger.exception("Google OAuth callback failed")
            return redirect(app.config["FRONTEND_URL"].rstrip("/") + "/?oauth_error=sign_in_failed")
        email = (info.get("email") or "").strip().lower()
        verified = info.get("email_verified") is True or str(info.get("email_verified", "")).lower() == "true"
        if not email or not verified:
            return redirect(app.config["FRONTEND_URL"].rstrip("/") + "/?oauth_error=email_not_verified")
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if user is None:
            user = User(email=email, password_hash=None, role="viewer")
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
                if user is None:
                    return redirect(app.config["FRONTEND_URL"].rstrip("/") + "/?oauth_error=account_failed")
        login_user(user)
        session.pop("active_company_id", None)
        memberships = db.session.execute(db.select(CompanyMembership).filter_by(user_id=user.id)).scalars().all()
        if len(memberships) == 1:
            session["active_company_id"] = memberships[0].company_id
        target = app.config["FRONTEND_URL"].rstrip("/") + "/?oauth=success"
        if not memberships:
            target += "&setup_workspace=1"
        return redirect(target)

    @app.post("/companies")
    @login_required
    def create_or_request_workspace():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            return jsonify({"error": "A workspace name is required"}), 400
        name = " ".join(data["name"].split())
        if not name or len(name) > 200:
            return jsonify({"error": "Workspace name must be between 1 and 200 characters"}), 400
        requested_role = data.get("requested_role", "member")
        if requested_role not in ("admin", "member", "viewer"):
            return jsonify({"error": "Role must be admin, member, or viewer"}), 400
        company = _find_company_by_name(name)
        if company is not None:
            join_request, email_sent = _create_join_request(company, current_user.email, requested_role)
            return jsonify({"message": "Company exists. Administrator approval is required.", "status": "pending", "request_id": join_request.id, "notification_sent": bool(email_sent)}), 202
        company = Company(name=name, owner_user_id=current_user.id)
        membership = CompanyMembership(company=company, user_id=current_user.id, role="admin")
        db.session.add_all([company, membership])
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Could not create workspace. Please retry."}), 409
        session["active_company_id"] = company.id
        log_audit_event(action="WORKSPACE_CREATED", outcome="SUCCESS", actor_user_id=current_user.id, actor_email=current_user.email, company_id=company.id, details={"company_name": company.name})
        return jsonify({"message": "Workspace created", "company_id": company.id, "company_name": company.name, "workspace_role": "admin"}), 201

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        session.pop("active_company_id", None)
        return jsonify({"message": "Logged out"}), 200

    @app.get("/me")
    @login_required
    def me():
        memberships = db.session.execute(
            db.select(CompanyMembership, Company)
            .join(Company, Company.id == CompanyMembership.company_id)
            .where(CompanyMembership.user_id == current_user.id)
            .order_by(Company.name.asc())
        ).all()
        active_membership = current_company_membership()
        return jsonify({
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role,
            "active_company_id": active_membership.company_id if active_membership else None,
            "companies": [
                {
                    "id": membership.company_id,
                    "name": company.name,
                    "role": membership.role,
                    "is_owner": company.owner_user_id == current_user.id,
                }
                for membership, company in memberships
            ],
        }), 200

    # ---------------- Workspace selection ----------------

    @app.get("/companies")
    @login_required
    def list_companies():
        rows = db.session.execute(
            db.select(CompanyMembership, Company)
            .join(Company, Company.id == CompanyMembership.company_id)
            .where(CompanyMembership.user_id == current_user.id)
            .order_by(Company.name.asc())
        ).all()
        return jsonify({
            "companies": [
                {
                    "id": membership.company_id,
                    "name": company.name,
                    "role": membership.role,
                    "active": session.get("active_company_id") == membership.company_id,
                }
                for membership, company in rows
            ],
            "active_company_id": session.get("active_company_id"),
        }), 200

    @app.post("/companies/active")
    @login_required
    def select_active_company():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400
        try:
            company_id = int(data.get("company_id"))
        except (TypeError, ValueError):
            return jsonify({"error": "company_id must be an integer"}), 400

        membership = db.session.execute(
            db.select(CompanyMembership).filter_by(
                user_id=current_user.id,
                company_id=company_id,
            )
        ).scalar_one_or_none()
        if membership is None:
            log_audit_event(
                action="WORKSPACE_SWITCH",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                details={"reason": "not_a_workspace_member", "requested_company_id": company_id},
            )
            return jsonify({"error": "You are not a member of that workspace"}), 403

        session["active_company_id"] = membership.company_id
        company = db.session.get(Company, membership.company_id)
        log_audit_event(
            action="WORKSPACE_SWITCH",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            company_id=membership.company_id,
            details={"company_id": membership.company_id},
        )
        return jsonify({
            "message": "Active workspace changed",
            "active_company_id": membership.company_id,
            "company_name": company.name,
            "workspace_role": membership.role,
        }), 200

    # ---------------- Admin authorization ----------------

    def admin_required(view_function):
        """Allow only workspace administrators to access admin endpoints."""

        @wraps(view_function)
        @login_required
        def wrapped(*args, **kwargs):
            membership = current_company_membership()
            if membership is None or membership.role != "admin":
                return jsonify({
                    "error": "Administrator access required"
                }), 403

            return view_function(*args, **kwargs)

        return wrapped

    # ---------------- Authorization helpers ----------------


    def current_company_membership():
        """Resolve the active workspace from the session and verify membership.

        A single-workspace account is selected automatically for backward
        compatibility. Multi-workspace accounts must explicitly choose one.
        """
        memberships = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=current_user.id)
        ).scalars().all()

        selected_id = session.get("active_company_id")
        if selected_id is not None:
            for membership in memberships:
                if membership.company_id == selected_id:
                    return membership
            # Stale or forged workspace selection fails closed.
            session.pop("active_company_id", None)

        if len(memberships) == 1:
            session["active_company_id"] = memberships[0].company_id
            return memberships[0]

        return None


    def user_is_company_member(user_id, company_id):
        """Check workspace membership directly in the database."""
        membership_id = db.session.execute(
            db.select(CompanyMembership.id).filter_by(
                user_id=user_id,
                company_id=company_id,
            )
        ).scalar_one_or_none()

        return membership_id is not None


    def get_document_access(document):
        """Require active-workspace membership before checking document grants."""
        if document.company_id is None:
            return None

        active_membership = current_company_membership()
        if (
            active_membership is None
            or document.company_id != active_membership.company_id
        ):
            return None

        if document.owner_id == current_user.id:
            return "READ" if active_membership.role == "viewer" else "OWNER"

        grant = db.session.execute(
            db.select(DocumentPermission).filter_by(
                document_id=document.id,
                user_id=current_user.id,
            )
        ).scalar_one_or_none()
        if grant is None:
            return None
        # Workspace viewers can never elevate themselves with an EDIT document grant.
        if active_membership.role == "viewer":
            return "READ"
        return grant.permission_level


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
            "has_file": bool(document.stored_filename),
            "original_filename": document.original_filename,
            "file_size": document.file_size,
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

        membership = current_company_membership()

        if membership is None:
            return jsonify({
                "error": "A single active company workspace is required"
            }), 403
        if membership.role == "viewer":
            return jsonify({"error": "Viewer role cannot create documents"}), 403

        if not valid_text(title, 255):
            return jsonify({"error": "A valid title is required"}), 400

        if not valid_text(category, 100):
            return jsonify({"error": "A valid category is required"}), 400

        if not valid_text(description, 5000, allow_empty=True):
            return jsonify({"error": "Invalid description"}), 400

        document = Document(
            company_id=membership.company_id,
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
        membership = current_company_membership()
        if membership is None:
            return jsonify({
                "error": "A single active company workspace is required"
            }), 403

        # Apply access control in SQL before applying user-controlled filters.
        # A search query must never reveal documents the user cannot access.
        statement = (
            db.select(Document)
            .outerjoin(
                DocumentPermission,
                DocumentPermission.document_id == Document.id,
            )
            .join(User, User.id == Document.owner_id)
            .where(
                Document.company_id == membership.company_id,
                db.or_(
                    Document.owner_id == current_user.id,
                    DocumentPermission.user_id == current_user.id,
                ),
            )
        )

        title_query = request.args.get("title", "").strip()
        owner_query = request.args.get("owner", "").strip().lower()
        category_query = request.args.get("category", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        if title_query:
            statement = statement.where(
                Document.title.ilike(f"%{title_query}%")
            )
        if owner_query:
            statement = statement.where(User.email.ilike(f"%{owner_query}%"))
        if category_query:
            statement = statement.where(
                Document.category.ilike(f"%{category_query}%")
            )
        for field_name, date_value, operator in (
            ("date_from", date_from, "from"),
            ("date_to", date_to, "to"),
        ):
            if date_value:
                try:
                    from datetime import date
                    parsed_date = date.fromisoformat(date_value)
                except ValueError:
                    return jsonify({
                        "error": f"{field_name} must use YYYY-MM-DD format"
                    }), 400
                if operator == "from":
                    statement = statement.where(
                        db.func.date(Document.created_at) >= parsed_date.isoformat()
                    )
                else:
                    statement = statement.where(
                        db.func.date(Document.created_at) <= parsed_date.isoformat()
                    )

        documents = db.session.execute(
            statement.distinct().order_by(Document.created_at.desc())
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

    # ---------------- Private file upload/download ----------------

    allowed_file_extensions = {
        ".pdf", ".doc", ".docx", ".txt", ".csv",
        ".xlsx", ".png", ".jpg", ".jpeg",
    }

    @app.post("/documents/<int:document_id>/upload")
    @login_required
    def upload_document_file(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        access = get_document_access(document)
        if access not in ("OWNER", "EDIT"):
            log_audit_event(
                action="DOCUMENT_UPLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "edit_permission_required"},
            )
            return jsonify({"error": "Edit permission required"}), 403

        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            log_audit_event(
                action="DOCUMENT_UPLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "file_required"},
            )
            return jsonify({"error": "A file is required in the 'file' field"}), 400

        original_filename = secure_filename(uploaded.filename)
        extension = os.path.splitext(original_filename)[1].lower()

        if (
            not original_filename
            or len(original_filename) > 255
            or extension not in allowed_file_extensions
        ):
            log_audit_event(
                action="DOCUMENT_UPLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "invalid_file_type_or_name"},
            )
            return jsonify({
                "error": "Unsupported filename or file type",
                "allowed_extensions": sorted(allowed_file_extensions),
            }), 400

        storage_name = f"{secrets.token_hex(24)}{extension}"
        storage_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
        storage_root.mkdir(parents=True, exist_ok=True)
        storage_path = (storage_root / storage_name).resolve()

        # The storage name is generated by the server, never from user input.
        if storage_path.parent != storage_root:
            return jsonify({"error": "Invalid storage path"}), 400

        try:
            uploaded.save(storage_path)
            file_size = storage_path.stat().st_size

            if file_size == 0:
                storage_path.unlink(missing_ok=True)
                log_audit_event(
                    action="DOCUMENT_UPLOAD",
                    outcome="DENIED",
                    actor_user_id=current_user.id,
                    actor_email=current_user.email,
                    document_id=document.id,
                    details={"reason": "empty_file"},
                )
                return jsonify({"error": "Empty files are not allowed"}), 400

            if file_size > 10 * 1024 * 1024:
                storage_path.unlink(missing_ok=True)
                log_audit_event(
                    action="DOCUMENT_UPLOAD",
                    outcome="DENIED",
                    actor_user_id=current_user.id,
                    actor_email=current_user.email,
                    document_id=document.id,
                    details={"reason": "file_too_large", "file_size": file_size},
                )
                return jsonify({"error": "File exceeds the 10 MB limit"}), 413

            old_storage_name = document.stored_filename
            document.stored_filename = storage_name
            document.original_filename = original_filename
            document.content_type = uploaded.mimetype or "application/octet-stream"
            document.file_size = file_size

            log_audit_event(
                action="DOCUMENT_UPLOADED",
                outcome="SUCCESS",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={
                    "filename": original_filename,
                    "file_size": file_size,
                    "content_type": document.content_type,
                },
                commit=False,
            )
            db.session.commit()

        except Exception:
            db.session.rollback()
            storage_path.unlink(missing_ok=True)
            raise

        # Remove the previous stored file only after the database commit succeeds.
        if old_storage_name:
            old_path = (storage_root / old_storage_name).resolve()
            if old_path.parent == storage_root and old_path != storage_path:
                old_path.unlink(missing_ok=True)

        return jsonify(serialize_document(document, access)), 200

    @app.get("/documents/<int:document_id>/download")
    @login_required
    def download_document_file(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        access = get_document_access(document)
        if access not in ("OWNER", "READ", "EDIT"):
            log_audit_event(
                action="DOCUMENT_DOWNLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "missing_permission"},
            )
            return jsonify({"error": "Document access denied"}), 403

        if not document.stored_filename:
            log_audit_event(
                action="DOCUMENT_DOWNLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "file_not_attached"},
            )
            return jsonify({"error": "No file is attached to this document"}), 404

        storage_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
        storage_path = (storage_root / document.stored_filename).resolve()

        # Fail closed if the database value is malformed or escapes private storage.
        if (
            os.path.basename(document.stored_filename) != document.stored_filename
            or storage_path.parent != storage_root
            or not storage_path.is_file()
        ):
            log_audit_event(
                action="DOCUMENT_DOWNLOAD",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "stored_file_missing_or_invalid"},
            )
            return jsonify({"error": "Stored file not found"}), 404

        log_audit_event(
            action="DOCUMENT_DOWNLOADED",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document.id,
            details={
                "filename": document.original_filename,
                "file_size": document.file_size,
            },
        )

        response = send_file(
            storage_path,
            as_attachment=True,
            download_name=document.original_filename or document.title,
            mimetype=document.content_type or "application/octet-stream",
            conditional=True,
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "private, no-store"
        return response

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
            if not valid_text(data["description"], 5000, allow_empty=True):
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

    @app.delete("/documents/<int:document_id>")
    @login_required
    def delete_document(document_id):
        """Delete a document only when the authenticated user owns it."""
        document = document_or_404(document_id)
        if document is None:
            return jsonify({"error": "Document not found"}), 404

        access = get_document_access(document)
        if access != "OWNER":
            log_audit_event(
                action="DOCUMENT_DELETE",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                details={"reason": "not_document_owner"},
            )
            return jsonify({"error": "Only the document owner can delete it"}), 403

        stored_filename = document.stored_filename
        document_id_snapshot = document.id
        original_filename = document.original_filename

        # Explicitly remove grants; audit rows intentionally remain as history.
        db.session.execute(
            db.delete(DocumentPermission).where(
                DocumentPermission.document_id == document.id
            )
        )
        db.session.delete(document)
        log_audit_event(
            action="DOCUMENT_DELETED",
            outcome="SUCCESS",
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            document_id=document_id_snapshot,
            company_id=document.company_id,
            details={"filename": original_filename, "file_attached": bool(stored_filename)},
            commit=False,
        )
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        # Remove the private file only after the DB transaction commits.
        # Resolve and constrain the path to the configured storage directory.
        if stored_filename:
            storage_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
            storage_path = (storage_root / stored_filename).resolve()
            if (
                os.path.basename(stored_filename) == stored_filename
                and storage_path.parent == storage_root
                and storage_path.is_file()
            ):
                try:
                    storage_path.unlink()
                except OSError:
                    app.logger.exception(
                        "Document %s deleted but its stored file could not be removed",
                        document_id_snapshot,
                    )

        return jsonify({"message": "Document deleted", "document_id": document_id_snapshot}), 200

    # ---------------- Owner-controlled permissions ----------------

    @app.post("/documents/<int:document_id>/permissions")
    @login_required
    def grant_permission(document_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        if get_document_access(document) != "OWNER":
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

        if not user_is_company_member(target.id, document.company_id):
            log_audit_event(
                action="PERMISSION_GRANT",
                outcome="DENIED",
                actor_user_id=current_user.id,
                actor_email=current_user.email,
                document_id=document.id,
                target_user_id=target.id,
                details={"reason": "target_not_company_member"},
            )
            return jsonify({
                "error": "Permission can only be granted to a member of the same company"
            }), 403

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

    @app.delete("/documents/<int:document_id>/permissions/by-email")
    @login_required
    def revoke_permission_by_email(document_id):
        data = request.get_json(silent=True) or {}
        email = data.get("email")
        if not isinstance(email, str) or not email.strip():
            return jsonify({"error": "Provide the user's email address"}), 400
        target = db.session.execute(db.select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
        if target is None:
            return jsonify({"error": "No user found with that email"}), 404
        document = document_or_404(document_id)
        if document is None:
            return jsonify({"error": "Document not found"}), 404
        if get_document_access(document) != "OWNER":
            return jsonify({"error": "Only the document owner can revoke permissions"}), 403
        grant = db.session.execute(db.select(DocumentPermission).filter_by(document_id=document.id, user_id=target.id)).scalar_one_or_none()
        if grant is None:
            return jsonify({"error": "That user has no explicit permission on this document"}), 404
        level = grant.permission_level
        db.session.delete(grant)
        log_audit_event(action="PERMISSION_REVOKED", outcome="SUCCESS", actor_user_id=current_user.id,
            actor_email=current_user.email, document_id=document.id, target_user_id=target.id,
            company_id=document.company_id, details={"target_email": target.email, "permission_level": level}, commit=False)
        db.session.commit()
        return jsonify({"message": f"Permission revoked for {target.email}"}), 200

    @app.delete(
        "/documents/<int:document_id>/permissions/<int:user_id>"
    )
    @login_required
    def revoke_permission(document_id, user_id):
        document = document_or_404(document_id)

        if document is None:
            return jsonify({"error": "Document not found"}), 404

        if get_document_access(document) != "OWNER":
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

    # ---------------- Workspace member onboarding ----------------

    @app.get("/admin/members")
    @admin_required
    def list_workspace_members():
        """List member metadata for the administrator's active workspace."""
        membership = current_company_membership()
        if membership is None:
            return jsonify({"error": "A single active company workspace is required"}), 403

        rows = db.session.execute(
            db.select(CompanyMembership, User)
            .join(User, User.id == CompanyMembership.user_id)
            .where(CompanyMembership.company_id == membership.company_id)
            .order_by(CompanyMembership.created_at.asc())
        ).all()

        return jsonify({
            "members": [
                {
                    "user_id": member.user_id,
                    "email": user.email,
                    "workspace_role": member.role,
                    "joined_at": member.created_at.isoformat(),
                }
                for member, user in rows
            ]
        }), 200

    @app.post("/admin/members")
    @admin_required
    def add_workspace_member():
        """Invite an email address to the active workspace."""
        membership = current_company_membership()
        if membership is None:
            return jsonify({"error": "A single active company workspace is required"}), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400
        email = data.get("email")
        role = data.get("role", "member")
        if not isinstance(email, str) or not email.strip() or len(email.strip()) > 255 or "@" not in email:
            return jsonify({"error": "A valid email is required"}), 400
        email = email.strip().lower()
        if role not in ("member", "viewer"):
            return jsonify({"error": "Invitations can assign the Member or Viewer role. Administrator access requires an approval request."}), 400
        if email == current_user.email:
            return jsonify({"error": "You are already a workspace member"}), 409
        target = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if target is not None:
            existing = db.session.execute(db.select(CompanyMembership).filter_by(user_id=target.id, company_id=membership.company_id)).scalar_one_or_none()
            if existing is not None:
                return jsonify({"error": "This user is already a member of this workspace"}), 409
            db.session.add(CompanyMembership(company_id=membership.company_id, user_id=target.id, role=role))
            log_audit_event(action="WORKSPACE_MEMBER_ADDED", outcome="SUCCESS", actor_user_id=current_user.id, actor_email=current_user.email, target_user_id=target.id, company_id=membership.company_id, details={"target_email": email, "role": role}, commit=False)
            db.session.commit()
            company = db.session.get(Company, membership.company_id)
            sent = _send_email_safely(email, f"You were added to {company.name} on TrustVault", f"An administrator added your account to the {company.name} workspace as {role}. Sign in to TrustVault to continue.")
            return jsonify({"message": "Existing account added to workspace", "user_id": target.id, "email": email, "workspace_role": role, "notification_sent": bool(sent)}), 201

        token = _new_token()
        invitation = WorkspaceInvitation(
            company_id=membership.company_id,
            email=email,
            role=role,
            token_hash=_token_digest(token),
            invited_by_user_id=current_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=app.config["INVITATION_TTL_HOURS"]),
        )
        db.session.add(invitation)
        db.session.commit()
        company = db.session.get(Company, membership.company_id)
        link = _frontend_link("", token)
        sent = _send_email_safely(email, f"Invitation to join {company.name} on TrustVault", f"You have been invited to join {company.name} on TrustVault as a {role}.\n\nUse this one-time link within {app.config['INVITATION_TTL_HOURS']} hours to set your password and activate your account:\n{link}\n\nIf you were not expecting this invitation, you can ignore this email.")
        if not sent:
            db.session.delete(invitation)
            db.session.commit()
            return jsonify({"error": "Email was not delivered. Configure SMTP and ensure MAIL_SUPPRESS_SEND=false, then try again."}), 503
        log_audit_event(action="WORKSPACE_INVITATION_SENT", outcome="SUCCESS", actor_user_id=current_user.id, actor_email=current_user.email, company_id=membership.company_id, details={"target_email": email, "role": role})
        return jsonify({"message": "Invitation sent", "email": email, "workspace_role": role, "notification_sent": bool(sent)}), 201

    @app.get("/invites/validate")
    def validate_invitation():
        token = request.args.get("token", "")
        if not token or len(token) > 256:
            return jsonify({"error": "A valid invitation token is required"}), 400
        invitation = db.session.execute(db.select(WorkspaceInvitation).filter_by(token_hash=_token_digest(token))).scalar_one_or_none()
        if invitation is None or invitation.accepted_at is not None or invitation.revoked_at is not None or invitation.expires_at <= datetime.utcnow():
            return jsonify({"error": "This invitation is invalid, expired, or already used"}), 410
        company = db.session.get(Company, invitation.company_id)
        return jsonify({"email": invitation.email, "company_name": company.name if company else "Workspace", "role": invitation.role}), 200

    @app.post("/invites/accept")
    def accept_invitation():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required"}), 400
        token = data.get("token", "")
        password = data.get("password", "")
        if not isinstance(token, str) or not token or not isinstance(password, str) or len(password) < 12:
            return jsonify({"error": "A valid invitation token and password of at least 12 characters are required"}), 400
        invitation = db.session.execute(db.select(WorkspaceInvitation).filter_by(token_hash=_token_digest(token))).scalar_one_or_none()
        if invitation is None or invitation.accepted_at is not None or invitation.revoked_at is not None or invitation.expires_at <= datetime.utcnow():
            return jsonify({"error": "This invitation is invalid, expired, or already used"}), 410
        user = db.session.execute(db.select(User).filter_by(email=invitation.email)).scalar_one_or_none()
        if user is None:
            user = User(email=invitation.email, role="viewer")
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
        elif not user.password_hash:
            user.set_password(password)
        existing = db.session.execute(db.select(CompanyMembership).filter_by(user_id=user.id, company_id=invitation.company_id)).scalar_one_or_none()
        if existing is None:
            db.session.add(CompanyMembership(user_id=user.id, company_id=invitation.company_id, role=invitation.role))
        elif existing.role != invitation.role:
            existing.role = invitation.role
        invitation.accepted_at = datetime.utcnow()
        log_audit_event(action="WORKSPACE_INVITATION_ACCEPTED", outcome="SUCCESS", actor_user_id=user.id, actor_email=user.email, company_id=invitation.company_id, details={"role": invitation.role}, commit=False)
        db.session.commit()
        login_user(user)
        session["active_company_id"] = invitation.company_id
        return jsonify({"message": "Invitation accepted", "email": user.email, "active_company_id": invitation.company_id}), 200

    @app.delete("/admin/members/<int:user_id>")
    @admin_required
    def remove_workspace_member(user_id):
        membership = current_company_membership()
        if membership is None:
            return jsonify({"error": "A single active company workspace is required"}), 403
        company = db.session.get(Company, membership.company_id)
        is_owner = company is not None and company.owner_user_id == current_user.id
        if user_id == current_user.id:
            return jsonify({"error": "You cannot remove your own workspace membership"}), 409
        if company and company.owner_user_id == user_id:
            return jsonify({"error": "The original company owner cannot be removed through member management"}), 403
        target_membership = db.session.execute(db.select(CompanyMembership).filter_by(user_id=user_id, company_id=membership.company_id)).scalar_one_or_none()
        if target_membership is None:
            return jsonify({"error": "Workspace member not found"}), 404
        if target_membership.role == "admin" and not is_owner:
            return jsonify({"error": "Only the original company owner can remove another administrator"}), 403
        if target_membership.role == "admin":
            admin_count = db.session.execute(db.select(db.func.count(CompanyMembership.id)).filter_by(company_id=membership.company_id, role="admin")).scalar_one()
            if admin_count <= 1:
                return jsonify({"error": "The last workspace administrator cannot be removed"}), 409
        target = db.session.get(User, user_id)
        email = target.email if target else None
        # Remove only this workspace membership and its grants; never delete the account.
        workspace_doc_ids = db.select(Document.id).where(Document.company_id == membership.company_id)
        db.session.execute(db.delete(DocumentPermission).where(DocumentPermission.user_id == user_id, DocumentPermission.document_id.in_(workspace_doc_ids)))
        db.session.delete(target_membership)
        log_audit_event(action="WORKSPACE_MEMBER_REMOVED", outcome="SUCCESS", actor_user_id=current_user.id, actor_email=current_user.email, target_user_id=user_id, company_id=membership.company_id, details={"target_email": email}, commit=False)
        db.session.commit()
        return jsonify({"message": "Workspace access removed", "user_id": user_id, "email": email}), 200

    @app.delete("/company")
    @admin_required
    def permanently_delete_company():
        membership = current_company_membership()
        if membership is None:
            return jsonify({"error": "No active company workspace"}), 403
        company = db.session.get(Company, membership.company_id)
        if company is None:
            return jsonify({"error": "Company not found"}), 404

        # Compatibility repair for workspaces created before explicit ownership
        # was added. Only an admin can claim a genuinely unowned workspace.
        # Existing owners are never overwritten.
        if company.owner_user_id is None and membership.role == "admin":
            company.owner_user_id = current_user.id
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception("Could not assign legacy company owner")
                return jsonify({"error": "Could not establish company ownership. Check migrations and server logs."}), 500

        if company.owner_user_id != current_user.id:
            return jsonify({"error": "Only the original company owner can permanently delete this company"}), 403
        data = request.get_json(silent=True) or {}
        if data.get("confirm_name") != company.name:
            return jsonify({"error": "Enter the exact company name to confirm permanent deletion"}), 400

        company_id, company_name = company.id, company.name
        documents = db.session.execute(db.select(Document).where(Document.company_id == company_id)).scalars().all()
        storage_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
        file_paths = []
        for document in documents:
            if not document.stored_filename:
                continue
            # Stored names are generated by the server; still constrain paths defensively.
            if os.path.basename(document.stored_filename) != document.stored_filename:
                db.session.rollback()
                return jsonify({"error": "Unsafe stored file path detected; deletion cancelled"}), 500
            path = (storage_root / document.stored_filename).resolve()
            if path.parent != storage_root:
                db.session.rollback()
                return jsonify({"error": "Unsafe stored file path detected; deletion cancelled"}), 500
            if path.is_file():
                file_paths.append(path)

        doc_ids = [document.id for document in documents]
        membership_count = db.session.execute(db.select(db.func.count(CompanyMembership.id)).where(CompanyMembership.company_id == company_id)).scalar_one()
        try:
            # Explicitly remove every workspace-scoped row before deleting the company.
            if doc_ids:
                db.session.execute(db.delete(DocumentPermission).where(DocumentPermission.document_id.in_(doc_ids)))
            db.session.execute(db.delete(WorkspaceInvitation).where(WorkspaceInvitation.company_id == company_id))
            db.session.execute(db.delete(WorkspaceJoinRequest).where(WorkspaceJoinRequest.company_id == company_id))
            db.session.execute(db.delete(CompanyMembership).where(CompanyMembership.company_id == company_id))
            for document in documents:
                db.session.delete(document)
            # Audit records are historical security evidence and intentionally retained.
            log_audit_event(action="COMPANY_PERMANENTLY_DELETED", outcome="SUCCESS",
                actor_user_id=current_user.id, actor_email=current_user.email, company_id=company_id,
                details={"company_name": company_name, "documents_deleted": len(documents),
                         "memberships_deleted": int(membership_count or 0)}, commit=False)
            db.session.delete(company)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Permanent company deletion failed for company_id=%s", company_id)
            return jsonify({"error": "Company deletion failed; database changes were rolled back. Check the server log."}), 500

        # Remove physical files only after the DB transaction commits. User accounts
        # and memberships in other companies are deliberately untouched.
        for path in file_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Company %s deleted but stored file cleanup failed", company_id)
        if session.get("active_company_id") == company_id:
            session.pop("active_company_id", None)
        remaining = db.session.execute(db.select(CompanyMembership).filter_by(user_id=current_user.id)).scalars().all()
        if len(remaining) == 1:
            session["active_company_id"] = remaining[0].company_id
        return jsonify({"message": "Company and its workspace data were permanently deleted. Personal accounts and memberships in other companies were preserved."}), 200

    @app.get("/admin/join-requests")
    @admin_required
    def list_join_requests():
        membership = current_company_membership()
        rows = db.session.execute(db.select(WorkspaceJoinRequest).where(WorkspaceJoinRequest.company_id == membership.company_id, WorkspaceJoinRequest.status == "pending", WorkspaceJoinRequest.expires_at > datetime.utcnow()).order_by(WorkspaceJoinRequest.created_at.asc())).scalars().all()
        return jsonify({"requests": [{"id": row.id, "email": row.requester_email, "role": row.requested_role, "created_at": row.created_at.isoformat(), "expires_at": row.expires_at.isoformat()} for row in rows]}), 200

    @app.post("/admin/join-requests/<int:request_id>/decision")
    @admin_required
    def decide_join_request(request_id):
        membership = current_company_membership()
        data = request.get_json(silent=True)
        decision = data.get("decision") if isinstance(data, dict) else None
        if decision not in ("approve", "reject"):
            return jsonify({"error": "decision must be approve or reject"}), 400
        row = db.session.get(WorkspaceJoinRequest, request_id)
        if row is None or row.company_id != membership.company_id:
            return jsonify({"error": "Join request not found"}), 404
        if row.status != "pending" or row.expires_at <= datetime.utcnow():
            return jsonify({"error": "This request is no longer pending or has expired"}), 409
        company = db.session.get(Company, row.company_id)
        target = db.session.execute(db.select(User).filter_by(email=row.requester_email)).scalar_one_or_none()
        invite = None
        invite_token = None
        if decision == "approve":
            if target is not None:
                existing = db.session.execute(db.select(CompanyMembership).filter_by(user_id=target.id, company_id=company.id)).scalar_one_or_none()
                if existing is None:
                    db.session.add(CompanyMembership(user_id=target.id, company_id=company.id, role=row.requested_role))
                else:
                    existing.role = row.requested_role
            else:
                invite_token = _new_token()
                invite = WorkspaceInvitation(company_id=company.id, email=row.requester_email, role=row.requested_role, token_hash=_token_digest(invite_token), invited_by_user_id=current_user.id, expires_at=datetime.utcnow() + timedelta(hours=app.config["INVITATION_TTL_HOURS"]))
                db.session.add(invite)
            row.status = "approved"
        else:
            row.status = "rejected"
        row.decided_at = datetime.utcnow()
        row.decided_by_user_id = current_user.id
        log_audit_event(action="WORKSPACE_ADMIN_REQUEST_" + decision.upper(), outcome="SUCCESS", actor_user_id=current_user.id, actor_email=current_user.email, target_user_id=target.id if target else None, company_id=company.id, details={"request_id": row.id, "requester_email": row.requester_email}, commit=False)
        db.session.commit()
        if decision == "reject":
            sent = _send_email_safely(row.requester_email, f"TrustVault request for {company.name}", f"Your request to join {company.name} as {row.requested_role} was not approved. Contact the company administrator if you believe this was a mistake.")
        elif target is not None:
            sent = _send_email_safely(row.requester_email, f"Your {company.name} request was approved", f"Your request to join {company.name} as {row.requested_role} was approved. Sign in to TrustVault using your existing account. If you registered with Google, continue with Google.")
        else:
            link = _frontend_link("", invite_token)
            sent = _send_email_safely(row.requester_email, f"Set up your TrustVault administrator account for {company.name}", f"Your request to join {company.name} as {row.requested_role} was approved. Use this one-time link within {app.config['INVITATION_TTL_HOURS']} hours to set your password and activate your account:\n{link}")
        if not sent and decision == "approve" and target is None and invite is not None:
            db.session.delete(invite)
            row.status = "pending"
            row.decided_at = None
            row.decided_by_user_id = None
            db.session.commit()
            return jsonify({"error": "Approval could not be completed because the setup email was not delivered. Configure SMTP and try again."}), 503
        if not sent:
            return jsonify({"message": f"Request {decision}d, but the notification email was not delivered. Check SMTP configuration.", "decision": decision, "notification_sent": False}), 200
        return jsonify({"message": f"Request {decision}d and notification email sent", "decision": decision, "notification_sent": True}), 200

    # ---------------- Admin audit history ----------------

    @app.get("/admin/audit-logs")
    @admin_required
    def list_audit_logs():
        """Return paginated audit metadata to administrators."""
        try:
            page = int(request.args.get("page", "1"))
            per_page = int(request.args.get("per_page", "20"))
        except (TypeError, ValueError):
            return jsonify({
                "error": "page and per_page must be integers"
            }), 400

        if page < 1 or per_page < 1 or per_page > 100:
            return jsonify({
                "error": "page must be positive and per_page must be between 1 and 100"
            }), 400

        membership = current_company_membership()
        if membership is None:
            return jsonify({
                "error": "A single active company workspace is required"
            }), 403

        workspace_document_ids = db.select(Document.id).where(
            Document.company_id == membership.company_id
        )
        # New audit records carry a workspace snapshot, so events remain visible
        # after a document is deleted without leaking events from another company.
        # The document-ID clause is a safe compatibility path for pre-migration rows.
        pagination = db.paginate(
            db.select(AuditLog)
            .where(db.or_(
                AuditLog.company_id == membership.company_id,
                db.and_(
                    AuditLog.company_id.is_(None),
                    AuditLog.document_id.in_(workspace_document_ids),
                ),
            ))
            .order_by(AuditLog.id.desc()),
            page=page,
            per_page=per_page,
            error_out=False,
        )

        return jsonify({
            "events": [
                {
                    "id": event.id,
                    "actor_user_id": event.actor_user_id,
                    "actor_email": event.actor_email,
                    "action": event.action,
                    "outcome": event.outcome,
                    "document_id": event.document_id,
                    "target_user_id": event.target_user_id,
                    "details": event.details,
                    "created_at": event.created_at.isoformat(),
                    "previous_hash": event.previous_hash,
                    "event_hash": event.event_hash,
                }
                for event in pagination.items
            ],
            "page": pagination.page,
            "per_page": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        }), 200

    # Final WSGI-level CORS enforcement. This wraps every Flask response,
    # including automatic OPTIONS responses and error/unauthorized responses.
    # It intentionally allows only the configured frontend origin.
    flask_wsgi_app = app.wsgi_app

    def cors_wsgi_app(environ, start_response):
        origin = environ.get("HTTP_ORIGIN", "")
        allowed_origin = app.config.get("FRONTEND_URL", "").rstrip("/")

        def cors_start_response(status, headers, exc_info=None):
            if origin and allowed_origin and origin.rstrip("/") == allowed_origin:
                cors_headers = {
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                    "access-control-allow-headers": "Content-Type, X-CSRFToken, X-CSRF-Token",
                    "access-control-expose-headers": "Content-Disposition",
                }
                headers = [
                    (key, value) for key, value in headers
                    if key.lower() not in cors_headers and key.lower() != "vary"
                ]
                headers.extend((key, value) for key, value in cors_headers.items())
                headers.append(("Vary", "Origin"))
            return start_response(status, headers, exc_info)

        return flask_wsgi_app(environ, cors_start_response)

    app.wsgi_app = cors_wsgi_app
    return app