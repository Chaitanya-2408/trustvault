
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

from backend.extensions import csrf, db, login_manager
from backend.models import User

# Load local development settings from .env when available.
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

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "TrustVault",
        }), 200

    @app.get("/csrf-token")
    def csrf_token():
        return jsonify({"csrf_token": generate_csrf()}), 200

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
            db.select(User).filter_by(
                email=email.strip().lower()
            )
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

    return app
