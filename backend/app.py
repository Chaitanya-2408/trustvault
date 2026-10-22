
import os

from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from backend.extensions import db, login_manager
from backend.models import User


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///trustvault.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"error": "Authentication required"}), 401

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "TrustVault"}), 200

    @app.post("/register")
    def register():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "")
        password = data.get("password", "")

        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "Email and password must be strings"}), 400

        email = email.strip().lower()

        if not email or len(email) > 255 or "@" not in email:
            return jsonify({"error": "A valid email is required"}), 400

        if len(password) < 12:
            return jsonify({"error": "Password must be at least 12 characters"}), 400

        user = User(email=email, role="viewer")
        user.set_password(password)
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "An account with that email already exists"}), 409

        return jsonify({"message": "Account created"}), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "")
        password = data.get("password", "")

        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "Invalid email or password"}), 400

        user = db.session.execute(
            db.select(User).filter_by(email=email.strip().lower())
        ).scalar_one_or_none()

        if user is None or not user.check_password(password):
            return jsonify({"error": "Invalid email or password"}), 401

        login_user(user)
        return jsonify({"message": "Logged in", "role": user.role}), 200

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
