from getpass import getpass

from backend.app import create_app
from backend.extensions import db
from backend.models import User


def main():
    email = input("Exact email of the existing TrustVault account to recover: ").strip().lower()
    if not email or "@" not in email:
        raise SystemExit("A valid email is required. No changes made.")

    confirmation = input(f"Type RESET PASSWORD for {email} to continue: ").strip()
    if confirmation != "RESET PASSWORD":
        raise SystemExit("Confirmation did not match. No changes made.")

    new_password = getpass("New password (minimum 12 characters): ")
    confirm_password = getpass("Confirm new password: ")
    if len(new_password) < 12:
        raise SystemExit("Password must be at least 12 characters. No changes made.")
    if new_password != confirm_password:
        raise SystemExit("Passwords do not match. No changes made.")

    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user is None:
            raise SystemExit("No existing account found for that email in this database. No changes made.")
        user.set_password(new_password)
        db.session.commit()
        print(f"Password reset successfully for existing account: {user.email}")
        print("No users, workspaces, documents, or permissions were created or deleted.")


if __name__ == "__main__":
    main()
