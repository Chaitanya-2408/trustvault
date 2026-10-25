"""
LOCAL-ONLY TrustVault security-test helper.

Creates a second test user in the same company workspace as an existing owner
so the READ/EDIT/revocation API checks can be exercised manually.

Do not expose this script as a production endpoint or run it against production.
Run it from the repository root with the project's virtual environment active.
"""
import argparse
from getpass import getpass

from backend.app import create_app
from backend.extensions import db
from backend.models import CompanyMembership, User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner-email", required=True, help="Existing workspace owner's email")
    parser.add_argument("--member-email", required=True, help="Email for the test member account")
    args = parser.parse_args()

    member_password = getpass("Password for test member (minimum 12 characters): ")
    if len(member_password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")

    app = create_app()
    with app.app_context():
        owner = db.session.execute(
            db.select(User).filter_by(email=args.owner_email.strip().lower())
        ).scalar_one_or_none()
        if owner is None:
            raise SystemExit("Owner account not found.")

        owner_memberships = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=owner.id)
        ).scalars().all()
        if len(owner_memberships) != 1:
            raise SystemExit("Owner must have exactly one workspace membership.")

        company_id = owner_memberships[0].company_id
        member_email = args.member_email.strip().lower()
        member = db.session.execute(
            db.select(User).filter_by(email=member_email)
        ).scalar_one_or_none()

        if member is None:
            member = User(email=member_email, role="viewer")
            member.set_password(member_password)
            db.session.add(member)
            db.session.flush()
        else:
            member.set_password(member_password)

        member_memberships = db.session.execute(
            db.select(CompanyMembership).filter_by(user_id=member.id)
        ).scalars().all()

        if any(m.company_id != company_id for m in member_memberships):
            db.session.rollback()
            raise SystemExit(
                "This account already belongs to a different workspace. "
                "Use a new test email; no workspace membership was changed."
            )

        if len(member_memberships) > 1:
            db.session.rollback()
            raise SystemExit("Test member has multiple memberships; refusing to continue.")

        if not member_memberships:
            db.session.add(
                CompanyMembership(
                    company_id=company_id,
                    user_id=member.id,
                    role="member",
                )
            )

        db.session.commit()
        print("Test member is ready.")
        print(f"Owner email:  {owner.email}")
        print(f"Member email: {member.email}")
        print(f"Member user ID: {member.id}")
        print(f"Shared company ID: {company_id}")
        print("The password was not printed. Use the password you entered to log in.")


if __name__ == "__main__":
    main()
