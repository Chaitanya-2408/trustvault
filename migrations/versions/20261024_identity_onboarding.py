"""Add Google identity support, invitations, join approvals, and viewer role.

Revision ID: 20261024_identity_onboarding
Revises: 20261024_audit_company
"""
from alembic import op
import sqlalchemy as sa

revision = "20261024_identity_onboarding"
down_revision = "20261024_audit_company"
branch_labels = None
depends_on = None


def upgrade():
    # Normalize existing company names. Keep old duplicate workspaces intact,
    # but give later duplicates a unique legacy key so the new index can be added
    # without merging or deleting company-owned data.
    op.add_column("company", sa.Column("normalized_name", sa.String(length=512), nullable=True))
    bind = op.get_bind()
    company_table = sa.table(
        "company",
        sa.column("id", sa.Integer()),
        sa.column("name", sa.String(length=200)),
        sa.column("normalized_name", sa.String(length=512)),
    )
    rows = bind.execute(sa.select(company_table.c.id, company_table.c.name).order_by(company_table.c.id.asc())).all()
    seen = set()
    for company_id, name in rows:
        normalized = " ".join((name or "").split()).casefold()
        key = normalized
        if key in seen:
            key = f"{normalized}#legacy-duplicate-{company_id}"
        seen.add(key)
        bind.execute(company_table.update().where(company_table.c.id == company_id).values(normalized_name=key))
    with op.batch_alter_table("company") as batch_op:
        batch_op.alter_column("normalized_name", existing_type=sa.String(length=512), nullable=False)
    op.create_index("ix_company_normalized_name", "company", ["normalized_name"], unique=True)

    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column("password_hash", existing_type=sa.String(length=255), nullable=True)

    with op.batch_alter_table("company_membership") as batch_op:
        batch_op.drop_constraint("ck_company_membership_role", type_="check")
        batch_op.create_check_constraint(
            "ck_company_membership_role",
            "role IN ('admin', 'member', 'viewer')",
        )

    op.create_table(
        "workspace_invitation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("company_id", sa.Integer(), sa.ForeignKey("company.id"), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="member"),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_workspace_invitation_company_id", "workspace_invitation", ["company_id"])
    op.create_index("ix_workspace_invitation_email", "workspace_invitation", ["email"])

    op.create_table(
        "workspace_join_request",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("company_id", sa.Integer(), sa.ForeignKey("company.id"), nullable=False),
        sa.Column("requester_email", sa.String(length=255), nullable=False),
        sa.Column("requested_role", sa.String(length=20), nullable=False, server_default="admin"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decided_by_user_id", sa.Integer(), nullable=True),
    )
    op.create_index("ix_workspace_join_request_company_id", "workspace_join_request", ["company_id"])
    op.create_index("ix_workspace_join_request_requester_email", "workspace_join_request", ["requester_email"])
    op.create_index("ix_workspace_join_request_status", "workspace_join_request", ["status"])


def downgrade():
    op.drop_index("ix_company_normalized_name", table_name="company")
    with op.batch_alter_table("company") as batch_op:
        batch_op.drop_column("normalized_name")
    op.drop_index("ix_workspace_join_request_status", table_name="workspace_join_request")
    op.drop_index("ix_workspace_join_request_requester_email", table_name="workspace_join_request")
    op.drop_index("ix_workspace_join_request_company_id", table_name="workspace_join_request")
    op.drop_table("workspace_join_request")
    op.drop_index("ix_workspace_invitation_email", table_name="workspace_invitation")
    op.drop_index("ix_workspace_invitation_company_id", table_name="workspace_invitation")
    op.drop_table("workspace_invitation")
    with op.batch_alter_table("company_membership") as batch_op:
        batch_op.drop_constraint("ck_company_membership_role", type_="check")
        batch_op.create_check_constraint("ck_company_membership_role", "role IN ('admin', 'member')")
    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column("password_hash", existing_type=sa.String(length=255), nullable=False)
