"""Add oauth_state table for cross-origin OAuth state persistence.

Revision ID: 20261025_add_oauth_state
Revises: 20261025_company_owner
"""
from alembic import op
import sqlalchemy as sa

revision = "20261025_add_oauth_state"
down_revision = "20261025_company_owner"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "oauth_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=255), nullable=False),
        sa.Column("data", sa.Text(), nullable=False),
        sa.Column("frontend_url", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("oauth_state") as batch_op:
        batch_op.create_index("ix_oauth_state_state", ["state"], unique=True)
        batch_op.create_index("ix_oauth_state_expires_at", ["expires_at"])


def downgrade():
    op.drop_table("oauth_state")
