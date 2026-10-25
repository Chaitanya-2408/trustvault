"""Add full_name column to User model.

Revision ID: 20261025_add_user_full_name
Revises: 20261025_add_oauth_state
"""
from alembic import op
import sqlalchemy as sa

revision = "20261025_add_user_full_name"
down_revision = "20261025_add_oauth_state"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(sa.Column("full_name", sa.String(length=255), nullable=True, server_default=""))


def downgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("full_name")
