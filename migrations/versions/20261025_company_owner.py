"""Add explicit company ownership.

Revision ID: 20261025_company_owner
Revises: a4c2d8f91e77
"""
from alembic import op
import sqlalchemy as sa

revision = "20261025_company_owner"
down_revision = "a4c2d8f91e77"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("company") as batch_op:
        batch_op.add_column(sa.Column("owner_user_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_company_owner_user_id", ["owner_user_id"])
        batch_op.create_foreign_key("fk_company_owner_user", "user", ["owner_user_id"], ["id"])
    # Backfill ownership for existing companies from their earliest admin membership.
    bind = op.get_bind()
    rows = bind.execute(sa.text("""
        SELECT c.id, cm.user_id
        FROM company c
        JOIN company_membership cm ON cm.company_id = c.id
        WHERE cm.role = 'admin'
        AND cm.id = (SELECT MIN(cm2.id) FROM company_membership cm2
                     WHERE cm2.company_id = c.id AND cm2.role = 'admin')
    """)).fetchall()
    for row in rows:
        bind.execute(sa.text("UPDATE company SET owner_user_id = :uid WHERE id = :cid"),
                     {"uid": row[1], "cid": row[0]})

def downgrade():
    with op.batch_alter_table("company") as batch_op:
        batch_op.drop_constraint("fk_company_owner_user", type_="foreignkey")
        batch_op.drop_index("ix_company_owner_user_id")
        batch_op.drop_column("owner_user_id")
