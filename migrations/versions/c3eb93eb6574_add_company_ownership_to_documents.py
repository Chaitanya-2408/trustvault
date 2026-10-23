
"""add company ownership to documents

Revision ID: c3eb93eb6574
Revises: 161669d590ef
Create Date: 2026-10-23 20:21:14.179926
"""

from alembic import op
import sqlalchemy as sa

revision = "c3eb93eb6574"
down_revision = "161669d590ef"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("document", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("company_id", sa.Integer(), nullable=True)
        )
        batch_op.create_index(
            "ix_document_company_id",
            ["company_id"],
            unique=False,
        )
        batch_op.create_foreign_key(
            "fk_document_company_id_company",
            "company",
            ["company_id"],
            ["id"],
        )


def downgrade():
    with op.batch_alter_table("document", schema=None) as batch_op:
        batch_op.drop_constraint(
            "fk_document_company_id_company",
            type_="foreignkey",
        )
        batch_op.drop_index("ix_document_company_id")
        batch_op.drop_column("company_id")
