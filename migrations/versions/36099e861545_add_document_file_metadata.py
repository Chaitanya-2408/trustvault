"""add document file metadata

Revision ID: 36099e861545
Revises: c3eb93eb6574
"""

from alembic import op
import sqlalchemy as sa

revision = "36099e861545"
down_revision = "c3eb93eb6574"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "document",
        sa.Column("stored_filename", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "document",
        sa.Column("original_filename", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "document",
        sa.Column("content_type", sa.String(length=150), nullable=True),
    )
    op.add_column(
        "document",
        sa.Column("file_size", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_document_stored_filename",
        "document",
        ["stored_filename"],
        unique=True,
    )


def downgrade():
    op.drop_index("ix_document_stored_filename", table_name="document")
    op.drop_column("document", "file_size")
    op.drop_column("document", "content_type")
    op.drop_column("document", "original_filename")
    op.drop_column("document", "stored_filename")