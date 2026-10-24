"""Add purpose to OTP challenges so login and reset codes cannot be mixed."""
from alembic import op
import sqlalchemy as sa

revision = "a4c2d8f91e77"
down_revision = "7bc2b9d8da9a"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("login_otp") as batch_op:
        batch_op.add_column(sa.Column("purpose", sa.String(length=20), nullable=False, server_default="login"))
        batch_op.create_index("ix_login_otp_purpose", ["purpose"], unique=False)

def downgrade():
    with op.batch_alter_table("login_otp") as batch_op:
        batch_op.drop_index("ix_login_otp_purpose")
        batch_op.drop_column("purpose")
