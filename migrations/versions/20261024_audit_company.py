"""Add workspace snapshot to audit events and rebuild the hash chain.

Revision ID: 20261024_audit_company
Revises: 36099e861545
"""
import hashlib
import json

from alembic import op
import sqlalchemy as sa

revision = "20261024_audit_company"
down_revision = "36099e861545"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64


def _hash_payload(row, previous_hash):
    payload = {
        "id": row["id"],
        "actor_user_id": row["actor_user_id"],
        "actor_email": row["actor_email"],
        "action": row["action"],
        "outcome": row["outcome"],
        "document_id": row["document_id"],
        "company_id": row["company_id"],
        "target_user_id": row["target_user_id"],
        "details": row["details"] or {},
        "created_at": row["created_at"].isoformat(),
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade():
    with op.batch_alter_table("audit_log", schema=None) as batch_op:
        batch_op.add_column(sa.Column("company_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_audit_log_company_id", ["company_id"], unique=False)

    # Backfill workspace snapshots for existing events before enabling multiple
    # memberships. Prefer the document's workspace. For document-deletion events
    # where the document no longer exists, use an actor's sole historical/current
    # membership when unambiguous.
    bind = op.get_bind()
    audit = sa.table(
        "audit_log",
        sa.column("id", sa.Integer()),
        sa.column("actor_user_id", sa.Integer()),
        sa.column("actor_email", sa.String()),
        sa.column("action", sa.String()),
        sa.column("outcome", sa.String()),
        sa.column("document_id", sa.Integer()),
        sa.column("company_id", sa.Integer()),
        sa.column("target_user_id", sa.Integer()),
        sa.column("details", sa.JSON()),
        sa.column("created_at", sa.DateTime()),
        sa.column("previous_hash", sa.String()),
        sa.column("event_hash", sa.String()),
    )
    documents = sa.table(
        "document",
        sa.column("id", sa.Integer()),
        sa.column("company_id", sa.Integer()),
    )
    memberships = sa.table(
        "company_membership",
        sa.column("user_id", sa.Integer()),
        sa.column("company_id", sa.Integer()),
    )
    rows = bind.execute(sa.select(audit).order_by(audit.c.id.asc())).mappings().all()

    for original in rows:
        row = dict(original)
        company_id = None
        if row["document_id"] is not None:
            company_id = bind.execute(
                sa.select(documents.c.company_id).where(
                    documents.c.id == row["document_id"]
                )
            ).scalar_one_or_none()
        if company_id is None and row["actor_user_id"] is not None:
            actor_companies = bind.execute(
                sa.select(memberships.c.company_id)
                .where(memberships.c.user_id == row["actor_user_id"])
                .distinct()
            ).scalars().all()
            if len(actor_companies) == 1:
                company_id = actor_companies[0]
        row["company_id"] = company_id
        bind.execute(
            audit.update().where(audit.c.id == row["id"]).values(company_id=company_id)
        )

    # The hash payload now includes company_id, so rebuild the chain atomically
    # during this schema migration to keep verification valid after deployment.
    expected_previous_hash = GENESIS_HASH
    refreshed = bind.execute(sa.select(audit).order_by(audit.c.id.asc())).mappings().all()
    for original in refreshed:
        row = dict(original)
        row["previous_hash"] = expected_previous_hash
        event_hash = _hash_payload(row, expected_previous_hash)
        bind.execute(
            audit.update().where(audit.c.id == row["id"]).values(
                previous_hash=expected_previous_hash,
                event_hash=event_hash,
            )
        )
        expected_previous_hash = event_hash


def downgrade():
    # Rebuild the original payload chain without company_id before dropping it.
    bind = op.get_bind()
    audit = sa.table(
        "audit_log",
        sa.column("id", sa.Integer()),
        sa.column("actor_user_id", sa.Integer()),
        sa.column("actor_email", sa.String()),
        sa.column("action", sa.String()),
        sa.column("outcome", sa.String()),
        sa.column("document_id", sa.Integer()),
        sa.column("company_id", sa.Integer()),
        sa.column("target_user_id", sa.Integer()),
        sa.column("details", sa.JSON()),
        sa.column("created_at", sa.DateTime()),
        sa.column("previous_hash", sa.String()),
        sa.column("event_hash", sa.String()),
    )
    expected_previous_hash = GENESIS_HASH
    rows = bind.execute(sa.select(audit).order_by(audit.c.id.asc())).mappings().all()
    for original in rows:
        row = dict(original)
        payload = {
            "id": row["id"],
            "actor_user_id": row["actor_user_id"],
            "actor_email": row["actor_email"],
            "action": row["action"],
            "outcome": row["outcome"],
            "document_id": row["document_id"],
            "target_user_id": row["target_user_id"],
            "details": row["details"] or {},
            "created_at": row["created_at"].isoformat(),
            "previous_hash": expected_previous_hash,
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        bind.execute(
            audit.update().where(audit.c.id == row["id"]).values(
                previous_hash=expected_previous_hash, event_hash=event_hash
            )
        )
        expected_previous_hash = event_hash

    with op.batch_alter_table("audit_log", schema=None) as batch_op:
        batch_op.drop_index("ix_audit_log_company_id")
        batch_op.drop_column("company_id")
