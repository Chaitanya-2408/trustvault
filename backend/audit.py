
import hashlib
import json
from datetime import datetime

from flask import has_request_context, session

from backend.extensions import db
from backend.models import AuditLog, CompanyMembership, Document


GENESIS_HASH = "0" * 64


def _event_payload(event):
    """Return a stable representation of an audit event."""
    return {
        "id": event.id,
        "actor_user_id": event.actor_user_id,
        "actor_email": event.actor_email,
        "action": event.action,
        "outcome": event.outcome,
        "document_id": event.document_id,
        "company_id": event.company_id,
        "target_user_id": event.target_user_id,
        "details": event.details,
        "created_at": event.created_at.isoformat(),
        "previous_hash": event.previous_hash,
    }


def _calculate_hash(event):
    """Calculate SHA-256 over the event and its previous hash."""
    canonical_json = json.dumps(
        _event_payload(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def log_audit_event(
    action,
    outcome,
    actor_user_id=None,
    actor_email=None,
    document_id=None,
    target_user_id=None,
    details=None,
    company_id=None,
    commit=True,
):
    """
    Append an audit event to the hash chain.

    Set commit=False when the event must be committed atomically
    with another database change in the calling route.
    """
    if outcome not in ("SUCCESS", "DENIED"):
        raise ValueError("Outcome must be SUCCESS or DENIED.")

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Action must be a non-empty string.")

    if len(action) > 80:
        raise ValueError("Action must be at most 80 characters.")

    previous_event = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()

    previous_hash = (
        previous_event.event_hash
        if previous_event is not None
        else GENESIS_HASH
    )

    # Resolve workspace ownership at event creation time. Explicit values take
    # precedence; document events use the document's workspace; non-document
    # events use the selected session workspace or an unambiguous membership.
    if company_id is None and document_id is not None:
        document = db.session.get(Document, document_id)
        if document is not None:
            company_id = document.company_id
    if company_id is None and has_request_context():
        selected_company_id = session.get("active_company_id")
        if selected_company_id is not None:
            company_id = selected_company_id
    if company_id is None and actor_user_id is not None:
        memberships = db.session.execute(
            db.select(CompanyMembership.company_id).where(
                CompanyMembership.user_id == actor_user_id
            )
        ).scalars().all()
        if len(memberships) == 1:
            company_id = memberships[0]

    event = AuditLog(
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        action=action,
        outcome=outcome,
        document_id=document_id,
        company_id=company_id,
        target_user_id=target_user_id,
        details=details or {},
        created_at=datetime.utcnow(),
        previous_hash=previous_hash,
        # Temporary value until the database assigns the event ID.
        event_hash=GENESIS_HASH,
    )

    db.session.add(event)
    db.session.flush()

    event.event_hash = _calculate_hash(event)

    if commit:
        db.session.commit()
    else:
        db.session.flush()

    return event


def verify_audit_chain():
    """Return True only when every event and chain link verifies."""
    events = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.id.asc())
    ).scalars().all()

    expected_previous_hash = GENESIS_HASH

    for event in events:
        if event.previous_hash != expected_previous_hash:
            return False

        if event.event_hash != _calculate_hash(event):
            return False

        expected_previous_hash = event.event_hash

    return True
