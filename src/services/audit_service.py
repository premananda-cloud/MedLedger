"""
AuditService — single, authoritative writer for the append-only audit trail.
Location: src/services/audit_service.py

All audit writes go through this module so that:
  1. previous_event_hash is always populated (real hash chain, not just event hashes).
  2. The immutable-row guard in models.py (before_update / before_delete) is the
     last line of defence, not the only one.
  3. Audit failures are surfaced as structured warnings, never silently swallowed
     in a way that hides bugs.

Hash-chain design
─────────────────
  event_hash = SHA-256(action | user_id | related_user_id | record_id |
                       description | iso_timestamp | previous_event_hash)

  previous_event_hash of the first row is the SHA-256 of the string "GENESIS".

  To verify the chain call AuditService.verify_chain(db).
  It returns (is_intact: bool, broken_at_id: int | None, message: str).
"""

import hashlib
import logging
from datetime import datetime
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from src.database.models import AuditAction, AuditLog

logger = logging.getLogger(__name__)

_GENESIS = hashlib.sha256(b"GENESIS").hexdigest()


def _compute_event_hash(
    action: AuditAction,
    user_id: int,
    related_user_id: Optional[int],
    record_id: Optional[str],
    description: str,
    iso_timestamp: str,
    previous_hash: str,
) -> str:
    raw = (
        f"{action}"
        f"{user_id}"
        f"{related_user_id}"
        f"{record_id}"
        f"{description}"
        f"{iso_timestamp}"
        f"{previous_hash}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append(
    db: Session,
    *,
    action: AuditAction,
    user_id: int,
    related_user_id: Optional[int] = None,
    record_id: Optional[str] = None,
    description: str = "",
    request_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[AuditLog]:
    """
    Insert one immutable audit row and return it.

    The previous_event_hash is fetched inside the same transaction so there is
    no gap under concurrent writers (SQLite serialises writes; for PostgreSQL
    use SERIALIZABLE isolation or an advisory lock on the audit table).

    Returns the new AuditLog row, or None if writing failed (caller must decide
    whether to abort the outer transaction).
    """
    try:
        # Fetch the most-recent event hash while still inside the transaction.
        last = (
            db.query(AuditLog.event_hash)
            .order_by(AuditLog.id.desc())
            .limit(1)
            .scalar()
        )
        previous_hash = last if last else _GENESIS

        now = datetime.utcnow()
        iso_now = now.isoformat()

        event_hash = _compute_event_hash(
            action=action,
            user_id=user_id,
            related_user_id=related_user_id,
            record_id=record_id,
            description=description,
            iso_timestamp=iso_now,
            previous_hash=previous_hash,
        )

        log = AuditLog(
            user_id=user_id,
            action=action,
            record_id=record_id,
            related_user_id=related_user_id,
            description=description,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
            request_ip=request_ip,
            user_agent=user_agent,
            timestamp=now,
            created_at=now,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    except Exception as exc:
        # Never let an audit failure crash the outer business operation.
        # Log the full traceback so it is never silently lost.
        logger.error(
            "AuditService.append failed — action=%s user_id=%s: %s",
            action, user_id, exc,
            exc_info=True,
        )
        try:
            db.rollback()
        except Exception:
            pass
        return None


def verify_chain(db: Session) -> Tuple[bool, Optional[int], str]:
    """
    Walk the entire audit log in insertion order and verify the hash chain.

    Returns:
        (True,  None,  "Chain intact")            — all good
        (False, row_id, "Chain broken at id=N …") — first broken link
    """
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not rows:
        return True, None, "Chain intact (empty log)"

    previous_hash = _GENESIS

    for row in rows:
        expected = _compute_event_hash(
            action=row.action,
            user_id=row.user_id,
            related_user_id=row.related_user_id,
            record_id=row.record_id,
            description=row.description or "",
            iso_timestamp=row.timestamp.isoformat(),
            previous_hash=previous_hash,
        )

        if row.event_hash != expected:
            return (
                False,
                row.id,
                f"Chain broken at id={row.id}: "
                f"stored={row.event_hash[:12]}… expected={expected[:12]}…",
            )

        if row.previous_event_hash != previous_hash:
            return (
                False,
                row.id,
                f"Chain broken at id={row.id}: "
                f"previous_event_hash mismatch",
            )

        previous_hash = row.event_hash

    return True, None, f"Chain intact ({len(rows)} entries)"
