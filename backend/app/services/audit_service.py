"""
Audit Logging Service:
Centralized recorder for security events, authentication lifecycle,
admin operations, and investigation access.
"""
import logging
from typing import Any, Optional, Dict
from sqlalchemy.orm import Session
from app.models.audit import AuditLog

logger = logging.getLogger("audit_service")

# Sensitive keys that must NEVER be recorded in audit log metadata
REDACTED_KEYS = {"password", "password_hash", "confirm_password", "token", "raw_token", "secret", "refresh_token", "access_token"}


def sanitize_metadata(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively scrub sensitive keys from metadata."""
    if not meta:
        return {}
    clean = {}
    for k, v in meta.items():
        if k.lower() in REDACTED_KEYS:
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = sanitize_metadata(v)
        else:
            clean[k] = v
    return clean


def log_audit_event(
    db: Session,
    event_type: str,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Record an immutable security audit log entry."""
    clean_meta = sanitize_metadata(metadata)
    audit = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
    )
    audit.metadata_dict = clean_meta
    db.add(audit)
    try:
        db.flush()
    except Exception as e:
        logger.error(f"Failed to write audit log entry: {e}")
    return audit


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        event_type: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        return log_audit_event(
            db=db,
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=metadata
        )


audit_service = AuditService()
