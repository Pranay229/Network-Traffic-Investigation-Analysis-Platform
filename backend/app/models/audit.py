"""
Audit Log Model — records security-critical events.
Tracks user actions, authentication results, admin modifications,
investigation lifecycle events, and IP/User-Agent metadata.
"""
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship, synonym
from app.database.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    event_type = Column(String(60), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    created_at = synonym("timestamp")

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    resource_type = Column(String(50), nullable=True, index=True)
    resource_id = Column(String(100), nullable=True)

    _metadata_json = Column("metadata_json", Text, default="{}")

    # Relationship
    user = relationship("User", foreign_keys=[user_id])

    @property
    def metadata_dict(self) -> dict:
        try:
            return json.loads(self._metadata_json or "{}")
        except Exception:
            return {}

    @metadata_dict.setter
    def metadata_dict(self, value: dict) -> None:
        self._metadata_json = json.dumps(value)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_email": self.user.email if self.user else None,
            "user_name": self.user.full_name if self.user else None,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "metadata": self.metadata_dict,
        }

    __table_args__ = (
        Index("ix_audit_event_time", "event_type", "timestamp"),
    )
