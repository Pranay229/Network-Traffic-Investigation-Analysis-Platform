"""
Alert model — produced by the detection engine.
Severity: informational | low | medium | high
Status: new | investigating | resolved
"""
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, DateTime, Index
from app.database.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    alert_id = Column(String(30), unique=True, index=True, nullable=False)  # ALT-0001

    # Detection metadata
    severity = Column(String(20), nullable=False)   # informational | low | medium | high
    alert_type = Column(String(100), nullable=False, index=True)
    detection_rule = Column(String(100), nullable=True)

    # Parties involved
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)

    # Time
    first_seen = Column(Float, nullable=True)
    last_seen = Column(Float, nullable=True)
    first_seen_str = Column(String(30), nullable=True)

    # Evidence & explanation
    _evidence_json = Column("evidence_json", Text, default="{}")
    reason = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)

    # Status: new | investigating | resolved
    status = Column(String(20), default="new", index=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def evidence(self) -> dict:
        try:
            return json.loads(self._evidence_json or "{}")
        except Exception:
            return {}

    @evidence.setter
    def evidence(self, value: dict) -> None:
        self._evidence_json = json.dumps(value)

    __table_args__ = (
        Index("ix_alerts_inv_severity", "investigation_id", "severity"),
    )
