"""
Investigation model — represents one uploaded PCAP analysis session.
"""
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    inv_id = Column(String(20), unique=True, index=True, nullable=False)  # INV-2026-0001
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    pcap_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    file_hash = Column(String(64), nullable=True)  # SHA-256

    owner = relationship("User", back_populates="investigations", foreign_keys=[user_id])

    # Status: pending | processing | completed | failed (processing lifecycle)
    status = Column(String(20), default="pending", index=True)
    error_message = Column(Text, nullable=True)
    progress = Column(Integer, default=0)  # 0-100
    current_stage = Column(String(100), nullable=True)

    # Workflow Status: OPEN | INVESTIGATING | CONTAINED | RESOLVED | CLOSED
    investigation_status = Column(String(32), default="OPEN", index=True)
    severity = Column(String(20), default="INFO", index=True)  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    related_scan_id = Column(String(64), nullable=True, index=True)
    _notes_json = Column("notes_json", Text, default="[]")

    # Analysis results summary (stored as JSON text)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    unique_hosts = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    capture_start = Column(String(50), nullable=True)
    capture_end = Column(String(50), nullable=True)
    capture_duration = Column(Float, default=0.0)

    # Metadata stored as JSON
    _metadata_json = Column("metadata_json", Text, default="{}")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    @property
    def metadata_dict(self) -> dict:
        try:
            return json.loads(self._metadata_json or "{}")
        except Exception:
            return {}

    @metadata_dict.setter
    def metadata_dict(self, value: dict) -> None:
        self._metadata_json = json.dumps(value)

    @property
    def notes(self) -> list:
        try:
            return json.loads(self._notes_json or "[]")
        except Exception:
            return []

    @notes.setter
    def notes(self, value: list) -> None:
        self._notes_json = json.dumps(value)
