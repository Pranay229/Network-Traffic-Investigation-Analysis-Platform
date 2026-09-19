"""
Scan model for Network Scanner and Finding Explanation engine.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(32), default="standard")  # fast, standard, full
    status = Column(String(32), default="pending")      # pending, running, completed, failed
    
    # Timestamps & Timezone
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    timezone = Column(String(32), default="UTC")
    
    # Summary Metrics
    hosts_discovered = Column(Integer, default=0)
    open_ports_count = Column(Integer, default=0)
    services_count = Column(Integer, default=0)
    potential_findings_count = Column(Integer, default=0)
    highest_severity = Column(String(20), default="INFO")  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    
    # Complete structured scan results and finding explanations
    results_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", backref="scans")

    # Convenience aliases for spec compliance
    @property
    def scan_started_at(self) -> datetime:
        return self.started_at

    @scan_started_at.setter
    def scan_started_at(self, value):
        self.started_at = value

    @property
    def scan_completed_at(self):
        return self.completed_at

    @scan_completed_at.setter
    def scan_completed_at(self, value):
        self.completed_at = value

    @property
    def scan_duration(self) -> float:
        return self.duration_seconds

    @scan_duration.setter
    def scan_duration(self, value):
        self.duration_seconds = value

    @property
    def scan_status(self) -> str:
        return self.status

    @scan_status.setter
    def scan_status(self, value):
        self.status = value

    def __init__(self, **kwargs):
        if "scan_id" not in kwargs:
            import uuid
            kwargs["scan_id"] = f"scan_{uuid.uuid4().hex[:8]}"
        if "user_id" not in kwargs:
            kwargs["user_id"] = 1
        super().__init__(**kwargs)
