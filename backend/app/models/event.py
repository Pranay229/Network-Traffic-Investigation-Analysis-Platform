"""
Event and Finding models for Network Traffic Investigation & Analysis Platform
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Provides structured, indexed event telemetry for:
- Scan Events (Milestones and discoveries during network scans)
- Traffic Events (Temporal packet, session, protocol, and security occurrences from PCAPs)
- Security Findings (Persistent findings with strict separation of Observation, Analysis, Recommendation)
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, Index, func
)
from sqlalchemy.orm import relationship
from app.database.base import Base


class ScanEvent(Base):
    """
    Chronological milestone or discovery event generated during a network scan.
    """
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)

    timestamp = Column(Float, nullable=False, index=True, comment="Unix epoch timestamp in UTC")
    timestamp_str = Column(String(50), nullable=True, comment="Formatted UTC timestamp string")

    # Event classification
    # SCAN_STARTED | HOST_DISCOVERED | PORT_DISCOVERED | SERVICE_DETECTED | HIGH_TRAFFIC | SCAN_COMPLETED | SECURITY_FINDING
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="INFO", index=True)  # INFO | LOW | MEDIUM | HIGH | CRITICAL

    # Network endpoints involved
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="TCP", nullable=True)

    # Narrative descriptions with strict separation of evidence
    short_explanation = Column(String(500), nullable=False)
    observation = Column(Text, nullable=True)
    analysis = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)

    # Telemetry and metrics
    packet_count = Column(Integer, default=0)
    bytes_count = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    evidence = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("Scan", backref="events")

    def __init__(self, **kwargs):
        if "description" in kwargs and "short_explanation" not in kwargs:
            kwargs["short_explanation"] = kwargs.pop("description")
        elif "description" in kwargs:
            kwargs.pop("description")
        if "timestamp" in kwargs and isinstance(kwargs["timestamp"], datetime):
            kwargs["timestamp"] = kwargs["timestamp"].timestamp()
        if "event_id" not in kwargs:
            import uuid
            kwargs["event_id"] = f"sev_{uuid.uuid4().hex[:12]}"
        super().__init__(**kwargs)

    @property
    def description(self):
        return self.short_explanation

    @description.setter
    def description(self, value):
        self.short_explanation = value

    __table_args__ = (
        Index("ix_scan_events_scan_ts", "scan_id", "timestamp"),
        Index("ix_scan_events_type_ts", "event_type", "timestamp"),
        Index("ix_scan_events_sev_ts", "severity", "timestamp"),
        Index("ix_scan_events_endpoints", "source_ip", "destination_ip"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "short_explanation": self.short_explanation,
            "description": self.short_explanation,
            "observation": self.observation or self.short_explanation,
            "analysis": self.analysis,
            "recommendation": self.recommendation,
            "packet_count": self.packet_count,
            "bytes_count": self.bytes_count,
            "duration": self.duration,
            "evidence": self.evidence or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TrafficEvent(Base):
    """
    Temporal network or security event generated during PCAP traffic analysis or live monitoring.
    """
    __tablename__ = "traffic_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    timestamp = Column(Float, nullable=False, index=True, comment="Unix epoch timestamp with sub-second precision")
    timestamp_str = Column(String(50), nullable=True)

    # HOST_DISCOVERED | PORT_DISCOVERED | SERVICE_DETECTED | DNS_ACTIVITY | HTTP_ACTIVITY |
    # TCP_CONNECTION | TCP_RESET | ICMP_ACTIVITY | HIGH_TRAFFIC | HIGH_PACKET_RATE |
    # EXCESSIVE_CONNECTIONS | POTENTIAL_PORT_SCAN | UNUSUAL_DNS_ACTIVITY | IOC_DETECTED | SECURITY_FINDING
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="INFO", index=True)  # INFO | LOW | MEDIUM | HIGH | CRITICAL

    # Network endpoints
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)

    # Narrative with strict factual separation
    short_explanation = Column(String(500), nullable=False)
    observation = Column(Text, nullable=True)
    analysis = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)

    # Metrics
    packet_count = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    packets_per_second = Column(Float, default=0.0)
    bytes_per_second = Column(Float, default=0.0)
    evidence = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    investigation = relationship("Investigation", backref="traffic_events")

    def __init__(self, **kwargs):
        if "description" in kwargs and "short_explanation" not in kwargs:
            kwargs["short_explanation"] = kwargs.pop("description")
        elif "description" in kwargs:
            kwargs.pop("description")
        if "timestamp" in kwargs and isinstance(kwargs["timestamp"], datetime):
            kwargs["timestamp"] = kwargs["timestamp"].timestamp()
        if "event_id" not in kwargs:
            import uuid
            kwargs["event_id"] = f"tev_{uuid.uuid4().hex[:12]}"
        super().__init__(**kwargs)

    @property
    def description(self):
        return self.short_explanation

    @description.setter
    def description(self, value):
        self.short_explanation = value

    __table_args__ = (
        Index("ix_traffic_events_inv_ts", "investigation_id", "timestamp"),
        Index("ix_traffic_events_type_ts", "event_type", "timestamp"),
        Index("ix_traffic_events_sev_ts", "severity", "timestamp"),
        Index("ix_traffic_events_endpoints", "source_ip", "destination_ip"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "short_explanation": self.short_explanation,
            "description": self.short_explanation,
            "observation": self.observation or self.short_explanation,
            "analysis": self.analysis,
            "recommendation": self.recommendation,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration": self.duration,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "evidence": self.evidence or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Finding(Base):
    """
    Structured, persistent security finding from scans or forensic analysis.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(64), unique=True, index=True, nullable=False)
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True)

    host = Column(String(45), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="TCP", nullable=True)
    service = Column(String(50), nullable=True)
    severity = Column(String(20), default="INFO", index=True)
    category = Column(String(50), default="Services", nullable=True)
    title = Column(String(255), nullable=False)

    observation = Column(Text, nullable=False)
    analysis = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    investigation_steps = Column(Text, nullable=True)
    learn_more = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "investigation_id": self.investigation_id,
            "host": self.host,
            "hostname": self.hostname,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "observation": self.observation,
            "analysis": self.analysis,
            "recommendation": self.recommendation,
            "investigation_steps": self.investigation_steps,
            "learn_more": self.learn_more or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
