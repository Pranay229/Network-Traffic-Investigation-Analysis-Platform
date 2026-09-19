"""IOC (Indicator of Compromise) model."""
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Index
from app.database.base import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Type: ipv4 | ipv6 | domain | url | port | user_agent
    ioc_type = Column(String(20), nullable=False, index=True)
    value = Column(String(2000), nullable=False)

    first_seen = Column(Float, nullable=True)
    last_seen = Column(Float, nullable=True)
    first_seen_str = Column(String(30), nullable=True)
    last_seen_str = Column(String(30), nullable=True)

    source_ip = Column(String(45), nullable=True)
    context = Column(Text, nullable=True)
    occurrence_count = Column(Integer, default=1)

    # NOTE: These are OBSERVED indicators, NOT confirmed malicious.
    # Enrichment with threat intel is a future Phase 3 feature.

    __table_args__ = (
        Index("ix_iocs_inv_type_value", "investigation_id", "ioc_type", "value"),
    )
