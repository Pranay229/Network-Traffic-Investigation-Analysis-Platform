"""Host model — per-IP statistics for an investigation."""
import json
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Index
from app.database.base import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    ip_address = Column(String(45), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)    # resolved via DNS if present in capture
    mac_address = Column(String(17), nullable=True)

    # Traffic stats
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)

    # Derived
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    unique_dest_ips = Column(Integer, default=0)
    unique_src_ips = Column(Integer, default=0)
    unique_dest_ports = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)

    # Role heuristic: client | server | gateway | unknown
    role = Column(String(20), default="unknown")

    first_seen = Column(Float, nullable=True)
    last_seen = Column(Float, nullable=True)

    # JSON lists stored as text
    _protocols_json = Column("protocols_json", Text, default="[]")
    _top_ports_json = Column("top_ports_json", Text, default="[]")

    @property
    def protocols(self) -> list:
        try:
            return json.loads(self._protocols_json or "[]")
        except Exception:
            return []

    @protocols.setter
    def protocols(self, value: list) -> None:
        self._protocols_json = json.dumps(value)

    @property
    def top_ports(self) -> list:
        try:
            return json.loads(self._top_ports_json or "[]")
        except Exception:
            return []

    @top_ports.setter
    def top_ports(self, value: list) -> None:
        self._top_ports_json = json.dumps(value)

    __table_args__ = (
        Index("ix_hosts_inv_ip", "investigation_id", "ip_address", unique=True),
    )
