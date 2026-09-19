"""
DNS, HTTP, and ICMP record models.
Stored in separate tables for query efficiency.
"""
import json
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Index
from app.database.base import Base


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    packet_id = Column(Integer, nullable=True)

    timestamp = Column(Float, nullable=True)
    timestamp_str = Column(String(30), nullable=True)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)  # DNS server

    query_name = Column(String(255), nullable=True, index=True)
    query_type = Column(String(20), nullable=True)   # A, AAAA, MX, TXT, CNAME...
    query_class = Column(String(10), nullable=True)
    is_response = Column(Integer, default=0)         # 0=query, 1=response
    response_code = Column(String(20), nullable=True)
    _response_ips_json = Column("response_ips_json", Text, default="[]")
    ttl = Column(Integer, nullable=True)
    transaction_id = Column(Integer, nullable=True)

    @property
    def response_ips(self) -> list:
        try:
            return json.loads(self._response_ips_json or "[]")
        except Exception:
            return []

    @response_ips.setter
    def response_ips(self, value: list) -> None:
        self._response_ips_json = json.dumps(value)

    __table_args__ = (
        Index("ix_dns_inv_query", "investigation_id", "query_name"),
        Index("ix_dns_inv_src", "investigation_id", "src_ip"),
    )


class HTTPRecord(Base):
    __tablename__ = "http_records"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    packet_id = Column(Integer, nullable=True)

    timestamp = Column(Float, nullable=True)
    timestamp_str = Column(String(30), nullable=True)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)

    # HTTP fields
    method = Column(String(10), nullable=True)        # GET, POST, PUT...
    host = Column(String(255), nullable=True)
    uri = Column(String(2000), nullable=True)
    user_agent = Column(String(500), nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)
    is_request = Column(Integer, default=1)            # 1=request, 0=response

    __table_args__ = (
        Index("ix_http_inv_host", "investigation_id", "host"),
        Index("ix_http_inv_src", "investigation_id", "src_ip"),
    )


class ICMPRecord(Base):
    __tablename__ = "icmp_records"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    packet_id = Column(Integer, nullable=True)

    timestamp = Column(Float, nullable=True)
    timestamp_str = Column(String(30), nullable=True)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)

    icmp_type = Column(Integer, nullable=True)
    icmp_code = Column(Integer, nullable=True)
    icmp_type_name = Column(String(50), nullable=True)  # "Echo Request", "Echo Reply"...
    length = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_icmp_inv_src", "investigation_id", "src_ip"),
    )
