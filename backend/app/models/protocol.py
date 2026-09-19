"""
Protocol Telemetry Models: ARP Records and TLS Handshake Metadata
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Defensive protocol telemetry storage supporting:
- Core Network: IPv4, IPv6, TCP, UDP, ICMP, ARP
- Application Protocols: DNS, HTTP, HTTPS/TLS, DHCP, SSH, FTP, SMTP, SMB, NTP, SNMP
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship
from app.database.base import Base


class ARPRecord(Base):
    """
    Observable ARP transactions (Request / Reply) capturing IP-to-MAC resolution.
    Used for verifying network bindings and detecting address mapping inconsistencies.
    """
    __tablename__ = "arp_records"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    timestamp = Column(Float, nullable=False, index=True)
    timestamp_str = Column(String(50), nullable=True)

    opcode = Column(String(20), default="REQUEST")  # REQUEST | REPLY
    sender_mac = Column(String(24), nullable=True, index=True)
    sender_ip = Column(String(45), nullable=True, index=True)
    target_mac = Column(String(24), nullable=True)
    target_ip = Column(String(45), nullable=True, index=True)

    is_inconsistent = Column(Boolean, default=False, index=True)
    inconsistency_note = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", backref="arp_records")

    __table_args__ = (
        Index("ix_arp_inv_ts", "investigation_id", "timestamp"),
        Index("ix_arp_sender", "sender_ip", "sender_mac"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "opcode": self.opcode,
            "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "is_inconsistent": self.is_inconsistent,
            "inconsistency_note": self.inconsistency_note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TLSMetadata(Base):
    """
    Unencrypted TLS handshake parameters (SNI, negotiated protocol version, certificate metadata)
    without decrypting encrypted payload streams.
    """
    __tablename__ = "tls_metadata"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    timestamp = Column(Float, nullable=False, index=True)
    timestamp_str = Column(String(50), nullable=True)

    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, default=443, nullable=True)

    version = Column(String(32), default="TLSv1.3", nullable=True)
    sni = Column(String(255), nullable=True, index=True)  # Server Name Indication
    cipher_suite = Column(String(100), nullable=True)
    cert_subject = Column(String(255), nullable=True)
    cert_issuer = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", backref="tls_metadata")

    __table_args__ = (
        Index("ix_tls_inv_ts", "investigation_id", "timestamp"),
        Index("ix_tls_sni", "sni"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "version": self.version,
            "sni": self.sni,
            "cipher_suite": self.cipher_suite,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
