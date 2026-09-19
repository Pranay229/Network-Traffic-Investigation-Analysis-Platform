"""
Packet model — stores individual packet metadata captured during network investigations.

Notes:
  - Full packet payloads are NOT stored for performance and privacy reasons.
  - Only metadata fields necessary for forensic analysis are persisted.
  - Sensitive data (e.g. raw HTTP bodies, credentials) must never be recorded here.

Platform : Nova Cyber Spark™ — Network Traffic Investigation & Analysis
Founder  : Pranay Kumar Mallem
Copyright: © 2026 Nova Cyber Spark™. All rights reserved.
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
    func,
)
from sqlalchemy.orm import relationship, Session

from app.database.base import Base

logger = logging.getLogger("nova.packet")


class Packet(Base):
    """
    Represents a single network packet observation linked to an Investigation.

    Columns
    -------
    id                : Primary key (auto-incremented).
    investigation_id  : FK → investigations.id (CASCADE delete).
    frame_number      : Sequential frame number from the PCAP/capture.
    timestamp         : Unix epoch float (high-precision).
    timestamp_str     : Human-readable timestamp string (e.g. "2026-09-17 12:00:00.000").
    src_ip            : Source IP address (IPv4 or IPv6, max 45 chars).
    dst_ip            : Destination IP address.
    src_port          : Source TCP/UDP port (nullable for non-TCP/UDP).
    dst_port          : Destination TCP/UDP port.
    protocol          : Transport/application protocol (e.g. TCP, UDP, ICMP, DNS).
    length            : Packet length in bytes.
    tcp_flags         : Decoded TCP control flags (e.g. "SYN", "SYN-ACK", "FIN").
    info              : Short human-readable summary (similar to Wireshark's Info column).
    direction         : Inbound / Outbound / Unknown (relative to investigation scope).
    ttl               : IP Time-To-Live value.
    window_size       : TCP window size (nullable).
    checksum_valid    : Whether the packet checksum was verified (nullable).
    app_protocol      : Application-layer protocol hint (e.g. HTTP, TLS, DNS).
    payload_hash      : SHA-256 hash of the payload for integrity tracking (no raw payload stored).
    is_flagged        : Quick-access flag for analyst-marked suspicious packets.
    analyst_note      : Short analyst annotation added during investigation.
    created_at        : DB record creation timestamp (UTC).
    """

    __tablename__ = "packets"

    # ── Primary Key ──────────────────────────────────────────────────────────
    id = Column(Integer, primary_key=True, index=True)

    # ── Relationship ─────────────────────────────────────────────────────────
    investigation_id = Column(
        Integer,
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent investigation that captured this packet.",
    )
    investigation = relationship(
        "Investigation",
        backref="packets",
        lazy="select",
    )

    # ── Frame / Capture Metadata ──────────────────────────────────────────────
    frame_number = Column(
        Integer,
        nullable=False,
        comment="Sequential frame number within the capture file.",
    )
    timestamp = Column(
        Float,
        nullable=False,
        comment="Unix epoch timestamp with sub-second precision.",
    )
    timestamp_str = Column(
        String(30),
        nullable=True,
        comment="Human-readable timestamp (e.g. 2026-09-17 12:00:00.123).",
    )

    # ── Network Layer ─────────────────────────────────────────────────────────
    src_ip = Column(
        String(45),
        nullable=True,
        comment="Source IP address — IPv4 (max 15 chars) or IPv6 (max 39 chars).",
    )
    dst_ip = Column(
        String(45),
        nullable=True,
        comment="Destination IP address.",
    )
    ttl = Column(
        Integer,
        nullable=True,
        comment="IP Time-To-Live field value.",
    )

    # ── Transport Layer ───────────────────────────────────────────────────────
    src_port = Column(
        Integer,
        nullable=True,
        comment="Source port (TCP/UDP only).",
    )
    dst_port = Column(
        Integer,
        nullable=True,
        comment="Destination port (TCP/UDP only).",
    )
    protocol = Column(
        String(20),
        nullable=True,
        index=True,
        comment="Transport protocol: TCP, UDP, ICMP, ARP, etc.",
    )
    tcp_flags = Column(
        String(30),
        nullable=True,
        comment="Decoded TCP flags string, e.g. 'SYN', 'SYN-ACK', 'FIN-ACK'.",
    )
    window_size = Column(
        Integer,
        nullable=True,
        comment="TCP receive window size.",
    )
    checksum_valid = Column(
        Boolean,
        nullable=True,
        comment="True if the packet checksum was verified correct; None if not checked.",
    )

    # ── Packet Properties ─────────────────────────────────────────────────────
    length = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Total packet length in bytes.",
    )
    direction = Column(
        String(10),
        nullable=True,
        default="unknown",
        comment="Relative direction: inbound, outbound, or unknown.",
    )

    # ── Application Layer ─────────────────────────────────────────────────────
    app_protocol = Column(
        String(30),
        nullable=True,
        comment="Inferred application-layer protocol, e.g. HTTP, TLS, DNS, SMTP.",
    )
    info = Column(
        String(500),
        nullable=True,
        comment="Short human-readable summary line (Wireshark-style Info column).",
    )

    # ── Security / Integrity ──────────────────────────────────────────────────
    payload_hash = Column(
        String(64),
        nullable=True,
        comment="SHA-256 hex digest of the raw payload — no raw bytes stored.",
    )
    is_flagged = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Quick analyst flag for suspicious/noteworthy packets.",
    )
    analyst_note = Column(
        Text,
        nullable=True,
        comment="Short analyst annotation attached during investigation review.",
    )

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        comment="UTC timestamp when this record was inserted into the database.",
    )

    # ── Composite Indexes ─────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_packets_inv_src",   "investigation_id", "src_ip"),
        Index("ix_packets_inv_dst",   "investigation_id", "dst_ip"),
        Index("ix_packets_inv_proto", "investigation_id", "protocol"),
        Index("ix_packets_inv_ts",    "investigation_id", "timestamp"),
        Index("ix_packets_flagged",   "investigation_id", "is_flagged"),
        {"comment": "Individual packet observations — no raw payload stored."},
    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"<Packet id={self.id} "
            f"frame={self.frame_number} "
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} "
            f"{self.protocol} len={self.length}>"
        )

    def to_dict(self) -> dict:
        """Serialises the packet to a dictionary safe for JSON responses."""
        return {
            "id":               self.id,
            "investigation_id": self.investigation_id,
            "frame_number":     self.frame_number,
            "timestamp":        self.timestamp,
            "timestamp_str":    self.timestamp_str,
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "src_port":         self.src_port,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "tcp_flags":        self.tcp_flags,
            "window_size":      self.window_size,
            "checksum_valid":   self.checksum_valid,
            "length":           self.length,
            "direction":        self.direction,
            "ttl":              self.ttl,
            "app_protocol":     self.app_protocol,
            "info":             self.info,
            "payload_hash":     self.payload_hash,
            "is_flagged":       self.is_flagged,
            "analyst_note":     self.analyst_note,
            "created_at":       self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def log_create(cls, packet: "Packet") -> None:
        """Emit a structured log entry when a packet record is persisted."""
        logger.debug(
            "Packet persisted: inv=%s frame=%s %s:%s->%s:%s proto=%s len=%s flagged=%s",
            packet.investigation_id,
            packet.frame_number,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
            packet.length,
            packet.is_flagged,
        )
