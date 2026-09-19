"""Conversation model — bidirectional flow between two endpoints."""
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Index
from app.database.base import Base


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=False)

    packets_a_to_b = Column(Integer, default=0)
    packets_b_to_a = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    bytes_a_to_b = Column(Integer, default=0)
    bytes_b_to_a = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)

    start_time = Column(Float, nullable=True)
    end_time = Column(Float, nullable=True)
    duration = Column(Float, default=0.0)  # seconds

    # TCP specific
    syn_count = Column(Integer, default=0)
    rst_count = Column(Integer, default=0)
    fin_count = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_conv_inv_flow", "investigation_id", "src_ip", "dst_ip", "protocol"),
    )
