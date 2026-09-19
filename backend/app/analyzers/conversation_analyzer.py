"""
Conversation analyzer — groups packets into bidirectional flows.
A flow is identified by the 5-tuple: src_ip, dst_ip, protocol, src_port, dst_port.
For bidirectional flows, we normalize so lower IP is always 'src'.
"""
import logging
from collections import defaultdict
from sqlalchemy.orm import Session
from app.models.conversation import Conversation

logger = logging.getLogger(__name__)


def _flow_key(src_ip: str, dst_ip: str, protocol: str, src_port: int | None, dst_port: int | None) -> tuple:
    """Normalize flow key so A->B and B->A map to the same conversation."""
    ep_a = (src_ip or "", src_port or 0)
    ep_b = (dst_ip or "", dst_port or 0)
    if ep_a > ep_b:
        ep_a, ep_b = ep_b, ep_a
    return (ep_a[0], ep_b[0], protocol or "UNKNOWN", ep_a[1], ep_b[1])


def analyze_conversations(db: Session, investigation_id: int, parsed_packets: list[dict]) -> dict:
    """Build bidirectional conversations from packet list and store in DB."""
    flows: dict[tuple, dict] = {}

    for p in parsed_packets:
        src = p.get("src_ip") or ""
        dst = p.get("dst_ip") or ""
        proto = p.get("protocol", "UNKNOWN")
        sp = p.get("src_port")
        dp = p.get("dst_port")
        length = p.get("length", 0)
        ts = p.get("timestamp", 0)
        flags = p.get("tcp_flags") or ""

        if not src or not dst:
            continue

        key = _flow_key(src, dst, proto, sp, dp)
        if key not in flows:
            flows[key] = {
                "src_ip": key[0], "dst_ip": key[1], "protocol": key[2],
                "src_port": key[3], "dst_port": key[4],
                "packets_a_b": 0, "packets_b_a": 0,
                "bytes_a_b": 0, "bytes_b_a": 0,
                "start_time": None, "end_time": None,
                "syn": 0, "rst": 0, "fin": 0,
            }

        f = flows[key]
        if ts > 0:
            if f["start_time"] is None or ts < f["start_time"]:
                f["start_time"] = ts
            if f["end_time"] is None or ts > f["end_time"]:
                f["end_time"] = ts

        # Determine direction
        if src == key[0]:
            f["packets_a_b"] += 1
            f["bytes_a_b"] += length
        else:
            f["packets_b_a"] += 1
            f["bytes_b_a"] += length

        if "SYN" in flags:
            f["syn"] += 1
        if "RST" in flags:
            f["rst"] += 1
        if "FIN" in flags:
            f["fin"] += 1

    conv_objects = []
    for key, f in flows.items():
        duration = (f["end_time"] - f["start_time"]) if (f["start_time"] and f["end_time"]) else 0.0
        c = Conversation(
            investigation_id=investigation_id,
            src_ip=f["src_ip"][:45],
            dst_ip=f["dst_ip"][:45],
            src_port=f["src_port"] or None,
            dst_port=f["dst_port"] or None,
            protocol=f["protocol"][:20],
            packets_a_to_b=f["packets_a_b"],
            packets_b_to_a=f["packets_b_a"],
            total_packets=f["packets_a_b"] + f["packets_b_a"],
            bytes_a_to_b=f["bytes_a_b"],
            bytes_b_to_a=f["bytes_b_a"],
            total_bytes=f["bytes_a_b"] + f["bytes_b_a"],
            start_time=f["start_time"],
            end_time=f["end_time"],
            duration=round(duration, 4),
            syn_count=f["syn"],
            rst_count=f["rst"],
            fin_count=f["fin"],
        )
        conv_objects.append(c)

    if conv_objects:
        db.bulk_save_objects(conv_objects)
        db.commit()

    logger.info(f"Found {len(flows)} conversations for investigation {investigation_id}")
    return {"total_conversations": len(flows)}
