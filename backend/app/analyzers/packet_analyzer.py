"""
Packet analyzer — parses TShark JSON output and stores packets in the database.
Also computes per-protocol counts and traffic timeline data.
"""
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.packet import Packet
from app.models.investigation import Investigation

logger = logging.getLogger(__name__)

ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    30: "Traceroute",
}


def _get_nested(data: dict, *keys: str, default=None):
    """Safely get nested dict value."""
    for k in keys:
        if isinstance(data, dict):
            data = data.get(k, default)
        else:
            return default
    return data


def _decode_tcp_flags(flag_hex: str) -> str:
    """Convert hex TCP flags to readable label."""
    if not flag_hex:
        return ""
    try:
        flags = int(flag_hex, 16) if flag_hex.startswith("0x") else int(flag_hex, 16)
        labels = []
        if flags & 0x002:
            labels.append("SYN")
        if flags & 0x010:
            labels.append("ACK")
        if flags & 0x001:
            labels.append("FIN")
        if flags & 0x004:
            labels.append("RST")
        if flags & 0x008:
            labels.append("PSH")
        if flags & 0x020:
            labels.append("URG")
        return "-".join(labels) if labels else flag_hex
    except Exception:
        return flag_hex or ""


def _determine_protocol(layers: dict) -> str:
    """Determine the highest-level protocol from frame.protocols field."""
    protocols_str = _get_nested(layers, "frame.protocols", default="")
    if isinstance(protocols_str, list):
        protocols_str = protocols_str[0] if protocols_str else ""
    protocols = protocols_str.lower().split(":")

    # Priority order — most specific first
    priority = ["http", "dns", "tls", "ssl", "icmp", "icmpv6", "tcp", "udp", "arp", "ipv6", "ip", "eth"]
    for p in priority:
        if p in protocols:
            return p.upper()
    return protocols[-1].upper() if protocols else "UNKNOWN"


def parse_tshark_packet(raw: dict) -> dict[str, Any] | None:
    """
    Parse a single TShark JSON packet into a flat dict.
    Returns None if the packet cannot be meaningfully parsed.
    """
    try:
        layers = raw.get("_source", {}).get("layers", {})
        if not layers:
            # Also try direct format
            layers = raw.get("layers", {})

        def g(key, default=None):
            val = layers.get(key, default)
            if isinstance(val, list):
                return val[0] if val else default
            return val

        # Timestamps
        ts_epoch = g("frame.time_epoch")
        ts_str = g("frame.time", "")
        try:
            ts_float = float(ts_epoch) if ts_epoch else 0.0
        except Exception:
            ts_float = 0.0

        # IPs
        src_ip = g("ip.src") or g("ipv6.src")
        dst_ip = g("ip.dst") or g("ipv6.dst")

        # Ports
        tcp_sp = g("tcp.srcport")
        tcp_dp = g("tcp.dstport")
        udp_sp = g("udp.srcport")
        udp_dp = g("udp.dstport")

        src_port = None
        dst_port = None
        if tcp_sp is not None:
            try:
                src_port = int(tcp_sp)
                dst_port = int(tcp_dp) if tcp_dp else None
            except Exception:
                pass
        elif udp_sp is not None:
            try:
                src_port = int(udp_sp)
                dst_port = int(udp_dp) if udp_dp else None
            except Exception:
                pass

        # Protocol
        protocol = _determine_protocol(layers)

        # TCP flags
        tcp_flags_raw = g("tcp.flags")
        tcp_flags = _decode_tcp_flags(tcp_flags_raw) if tcp_flags_raw else None

        # Frame info
        frame_num = g("frame.number", 0)
        try:
            frame_num = int(frame_num)
        except Exception:
            frame_num = 0

        length = g("frame.len", 0)
        try:
            length = int(length)
        except Exception:
            length = 0

        info = g("_ws.col.Info", "")
        if isinstance(info, list):
            info = info[0] if info else ""

        precise_ts_str = str(ts_str)[:30]
        if ts_float > 0:
            try:
                precise_ts_str = datetime.utcfromtimestamp(ts_float).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            except Exception:
                precise_ts_str = str(ts_str)[:30]

        return {
            "frame_number": frame_num,
            "timestamp": ts_float,
            "timestamp_str": precise_ts_str,
            "src_ip": str(src_ip)[:45] if src_ip else None,
            "dst_ip": str(dst_ip)[:45] if dst_ip else None,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol[:20] if protocol else "UNKNOWN",
            "length": length,
            "tcp_flags": tcp_flags[:20] if tcp_flags else None,
            "info": str(info)[:500] if info else None,
            # Extra fields for sub-analyzers (not stored in Packet table)
            "_layers": layers,
        }
    except Exception as e:
        logger.debug(f"Packet parse error: {e}")
        return None


def store_packets(
    db: Session,
    investigation_id: int,
    raw_packets: list[dict],
    batch_size: int = 500,
) -> tuple[list[dict], dict]:
    """
    Parse raw TShark JSON packets, store in DB, and return parsed packets + summary.
    Returns (parsed_packets, summary_stats)
    """
    parsed = []
    skipped = 0

    # Protocol counters
    proto_counts: dict[str, int] = defaultdict(int)
    timeline_buckets: dict[int, int] = defaultdict(int)  # unix_second -> packet_count
    total_bytes = 0
    min_ts: float | None = None
    max_ts: float | None = None

    db_packets = []
    for raw in raw_packets:
        p = parse_tshark_packet(raw)
        if p is None:
            skipped += 1
            continue

        parsed.append(p)
        proto_counts[p["protocol"]] += 1
        total_bytes += p["length"]

        if p["timestamp"] > 0:
            ts_sec = int(p["timestamp"])
            timeline_buckets[ts_sec] += 1
            if min_ts is None or p["timestamp"] < min_ts:
                min_ts = p["timestamp"]
            if max_ts is None or p["timestamp"] > max_ts:
                max_ts = p["timestamp"]

        db_packets.append(Packet(
            investigation_id=investigation_id,
            frame_number=p["frame_number"],
            timestamp=p["timestamp"],
            timestamp_str=p["timestamp_str"],
            src_ip=p["src_ip"],
            dst_ip=p["dst_ip"],
            src_port=p["src_port"],
            dst_port=p["dst_port"],
            protocol=p["protocol"],
            length=p["length"],
            tcp_flags=p["tcp_flags"],
            info=p["info"],
        ))

        # Bulk insert in batches
        if len(db_packets) >= batch_size:
            db.bulk_save_objects(db_packets)
            db.commit()
            db_packets = []

    if db_packets:
        db.bulk_save_objects(db_packets)
        db.commit()

    duration = (max_ts - min_ts) if (min_ts and max_ts) else 0.0
    pps = len(parsed) / duration if duration > 0 else 0.0

    summary = {
        "total_packets": len(parsed),
        "skipped_packets": skipped,
        "total_bytes": total_bytes,
        "protocol_counts": dict(proto_counts),
        "timeline_buckets": dict(timeline_buckets),
        "capture_start": min_ts,
        "capture_end": max_ts,
        "capture_duration": duration,
        "packets_per_second": round(pps, 2),
    }

    logger.info(f"Stored {len(parsed)} packets ({skipped} skipped) for investigation {investigation_id}")
    return parsed, summary
