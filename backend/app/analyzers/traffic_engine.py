"""
Reusable Traffic Analysis Engine
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Calculates real-time flow and volumetric traffic metrics with multi-time-window slicing:
- Windows: 5-second, 30-second, 1-minute, 5-minute
- Metrics: PPS, BPS, connections, connection rate, avg packet size, duration, top talkers, endpoints, protocols
"""
import math
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

WINDOW_SECONDS = {
    "5s": 5.0,
    "30s": 30.0,
    "1m": 60.0,
    "5m": 300.0,
}


def _format_bytes(bytes_count: int) -> str:
    if bytes_count >= 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"
    if bytes_count >= 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.2f} MB"
    if bytes_count >= 1024:
        return f"{bytes_count / 1024:.2f} KB"
    return f"{bytes_count} B"


def _format_rate(bps: float) -> str:
    if bps >= 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps:.2f} B/s"


def _ts_to_iso(ts: Optional[float]) -> Optional[str]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def compute_traffic_engine_metrics(
    packets: List[Any],
    window: str = "30s"
) -> Dict[str, Any]:
    """
    Computes volumetric telemetry and time-bucketed window slices from packet stream.
    """
    if not packets:
        return {
            "summary": {
                "total_packets": 0,
                "total_bytes": 0,
                "total_bytes_str": "0 B",
                "duration_seconds": 0.0,
                "packets_per_second": 0.0,
                "bytes_per_second": 0.0,
                "average_throughput_str": "0 B/s",
                "average_packet_size": 0.0,
                "connection_count": 0,
                "connection_rate": 0.0,
                "first_observed": None,
                "last_observed": None,
            },
            "window_size_seconds": WINDOW_SECONDS.get(window, 30.0),
            "window_label": window,
            "time_windows": [],
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_conversations": [],
            "top_protocols": [],
            "top_ports": [],
        }

    # Normalize packets whether passed as dicts or ORM/mock objects
    norm_packets = [
        p if isinstance(p, dict) else {
            "length": getattr(p, "length", 0),
            "timestamp": getattr(p, "timestamp", 0.0),
            "src_ip": getattr(p, "src_ip", None),
            "dst_ip": getattr(p, "dst_ip", None),
            "src_port": getattr(p, "src_port", None),
            "dst_port": getattr(p, "dst_port", None),
            "protocol": getattr(p, "protocol", "OTHER"),
            "tcp_flags": getattr(p, "tcp_flags", ""),
        }
        for p in packets
    ]
    packets = norm_packets

    window_len = WINDOW_SECONDS.get(window, 30.0)

    total_packets = len(packets)
    total_bytes = sum(p.get("length", 0) for p in packets)
    timestamps = [p.get("timestamp") for p in packets if p.get("timestamp") and p["timestamp"] > 0]

    min_ts = min(timestamps) if timestamps else 0.0
    max_ts = max(timestamps) if timestamps else min_ts
    total_duration = max(max_ts - min_ts, 0.001) if (min_ts and max_ts and max_ts > min_ts) else 1.0

    overall_pps = round(total_packets / total_duration, 2)
    overall_bps = round(total_bytes / total_duration, 2)
    avg_packet_size = round(total_bytes / total_packets, 2) if total_packets > 0 else 0.0

    # 1. Connection tracking (TCP SYN packets)
    syn_packets = [
        p for p in packets
        if "SYN" in (p.get("tcp_flags") or "") and "ACK" not in (p.get("tcp_flags") or "")
    ]
    connection_count = len(syn_packets)
    conn_rate = round(connection_count / total_duration, 2)

    # 2. Aggregations for Top Talkers, Ports, Conversations
    src_bytes = Counter()
    dst_bytes = Counter()
    proto_bytes = Counter()
    port_bytes = Counter()
    conv_bytes = Counter()

    # Time-window buckets: bucket_idx = int((ts - min_ts) // window_len)
    window_buckets = defaultdict(lambda: {
        "packet_count": 0,
        "total_bytes": 0,
        "syn_count": 0,
        "start_time": 0.0,
        "end_time": 0.0,
    })

    for p in packets:
        length = p.get("length", 0)
        ts = p.get("timestamp") or min_ts
        src = p.get("src_ip") or "Unknown"
        dst = p.get("dst_ip") or "Unknown"
        sp = p.get("src_port")
        dp = p.get("dst_port")
        proto = (p.get("protocol") or "OTHER").upper()
        flags = p.get("tcp_flags") or ""

        src_bytes[src] += length
        dst_bytes[dst] += length
        proto_bytes[proto] += length
        if dp:
            port_bytes[dp] += length
        if sp:
            port_bytes[sp] += length

        # Conversation pair
        ep1, ep2 = (src, dst) if src < dst else (dst, src)
        conv_bytes[(ep1, ep2, proto)] += length

        # Bucket calculation
        if min_ts > 0 and ts >= min_ts:
            bucket_idx = int((ts - min_ts) // window_len)
            b = window_buckets[bucket_idx]
            b["packet_count"] += 1
            b["total_bytes"] += length
            if "SYN" in flags and "ACK" not in flags:
                b["syn_count"] += 1
            if b["start_time"] == 0.0 or ts < b["start_time"]:
                b["start_time"] = ts
            if ts > b["end_time"]:
                b["end_time"] = ts

    # Build Top Items
    top_sources = [
        {"ip": ip, "bytes": b, "bytes_str": _format_bytes(b), "percentage": round(b / total_bytes * 100, 2) if total_bytes else 0}
        for ip, b in src_bytes.most_common(10)
    ]
    top_destinations = [
        {"ip": ip, "bytes": b, "bytes_str": _format_bytes(b), "percentage": round(b / total_bytes * 100, 2) if total_bytes else 0}
        for ip, b in dst_bytes.most_common(10)
    ]
    top_protocols = [
        {"protocol": proto, "bytes": b, "bytes_str": _format_bytes(b), "percentage": round(b / total_bytes * 100, 2) if total_bytes else 0}
        for proto, b in proto_bytes.most_common(10)
    ]
    top_ports = [
        {"port": port, "bytes": b, "bytes_str": _format_bytes(b), "percentage": round(b / total_bytes * 100, 2) if total_bytes else 0}
        for port, b in port_bytes.most_common(10)
    ]
    top_conversations = [
        {
            "endpoint_a": conv[0],
            "endpoint_b": conv[1],
            "protocol": conv[2],
            "bytes": b,
            "bytes_str": _format_bytes(b),
            "percentage": round(b / total_bytes * 100, 2) if total_bytes else 0
        }
        for conv, b in conv_bytes.most_common(10)
    ]

    # Format time windows
    time_windows: List[Dict[str, Any]] = []
    for idx in sorted(window_buckets.keys()):
        b = window_buckets[idx]
        dur = max(b["end_time"] - b["start_time"], 1.0)
        pps = round(b["packet_count"] / dur, 2)
        bps = round(b["total_bytes"] / dur, 2)
        time_windows.append({
            "window_index": idx,
            "start_time": b["start_time"],
            "start_time_str": _ts_to_iso(b["start_time"]),
            "end_time": b["end_time"],
            "end_time_str": _ts_to_iso(b["end_time"]),
            "packet_count": b["packet_count"],
            "total_bytes": b["total_bytes"],
            "total_bytes_str": _format_bytes(b["total_bytes"]),
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "transfer_rate_str": _format_rate(bps),
            "syn_connections": b["syn_count"],
        })

    return {
        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_bytes_str": _format_bytes(total_bytes),
            "duration_seconds": round(total_duration, 2),
            "packets_per_second": overall_pps,
            "packets_per_sec": overall_pps,
            "bytes_per_second": overall_bps,
            "bytes_per_sec": overall_bps,
            "average_throughput_str": _format_rate(overall_bps),
            "average_packet_size": avg_packet_size,
            "avg_packet_size": avg_packet_size,
            "connection_count": connection_count,
            "connection_rate": conn_rate,
            "first_observed": min_ts,
            "first_observed_str": _ts_to_iso(min_ts),
            "last_observed": max_ts,
            "last_observed_str": _ts_to_iso(max_ts),
        },
        "window": window,
        "window_size_seconds": window_len,
        "window_label": window,
        "buckets": time_windows,
        "time_windows": time_windows,
        "top_source_ips": top_sources,
        "top_destination_ips": top_destinations,
        "top_conversations": top_conversations,
        "top_protocols": top_protocols,
        "top_ports": top_ports,
    }


def calculate_traffic_metrics(packets: List[Any]) -> Dict[str, Any]:
    """Returns basic volumetric summary of packets."""
    res = compute_traffic_engine_metrics(packets, window="30s")
    s = res["summary"]
    return {
        "total_packets": s["total_packets"],
        "total_bytes": s["total_bytes"],
        "avg_packet_size": s["average_packet_size"],
        "packets_per_sec": s["packets_per_second"],
        "bytes_per_sec": s["bytes_per_second"],
        "duration": s["duration_seconds"],
    }


def aggregate_time_windows(packets: List[Any], window: str = "30s") -> Dict[str, Any]:
    """Buckets and aggregates telemetry across specific window intervals."""
    res = compute_traffic_engine_metrics(packets, window=window)
    return {
        "window": window,
        "summary": res["summary"],
        "buckets": res["time_windows"],
        "top_sources": res["top_source_ips"],
        "top_destinations": res["top_destination_ips"],
        "top_protocols": res["top_protocols"],
        "top_ports": res["top_ports"],
    }

