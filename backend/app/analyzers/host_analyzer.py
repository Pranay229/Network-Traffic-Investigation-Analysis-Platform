"""
Host analyzer — computes per-IP statistics from parsed packets.
Determines host roles (client/server/gateway) based on traffic patterns.
"""
import logging
from collections import defaultdict
from sqlalchemy.orm import Session
from app.models.host import Host

logger = logging.getLogger(__name__)


def _infer_role(src_packet_count: int, dst_packet_count: int, unique_src_count: int) -> str:
    """
    Heuristic role inference:
    - Server: receives many connections from many sources
    - Client: initiates many connections, few incoming
    - Gateway: high traffic in both directions
    """
    total = src_packet_count + dst_packet_count
    if total == 0:
        return "unknown"

    incoming_ratio = dst_packet_count / total
    if unique_src_count > 5 and incoming_ratio > 0.6:
        return "server"
    elif src_packet_count > dst_packet_count * 2:
        return "client"
    elif src_packet_count > 100 and dst_packet_count > 100:
        return "gateway"
    return "client"


def analyze_hosts(db: Session, investigation_id: int, parsed_packets: list[dict]) -> dict:
    """
    Build host statistics from parsed packet list and store in DB.
    Returns summary statistics.
    """
    # Accumulate stats per IP
    stats: dict[str, dict] = {}

    def get_host(ip: str) -> dict:
        if ip not in stats:
            stats[ip] = {
                "packets_sent": 0, "packets_received": 0,
                "bytes_sent": 0, "bytes_received": 0,
                "dest_ips": set(), "src_ips": set(),
                "dest_ports": set(), "protocols": set(),
                "first_seen": None, "last_seen": None,
                "connection_count": 0,
            }
        return stats[ip]

    for p in parsed_packets:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        length = p.get("length", 0)
        ts = p.get("timestamp", 0)
        proto = p.get("protocol", "UNKNOWN")
        dst_port = p.get("dst_port")

        if src:
            h = get_host(src)
            h["packets_sent"] += 1
            h["bytes_sent"] += length
            h["protocols"].add(proto)
            if dst:
                h["dest_ips"].add(dst)
            if dst_port:
                h["dest_ports"].add(dst_port)
            if ts > 0:
                if h["first_seen"] is None or ts < h["first_seen"]:
                    h["first_seen"] = ts
                if h["last_seen"] is None or ts > h["last_seen"]:
                    h["last_seen"] = ts

        if dst:
            h = get_host(dst)
            h["packets_received"] += 1
            h["bytes_received"] += length
            h["protocols"].add(proto)
            if src:
                h["src_ips"].add(src)
            if ts > 0:
                if h["first_seen"] is None or ts < h["first_seen"]:
                    h["first_seen"] = ts
                if h["last_seen"] is None or ts > h["last_seen"]:
                    h["last_seen"] = ts

        # Count TCP SYN (new connection attempts)
        flags = p.get("tcp_flags", "")
        if flags and "SYN" in flags and "ACK" not in flags:
            if src:
                get_host(src)["connection_count"] += 1

    # Store host records in DB
    host_objects = []
    for ip, s in stats.items():
        total_packets = s["packets_sent"] + s["packets_received"]
        total_bytes = s["bytes_sent"] + s["bytes_received"]
        role = _infer_role(s["packets_sent"], s["packets_received"], len(s["src_ips"]))

        # Top 10 ports sorted by frequency (we just have the set here, so list them)
        top_ports = sorted(s["dest_ports"])[:20]

        h = Host(
            investigation_id=investigation_id,
            ip_address=ip[:45],
            packets_sent=s["packets_sent"],
            packets_received=s["packets_received"],
            bytes_sent=s["bytes_sent"],
            bytes_received=s["bytes_received"],
            total_packets=total_packets,
            total_bytes=total_bytes,
            unique_dest_ips=len(s["dest_ips"]),
            unique_src_ips=len(s["src_ips"]),
            unique_dest_ports=len(s["dest_ports"]),
            connection_count=s["connection_count"],
            role=role,
            first_seen=s["first_seen"],
            last_seen=s["last_seen"],
        )
        h.protocols = list(s["protocols"])
        h.top_ports = top_ports
        host_objects.append(h)

    if host_objects:
        db.bulk_save_objects(host_objects)
        db.commit()

    logger.info(f"Analyzed {len(stats)} unique hosts for investigation {investigation_id}")
    return {
        "unique_hosts": len(stats),
        "top_talkers": sorted(
            [{"ip": ip, "packets": s["packets_sent"] + s["packets_received"]}
             for ip, s in stats.items()],
            key=lambda x: x["packets"], reverse=True
        )[:10],
    }
