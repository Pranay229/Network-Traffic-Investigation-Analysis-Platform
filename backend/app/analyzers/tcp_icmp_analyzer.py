"""TCP and ICMP analyzers."""
import logging
from collections import defaultdict, Counter
from sqlalchemy.orm import Session
from app.models.record import ICMPRecord

logger = logging.getLogger(__name__)

ICMP_TYPE_NAMES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp", 14: "Timestamp Reply", 30: "Traceroute",
}


# ─── TCP Analyzer ────────────────────────────────────────────────────────────

def analyze_tcp(parsed_packets: list[dict]) -> dict:
    """
    Analyze TCP traffic from parsed packets.
    Returns statistics on flags, connections, and resets.
    """
    tcp_packets = [p for p in parsed_packets if p.get("protocol") == "TCP"]

    syn_count = 0
    syn_ack_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    psh_count = 0

    connection_attempts: dict[tuple, list] = defaultdict(list)  # (src, dst, dst_port) -> timestamps

    for p in tcp_packets:
        flags = p.get("tcp_flags") or ""
        ts = p.get("timestamp", 0)
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        dport = p.get("dst_port")

        if "SYN" in flags and "ACK" not in flags:
            syn_count += 1
            if src and dst and dport:
                connection_attempts[(src, dst, dport)].append(ts)
        elif "SYN" in flags and "ACK" in flags:
            syn_ack_count += 1
        elif "FIN" in flags:
            fin_count += 1
        elif "RST" in flags:
            rst_count += 1
        elif "PSH" in flags:
            psh_count += 1
        elif "ACK" in flags:
            ack_count += 1

    # Successful connections = pairs that have both SYN and SYN-ACK (approximate)
    successful_est = min(syn_count, syn_ack_count)

    # Most targeted destination ports
    dport_counter = Counter(
        p.get("dst_port") for p in tcp_packets if p.get("dst_port")
    )

    return {
        "total_tcp_packets": len(tcp_packets),
        "syn_count": syn_count,
        "syn_ack_count": syn_ack_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "estimated_connections": syn_count,
        "estimated_established": successful_est,
        "reset_connections": rst_count,
        "top_destination_ports": dport_counter.most_common(15),
    }


# ─── ICMP Analyzer ───────────────────────────────────────────────────────────

def analyze_icmp(db: Session, investigation_id: int, parsed_packets: list[dict]) -> dict:
    """Extract ICMP records from parsed packets and store in DB."""
    icmp_packets = [p for p in parsed_packets if p.get("protocol") == "ICMP"]

    icmp_records = []
    for p in icmp_packets:
        layers = p.get("_layers", {})

        def g(key, default=None):
            val = layers.get(key, default)
            if isinstance(val, list):
                return val[0] if val else default
            return val

        icmp_type_raw = g("icmp.type")
        icmp_code_raw = g("icmp.code")
        try:
            icmp_type = int(icmp_type_raw) if icmp_type_raw is not None else None
            icmp_code = int(icmp_code_raw) if icmp_code_raw is not None else None
        except Exception:
            icmp_type = None
            icmp_code = None

        type_name = ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}") if icmp_type is not None else "Unknown"

        rec = ICMPRecord(
            investigation_id=investigation_id,
            timestamp=p.get("timestamp"),
            timestamp_str=p.get("timestamp_str"),
            src_ip=p.get("src_ip"),
            dst_ip=p.get("dst_ip"),
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_type_name=type_name[:50],
            length=p.get("length", 0),
        )
        icmp_records.append(rec)

    if icmp_records:
        db.bulk_save_objects(icmp_records)
        db.commit()

    # Statistics
    type_counter = Counter(r.icmp_type_name for r in icmp_records)
    src_counter = Counter(r.src_ip for r in icmp_records if r.src_ip)
    echo_requests = sum(1 for r in icmp_records if r.icmp_type == 8)
    echo_replies = sum(1 for r in icmp_records if r.icmp_type == 0)

    logger.info(f"Extracted {len(icmp_records)} ICMP records for investigation {investigation_id}")

    return {
        "total_icmp_packets": len(icmp_records),
        "echo_requests": echo_requests,
        "echo_replies": echo_replies,
        "type_distribution": dict(type_counter),
        "top_sources": src_counter.most_common(10),
    }
