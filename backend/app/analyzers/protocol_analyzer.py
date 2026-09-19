"""
Protocol Analysis Engine for Network Security Investigation and Monitoring Platform
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Analyzes and extracts structured telemetry for:
- CORE NETWORK: IPv4, IPv6, TCP, UDP, ICMP, ARP
- APPLICATION PROTOCOLS: DNS, HTTP, HTTPS/TLS, DHCP, SSH, FTP, SMTP, SMB, NTP, SNMP

Strict evidence-based classification without speculative or alarmist claims.
"""
import logging
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.protocol import ARPRecord, TLSMetadata

logger = logging.getLogger("nova.protocol_analyzer")

# Standard port associations for heuristic application protocol detection
PORT_PROTOCOL_MAP = {
    53: "DNS",
    5353: "mDNS",
    80: "HTTP",
    8080: "HTTP",
    8000: "HTTP",
    8888: "HTTP",
    443: "HTTPS/TLS",
    8443: "HTTPS/TLS",
    67: "DHCP",
    68: "DHCP",
    22: "SSH",
    20: "FTP-Data",
    21: "FTP",
    25: "SMTP",
    465: "SMTP/TLS",
    587: "SMTP",
    139: "SMB",
    445: "SMB",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-Trap",
}

SUPPORTED_PROTOCOLS = [
    "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP",
    "DNS", "HTTP", "HTTPS/TLS", "DHCP", "SSH",
    "FTP", "SMTP", "SMB", "NTP", "SNMP"
]

PROTOCOL_CATEGORIES = {
    "CORE_NETWORK": ["IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"],
    "WEB_TRAFFIC": ["HTTP", "HTTPS/TLS"],
    "NETWORK_SERVICES": ["DNS", "DHCP", "NTP", "SNMP"],
    "REMOTE_ACCESS": ["SSH", "FTP", "SMTP", "SMB"],
}


def classify_packet_protocol(packet: Any) -> str:
    """Classifies primary application or network protocol of a packet object or dict."""
    p_dict = packet if isinstance(packet, dict) else {
        "protocol": getattr(packet, "protocol", None),
        "app_protocol": getattr(packet, "app_protocol", None),
        "info": getattr(packet, "info", None),
        "src_ip": getattr(packet, "src_ip", None),
        "dst_ip": getattr(packet, "dst_ip", None),
        "src_port": getattr(packet, "src_port", None),
        "dst_port": getattr(packet, "dst_port", None),
        "tcp_flags": getattr(packet, "tcp_flags", None),
    }
    all_protos = classify_packet_protocols(p_dict)
    # Prefer highest-layer application protocols if present
    for cat in ["REMOTE_ACCESS", "NETWORK_SERVICES", "WEB_TRAFFIC"]:
        for p in PROTOCOL_CATEGORIES[cat]:
            if p in all_protos:
                return p
    for p in all_protos:
        if p not in ["IPv4", "IPv6"]:
            return p
    return all_protos[0] if all_protos else "OTHER"


def detect_arp_inconsistencies(arp_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects when an IP is associated with multiple distinct MAC addresses."""
    ip_map = defaultdict(set)
    for entry in arp_entries:
        ip = entry.get("ip") or entry.get("ip_address")
        mac = entry.get("mac") or entry.get("mac_address")
        if ip and mac:
            ip_map[ip].add(mac)

    anomalies = []
    for ip, macs in ip_map.items():
        if len(macs) > 1:
            anomalies.append({
                "ip": ip,
                "associated_macs": sorted(list(macs)),
                "description": f"Potential ARP address inconsistency detected for {ip}. Observed {len(macs)} conflicting MAC addresses.",
            })
    return anomalies


def extract_tls_metadata(packets: List[Any]) -> List[Dict[str, Any]]:
    """Extracts non-intrusive TLS handshake records (SNI, versions) from packet objects."""
    results = []
    for p in packets:
        proto = (getattr(p, "protocol", "") or "").upper()
        info = getattr(p, "info", "") or ""
        sp = getattr(p, "src_port", None)
        dp = getattr(p, "dst_port", None)

        if "TLS" in proto or "SSL" in proto or dp == 443 or sp == 443:
            sni = None
            if "SNI=" in info:
                try:
                    sni = info.split("SNI=")[1].split()[0].rstrip("),; \t\r\n")
                except Exception:
                    pass
            elif "Client Hello" in info and " - " in info:
                sni = info.split(" - ")[-1].strip()

            tls_ver = "TLSv1.3" if "1.3" in info or "TLSV1.3" in proto else ("TLSv1.2" if "1.2" in info else "TLS")
            results.append({
                "src_ip": getattr(p, "src_ip", None),
                "dst_ip": getattr(p, "dst_ip", None),
                "src_port": sp,
                "dst_port": dp,
                "sni": sni,
                "tls_version": tls_ver,
                "cipher_suite": None,
                "timestamp": getattr(p, "timestamp_str", str(getattr(p, "timestamp", ""))),
            })
    return results



def _format_bytes(bytes_count: int) -> str:
    if bytes_count >= 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"
    if bytes_count >= 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.2f} MB"
    if bytes_count >= 1024:
        return f"{bytes_count / 1024:.2f} KB"
    return f"{bytes_count} B"


def _format_ts(ts: Optional[float]) -> Optional[str]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def classify_packet_protocols(packet: Dict[str, Any]) -> List[str]:
    """
    Identifies all core network and application protocol layers present in a packet.
    """
    protocols = set()
    proto_str = (packet.get("protocol") or "").upper()
    app_proto = (packet.get("app_protocol") or "").upper()
    info = (packet.get("info") or "").upper()

    src_ip = packet.get("src_ip") or ""
    dst_ip = packet.get("dst_ip") or ""
    sp = packet.get("src_port")
    dp = packet.get("dst_port")

    # 1. Network Layer: IPv4 vs IPv6 vs ARP
    if ":" in src_ip or ":" in dst_ip:
        protocols.add("IPv6")
    elif "." in src_ip or "." in dst_ip:
        protocols.add("IPv4")

    if proto_str == "ARP" or "ARP" in info:
        protocols.add("ARP")

    # 2. Transport Layer: TCP / UDP / ICMP
    if proto_str == "TCP" or packet.get("tcp_flags") is not None:
        protocols.add("TCP")
    elif proto_str == "UDP":
        protocols.add("UDP")
    elif "ICMP" in proto_str or "ICMP" in info:
        protocols.add("ICMP")

    # 3. Application / Service Layer
    ports = {p for p in (sp, dp) if p is not None}
    
    # Check port mappings and app_protocol
    for p in ports:
        if p in PORT_PROTOCOL_MAP:
            protocols.add(PORT_PROTOCOL_MAP[p])

    if app_proto:
        if "TLS" in app_proto or "SSL" in app_proto:
            protocols.add("HTTPS/TLS")
        elif "HTTP" in app_proto:
            protocols.add("HTTP")
        elif "DNS" in app_proto:
            protocols.add("DNS")
        elif "SSH" in app_proto:
            protocols.add("SSH")
        elif "SMB" in app_proto:
            protocols.add("SMB")
        elif "DHCP" in app_proto:
            protocols.add("DHCP")
        elif "NTP" in app_proto:
            protocols.add("NTP")
        elif "SNMP" in app_proto:
            protocols.add("SNMP")

    # Fallback to general protocol if none matched
    if not protocols:
        protocols.add(proto_str or "OTHER")

    return list(protocols)


def analyze_protocol_activity(
    db: Session,
    investigation_id: int,
    packets: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Performs comprehensive protocol analysis across all packets.
    Extracts protocol metrics, flows, ARP table mappings, and TLS handshakes.
    """
    if not packets:
        return {
            "summary": {
                "total_packets": 0,
                "total_bytes": 0,
                "total_bytes_str": "0 B",
                "unique_protocols": 0
            },
            "distribution": [],
            "core_network": {},
            "application_protocols": {},
            "arp_analysis": {"records": [], "inconsistencies_count": 0, "mappings": {}},
            "tls_analysis": {"records": [], "sni_list": []}
        }

    total_bytes = sum(p.get("length", 0) for p in packets)
    total_packets = len(packets)

    # Aggregation per protocol
    proto_stats = defaultdict(lambda: {
        "packet_count": 0,
        "total_bytes": 0,
        "first_observed": None,
        "last_observed": None,
        "endpoints": set(),
        "ports": set(),
    })

    arp_records_to_save: List[ARPRecord] = []
    tls_records_to_save: List[TLSMetadata] = []

    # Map to detect ARP IP/MAC inconsistencies: IP -> set of MACs seen
    arp_ip_to_macs = defaultdict(set)
    arp_mac_to_ips = defaultdict(set)

    for p in packets:
        length = p.get("length", 0)
        ts = p.get("timestamp")
        src_ip = p.get("src_ip")
        dst_ip = p.get("dst_ip")
        sp = p.get("src_port")
        dp = p.get("dst_port")
        info = p.get("info") or ""
        proto_str = (p.get("protocol") or "").upper()

        identified_protos = classify_packet_protocols(p)

        for proto in identified_protos:
            st = proto_stats[proto]
            st["packet_count"] += 1
            st["total_bytes"] += length

            if ts:
                if st["first_observed"] is None or ts < st["first_observed"]:
                    st["first_observed"] = ts
                if st["last_observed"] is None or ts > st["last_observed"]:
                    st["last_observed"] = ts

            if src_ip and dst_ip:
                st["endpoints"].add((src_ip, dst_ip))
            if sp:
                st["ports"].add(sp)
            if dp:
                st["ports"].add(dp)

        # ── ARP Handling ──
        if "ARP" in identified_protos:
            # Check info string or custom fields for ARP opcode and MACs
            # Wireshark typical info: "Who has 192.168.1.1? Tell 192.168.1.50" or "192.168.1.1 is at 00:11:22:33:44:55"
            opcode = "REQUEST" if ("Who has" in info or "request" in info.lower()) else "REPLY"
            sender_mac = p.get("eth_src") or p.get("src_mac")
            target_mac = p.get("eth_dst") or p.get("dst_mac")

            if sender_mac and src_ip:
                arp_ip_to_macs[src_ip].add(sender_mac)
                arp_mac_to_ips[sender_mac].add(src_ip)

            # Detect potential inconsistency
            is_inconsistent = False
            inconsistency_note = None
            if src_ip and len(arp_ip_to_macs[src_ip]) > 1:
                is_inconsistent = True
                inconsistency_note = (
                    f"Potential ARP address inconsistency detected. IP {src_ip} was observed with multiple MACs "
                    f"({', '.join(sorted(arp_ip_to_macs[src_ip]))}). "
                    f"Verify the IP/MAC mapping against the authorized network configuration."
                )

            arp_rec = ARPRecord(
                investigation_id=investigation_id,
                timestamp=ts or 0.0,
                timestamp_str=_format_ts(ts),
                opcode=opcode,
                sender_mac=sender_mac,
                sender_ip=src_ip,
                target_mac=target_mac,
                target_ip=dst_ip,
                is_inconsistent=is_inconsistent,
                inconsistency_note=inconsistency_note,
            )
            arp_records_to_save.append(arp_rec)

        # ── TLS / HTTPS Handling ──
        if "HTTPS/TLS" in identified_protos or "TLS" in proto_str or (dp == 443 or sp == 443):
            sni = None
            # Extract SNI if available in info or app_protocol
            if "Server Name:" in info:
                try:
                    sni = info.split("Server Name:")[1].split()[0].strip()
                except Exception:
                    pass
            elif "Client Hello" in info and " - " in info:
                sni = info.split(" - ")[-1].strip()

            tls_ver = "TLSv1.3" if "TLS 1.3" in info else ("TLSv1.2" if "TLS 1.2" in info else "TLS")
            if src_ip and dst_ip and ts:
                tls_meta = TLSMetadata(
                    investigation_id=investigation_id,
                    timestamp=ts,
                    timestamp_str=_format_ts(ts),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=sp,
                    destination_port=dp or 443,
                    version=tls_ver,
                    sni=sni,
                    cipher_suite=None,
                )
                tls_records_to_save.append(tls_meta)

    # Persist top ARP and TLS records (capped to avoid table bloat)
    try:
        if arp_records_to_save:
            db.bulk_save_objects(arp_records_to_save[:500])
            db.commit()
        if tls_records_to_save:
            # Dedup TLS by (source_ip, destination_ip, sni)
            seen_tls = set()
            unique_tls = []
            for t in tls_records_to_save:
                key = (t.source_ip, t.destination_ip, t.sni)
                if key not in seen_tls:
                    seen_tls.add(key)
                    unique_tls.append(t)
            db.bulk_save_objects(unique_tls[:300])
            db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Could not persist ARP/TLS records: {e}")

    # Build distribution table
    distribution: List[Dict[str, Any]] = []
    for proto, data in proto_stats.items():
        first_seen = data["first_observed"]
        last_seen = data["last_observed"]
        dur = max((last_seen - first_seen), 0.0) if (first_seen and last_seen) else 0.0
        pkt_pct = round((data["packet_count"] / total_packets * 100), 2) if total_packets > 0 else 0.0
        byte_pct = round((data["total_bytes"] / total_bytes * 100), 2) if total_bytes > 0 else 0.0

        distribution.append({
            "protocol": proto,
            "packet_count": data["packet_count"],
            "packet_percentage": pkt_pct,
            "total_bytes": data["total_bytes"],
            "total_bytes_str": _format_bytes(data["total_bytes"]),
            "byte_percentage": byte_pct,
            "first_observed": first_seen,
            "first_observed_str": _format_ts(first_seen),
            "last_observed": last_seen,
            "last_observed_str": _format_ts(last_seen),
            "duration_seconds": round(dur, 2),
            "unique_endpoints_count": len(data["endpoints"]),
            "unique_ports_count": len(data["ports"]),
        })

    # Sort distribution by total bytes descending
    distribution.sort(key=lambda x: x["total_bytes"], reverse=True)

    # Segregate Core vs Application
    core_keys = {"IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"}
    core_network = {d["protocol"]: d for d in distribution if d["protocol"] in core_keys}
    application_protocols = {d["protocol"]: d for d in distribution if d["protocol"] not in core_keys}

    # ARP mapping summary
    arp_inconsistencies = [
        {"ip": ip, "macs": sorted(list(macs)), "reason": f"Observed associated with {len(macs)} distinct MAC addresses."}
        for ip, macs in arp_ip_to_macs.items() if len(macs) > 1
    ]

    return {
        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_bytes_str": _format_bytes(total_bytes),
            "unique_protocols": len(distribution),
        },
        "distribution": distribution,
        "core_network": core_network,
        "application_protocols": application_protocols,
        "arp_analysis": {
            "total_arp_events": len(arp_records_to_save),
            "inconsistencies_count": len(arp_inconsistencies),
            "inconsistencies": arp_inconsistencies,
            "ip_mac_mappings": {ip: list(macs) for ip, macs in list(arp_ip_to_macs.items())[:50]},
        },
        "tls_analysis": {
            "total_handshakes": len(tls_records_to_save),
            "sni_list": sorted(list({t.sni for t in tls_records_to_save if t.sni})),
            "versions": Counter(t.version for t in tls_records_to_save if t.version),
        },
    }
