"""
Centralized Rule-Based Detection Engine
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Architecture:
Packet/Scan Data -> Protocol Parser -> Feature Extraction -> Detection Rules -> Security Event -> Timeline -> Investigation

Initial Rules:
- NET-001 Potential Port Scan
- NET-002 High Traffic
- NET-003 High Packet Rate
- NET-004 High Connection Rate
- NET-005 Excessive SYN Activity
- NET-006 Repeated Failed Connections
- NET-007 Excessive TCP RST
- NET-008 High ICMP Activity
- NET-009 DNS Query Spike
- NET-010 High NXDOMAIN Activity
- NET-011 Long DNS Query
- NET-012 ARP Address Inconsistency
- NET-013 Unusual Protocol Activity
- NET-014 Large Data Transfer

Strict evidence-based language:
- What was observed? (Factual measurement)
- Why does it matter? (Technical context)
- What evidence supports it? (Metrics)
- Security considerations & recommended investigation (Concrete next steps)
"""
import logging
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import TrafficEvent
from app.models.record import DNSRecord
from app.config import settings

logger = logging.getLogger("nova.detection_engine")

SECURITY_RULES = {
    "NET-001": {"name": "Potential Port Scan", "severity": "MEDIUM", "description": "Single source contacting multiple unique destination ports"},
    "NET-002": {"name": "High Traffic", "severity": "MEDIUM", "description": "Volumetric byte transfer rate exceeded configured threshold"},
    "NET-003": {"name": "High Packet Rate", "severity": "MEDIUM", "description": "High packet transmission rate observed"},
    "NET-004": {"name": "High Connection Rate", "severity": "MEDIUM", "description": "High frequency of TCP connection initiation attempts"},
    "NET-005": {"name": "Excessive SYN Activity", "severity": "MEDIUM", "description": "Elevated ratio of TCP SYN requests relative to established handshakes"},
    "NET-006": {"name": "Repeated Failed Connections", "severity": "MEDIUM", "description": "Repeated connection attempts with unacknowledged or reset states"},
    "NET-007": {"name": "Excessive TCP RST", "severity": "LOW", "description": "High proportion of TCP Reset flags terminating flows abruptly"},
    "NET-008": {"name": "High ICMP Activity", "severity": "MEDIUM", "description": "ICMP message generation rate exceeded baseline threshold"},
    "NET-009": {"name": "DNS Query Spike", "severity": "MEDIUM", "description": "Sudden volume spike in domain name lookups from host"},
    "NET-010": {"name": "High NXDOMAIN Activity", "severity": "MEDIUM", "description": "Frequent non-existent domain resolutions observed"},
    "NET-011": {"name": "Long DNS Query", "severity": "LOW", "description": "Domain query string exceeded character length limit"},
    "NET-012": {"name": "ARP Address Inconsistency", "severity": "HIGH", "description": "Conflicting hardware MAC addresses claiming identical IP address"},
    "NET-013": {"name": "Unusual Protocol Activity", "severity": "INFO", "description": "Cleartext or legacy service ports observed in communication"},
    "NET-014": {"name": "Large Data Transfer", "severity": "LOW", "description": "Substantial volumetric transfer across single flow conversation"},
}


def _normalize_packet(p: Any) -> Dict[str, Any]:
    if isinstance(p, dict):
        return p
    return {
        "src_ip": getattr(p, "src_ip", None),
        "dst_ip": getattr(p, "dst_ip", None),
        "src_port": getattr(p, "src_port", None),
        "dst_port": getattr(p, "dst_port", None),
        "protocol": getattr(p, "protocol", "OTHER"),
        "tcp_flags": getattr(p, "tcp_flags", ""),
        "length": getattr(p, "length", 0),
        "timestamp": getattr(p, "timestamp", 0.0),
        "info": getattr(p, "info", ""),
        "eth_src": getattr(p, "eth_src", getattr(p, "src_mac", None)),
    }


def _format_ts(ts: Optional[float]) -> str:
    if not ts or ts <= 0:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _format_rate(bps: float) -> str:
    if bps >= 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps:.2f} B/s"


def _is_syn_packet(p: Dict[str, Any]) -> bool:
    flags = str(p.get("tcp_flags") or "").upper()
    info = (p.get("info") or "").upper()
    if "SYN" in flags and "ACK" not in flags:
        return True
    if flags in ["0X0002", "0X02", "2"]:
        return True
    if "[SYN]" in info and "ACK" not in info:
        return True
    try:
        val = int(flags, 16) if flags.startswith("0X") else int(flags)
        if (val & 0x02) and not (val & 0x10):
            return True
    except Exception:
        pass
    return False


def _is_rst_packet(p: Dict[str, Any]) -> bool:
    flags = str(p.get("tcp_flags") or "").upper()
    info = (p.get("info") or "").upper()
    if "RST" in flags or "[RST]" in info or flags in ["0X0004", "0X04", "4"]:
        return True
    try:
        val = int(flags, 16) if flags.startswith("0X") else int(flags)
        if val & 0x04:
            return True
    except Exception:
        pass
    return False


# ─── NET-001: Potential Port Scan ─────────────────────────────────────────────

def rule_net_001_port_scan(packets: List[Dict[str, Any]], thresholds: dict) -> List[Dict[str, Any]]:
    """NET-001: Detects one source IP contacting multiple unique destination ports within a time window."""
    min_ports = thresholds.get("port_scan_min_ports", settings.PORT_SCAN_MIN_PORTS)
    time_window = thresholds.get("port_scan_time_window", settings.PORT_SCAN_TIME_WINDOW)

    syn_groups = defaultdict(list)
    for p in packets:
        if _is_syn_packet(p):
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            dport = p.get("dst_port")
            ts = p.get("timestamp", 0)
            if src and dst and dport and ts > 0:
                syn_groups[(src, dst)].append((ts, dport))

    detections = []
    for (src, dst), events in syn_groups.items():
        events.sort(key=lambda x: x[0])
        for i, (ts, port) in enumerate(events):
            window_end = ts + time_window
            window_ports = [p for t, p in events if ts <= t <= window_end]
            unique_ports = set(window_ports)
            if len(unique_ports) >= min_ports:
                first_ts = ts
                last_ts = events[min(i + len(window_ports) - 1, len(events) - 1)][0]
                detections.append({
                    "rule_id": "NET-001",
                    "rule_name": "Potential Port Scan",
                    "event_type": "POTENTIAL_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": src,
                    "destination_ip": dst,
                    "source_port": None,
                    "destination_port": None,
                    "protocol": "TCP",
                    "first_observed": first_ts,
                    "last_observed": last_ts,
                    "packet_count": len(window_ports),
                    "total_bytes": len(window_ports) * 60,
                    "duration": max(last_ts - first_ts, 1.0),
                    "evidence": {
                        "unique_ports_contacted": len(unique_ports),
                        "ports": sorted(list(unique_ports))[:50],
                        "time_window_seconds": time_window,
                        "syn_packets": len(window_ports),
                    },
                    "description": f"Source {src} generated connection attempts to {len(unique_ports)} ports on {dst}.",
                    "observation": f"A single source {src} initiated TCP connections across {len(unique_ports)} unique destination ports on {dst} within {time_window} seconds.",
                    "analysis": "This pattern is characteristic of automated port discovery or network scanning. While authorized vulnerability scanners and management tools display this behavior, unauthorized scanning is frequently used for reconnaissance.",
                    "recommendation": "1. Confirm whether source IP is an authorized security scanner or management asset.\n2. Review firewall logs for blocked connection attempts.\n3. Verify whether any contacted ports are exposed externally.",
                })
                break
    return detections


# ─── NET-002, NET-003, NET-004, NET-014: Flow Volumetric Rules ────────────────

def rule_net_volumetric(packets: List[Dict[str, Any]], thresholds: dict) -> List[Dict[str, Any]]:
    """
    NET-002: High Traffic (byte rate limit exceeded)
    NET-003: High Packet Rate (packet rate limit exceeded)
    NET-004: High Connection Rate (connection rate exceeded)
    NET-014: Large Data Transfer (single flow byte threshold)
    """
    byte_rate_limit = thresholds.get("high_byte_rate_threshold", settings.HIGH_BYTE_RATE_THRESHOLD)
    packet_rate_limit = thresholds.get("high_packet_rate_threshold", settings.HIGH_PACKET_RATE_THRESHOLD)
    conn_rate_limit = thresholds.get("high_connection_rate_threshold", settings.HIGH_CONNECTION_RATE_THRESHOLD)
    large_transfer_limit = thresholds.get("large_data_transfer_threshold", settings.LARGE_DATA_TRANSFER_THRESHOLD)

    # Aggregate flows by (src, dst, proto)
    flow_packets = defaultdict(list)
    host_syns = defaultdict(list)

    for p in packets:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        proto = p.get("protocol") or "TCP"
        ts = p.get("timestamp") or 0.0
        flags = p.get("tcp_flags") or ""

        if src and dst:
            flow_packets[(src, dst, proto)].append(p)
        if "SYN" in flags and "ACK" not in flags and src and ts > 0:
            host_syns[src].append(ts)

    detections = []

    # Flow evaluations
    for (src, dst, proto), pkts in flow_packets.items():
        total_bytes = sum(p.get("length", 0) for p in pkts)
        packet_count = len(pkts)
        timestamps = [p.get("timestamp") for p in pkts if p.get("timestamp")]
        first_ts = min(timestamps) if timestamps else 0.0
        last_ts = max(timestamps) if timestamps else first_ts
        dur = max(last_ts - first_ts, 1.0)
        pps = round(packet_count / dur, 2)
        bps = round(total_bytes / dur, 2)

        # NET-002: High Byte Rate
        if bps >= byte_rate_limit:
            detections.append({
                "rule_id": "NET-002",
                "rule_name": "High Traffic Volume",
                "event_type": "HIGH_TRAFFIC",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": proto,
                "first_observed": first_ts,
                "last_observed": last_ts,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "duration": dur,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "evidence": {"transfer_rate": _format_rate(bps), "threshold": _format_rate(byte_rate_limit), "total_bytes": total_bytes},
                "description": f"Traffic throughput ({_format_rate(bps)}) between {src} and {dst} exceeded threshold.",
                "observation": f"Traffic transfer rate reached {_format_rate(bps)} over a {dur:.1f}s period.",
                "analysis": "Traffic volume exceeded the configured threshold. This may represent legitimate high-speed data transfer, backups, media streaming, or unusual activity and should be investigated.",
                "recommendation": "1. Verify if endpoints are running scheduled data transfers or backups.\n2. Review protocol and application context.\n3. Cross-reference with authorized transfer schedules.",
            })

        # NET-003: High Packet Rate
        if pps >= packet_rate_limit:
            detections.append({
                "rule_id": "NET-003",
                "rule_name": "High Packet Rate",
                "event_type": "HIGH_PACKET_RATE",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": proto,
                "first_observed": first_ts,
                "last_observed": last_ts,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "duration": dur,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "evidence": {"packets_per_second": pps, "threshold": packet_rate_limit, "packet_count": packet_count},
                "description": f"Packet delivery rate ({pps} pps) from {src} to {dst} exceeded threshold.",
                "observation": f"Packet frequency measured at {pps} packets/sec over {dur:.1f} seconds.",
                "analysis": "A sustained high packet rate can indicate intensive service communication, network performance testing, or flooding behavior. Contextual review is advised.",
                "recommendation": "1. Determine the application initiating the high packet rate.\n2. Inspect TCP control flags and window states.\n3. Validate whether network throttling is appropriate.",
            })

        # NET-014: Large Data Transfer
        if total_bytes >= large_transfer_limit:
            detections.append({
                "rule_id": "NET-014",
                "rule_name": "Large Data Transfer",
                "event_type": "LARGE_DATA_TRANSFER",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": proto,
                "first_observed": first_ts,
                "last_observed": last_ts,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "duration": dur,
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "evidence": {"total_bytes": total_bytes, "threshold": large_transfer_limit, "duration": dur},
                "description": f"Total volume transferred ({total_bytes} bytes) between {src} and {dst} exceeded threshold.",
                "observation": f"Session cumulative data transfer reached {total_bytes} bytes.",
                "analysis": "Large data transfers are common in administrative syncing, updates, or backups, but can also represent bulk data exfiltration. Validate destination legitimacy.",
                "recommendation": "1. Check destination IP reputation and hosting provider.\n2. Verify if user or service account is authorized for large transfers.\n3. Review data sensitivity of endpoints involved.",
            })

    # NET-004: High Connection Rate (Host SYNs)
    for host_ip, syn_times in host_syns.items():
        if len(syn_times) >= 2:
            syn_times.sort()
            window_dur = max(syn_times[-1] - syn_times[0], 1.0)
            c_rate = round(len(syn_times) / window_dur, 2)
            if c_rate >= conn_rate_limit:
                detections.append({
                    "rule_id": "NET-004",
                    "rule_name": "High Connection Rate",
                    "event_type": "HIGH_CONNECTION_RATE",
                    "severity": "LOW",
                    "source_ip": host_ip,
                    "destination_ip": None,
                    "protocol": "TCP",
                    "first_observed": syn_times[0],
                    "last_observed": syn_times[-1],
                    "packet_count": len(syn_times),
                    "total_bytes": len(syn_times) * 60,
                    "duration": window_dur,
                    "packets_per_second": c_rate,
                    "bytes_per_second": round(c_rate * 60, 2),
                    "evidence": {"connection_rate": c_rate, "threshold": conn_rate_limit, "syn_count": len(syn_times)},
                    "description": f"Host {host_ip} initiated {c_rate} connections/sec, exceeding threshold.",
                    "observation": f"Connection initiation frequency measured at {c_rate} connections/sec across a {window_dur:.1f}s window.",
                    "analysis": "Rapid connection establishment can occur during web crawling, bulk API requests, load testing, or scanning. Investigation is needed to establish legitimacy.",
                    "recommendation": "1. Review destination services and ports targeted.\n2. Check application logs on source host.\n3. Verify if connection pooling or rate limiting is recommended.",
                })

    return detections


# ─── NET-005, NET-006, NET-007: TCP Behavioral Rules ──────────────────────────

def rule_net_tcp_behavior(packets: List[Dict[str, Any]], thresholds: dict) -> List[Dict[str, Any]]:
    """
    NET-005: Excessive SYN Activity
    NET-006: Repeated Failed Connections
    NET-007: Excessive TCP RST
    """
    syn_threshold = thresholds.get("tcp_conn_threshold", settings.TCP_CONN_THRESHOLD)
    rst_threshold = 20

    syn_counter = Counter()
    rst_counter = Counter()
    failed_conns = defaultdict(int)  # (src, dst) -> count of unacknowledged SYNs

    for p in packets:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        flags = p.get("tcp_flags") or ""
        if not src:
            continue

        if _is_syn_packet(p):
            syn_counter[src] += 1
            if dst:
                failed_conns[(src, dst)] += 1
        elif _is_rst_packet(p):
            rst_counter[src] += 1
        elif "SYN" in flags and "ACK" in flags:
            # Acknowledged
            if dst and (dst, src) in failed_conns:
                failed_conns[(dst, src)] = max(0, failed_conns[(dst, src)] - 1)

    detections = []

    # NET-005: Excessive SYN Activity
    for src, count in syn_counter.items():
        if count >= syn_threshold:
            detections.append({
                "rule_id": "NET-005",
                "rule_name": "Excessive SYN Activity",
                "event_type": "EXCESSIVE_SYN_ACTIVITY",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": None,
                "protocol": "TCP",
                "first_observed": None,
                "last_observed": None,
                "packet_count": count,
                "total_bytes": count * 60,
                "duration": 0.0,
                "evidence": {"syn_count": count, "threshold": syn_threshold},
                "description": f"Source {src} generated {count} TCP SYN packets exceeding threshold of {syn_threshold}.",
                "observation": f"Host {src} generated {count} TCP SYN packets.",
                "analysis": "Excessive SYN generation without completed handshakes can be caused by misconfigured services, network testing, or aggressive connection attempts.",
                "recommendation": "1. Verify whether the host is performing authorized network testing.\n2. Review destination responses to confirm whether services exist.\n3. Consider ingress connection limits if external.",
            })

    # NET-006: Repeated Failed Connections
    for (src, dst), fails in failed_conns.items():
        if fails >= 15:
            detections.append({
                "rule_id": "NET-006",
                "rule_name": "Repeated Failed Connections",
                "event_type": "REPEATED_FAILED_CONNECTIONS",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": "TCP",
                "first_observed": None,
                "last_observed": None,
                "packet_count": fails,
                "total_bytes": fails * 60,
                "duration": 0.0,
                "evidence": {"unacknowledged_syns": fails, "threshold": 15},
                "description": f"Host {src} attempted {fails} connections to {dst} without completed handshake.",
                "observation": f"{fails} TCP connection attempts from {src} to {dst} remained unacknowledged.",
                "analysis": "Potentially unusual TCP connection activity detected based on repeated connection attempts within a short time period. This could indicate an offline service, firewall drops, or probing.",
                "recommendation": "1. Confirm whether the target service on {dst} is online.\n2. Check host firewall rules on destination.\n3. Determine if source host is attempting automated retries.",
            })

    # NET-007: Excessive TCP RST
    for src, count in rst_counter.items():
        if count >= rst_threshold:
            detections.append({
                "rule_id": "NET-007",
                "rule_name": "Excessive TCP RST Responses",
                "event_type": "EXCESSIVE_TCP_RST",
                "severity": "INFO",
                "source_ip": src,
                "destination_ip": None,
                "protocol": "TCP",
                "first_observed": None,
                "last_observed": None,
                "packet_count": count,
                "total_bytes": count * 60,
                "duration": 0.0,
                "evidence": {"rst_count": count, "threshold": rst_threshold},
                "description": f"Host {src} returned {count} TCP RST packets.",
                "observation": f"Host {src} transmitted {count} TCP Reset (RST) control packets.",
                "analysis": "Elevated TCP RST rates typically occur when connections are rejected because destination ports are closed, or when firewall policy forcibly terminates connections.",
                "recommendation": "1. Verify whether services on targeted ports are active.\n2. Review ingress firewall drop/reject configurations.\n3. Correlate with concurrent port scan activity.",
            })

    return detections


# ─── NET-008: High ICMP Activity ─────────────────────────────────────────────

def rule_net_008_icmp(packets: List[Dict[str, Any]], thresholds: dict) -> List[Dict[str, Any]]:
    """NET-008: High ICMP Activity detection."""
    icmp_threshold = thresholds.get("icmp_threshold", settings.ICMP_THRESHOLD)
    icmp_counts = Counter(p.get("src_ip") for p in packets if (p.get("protocol") == "ICMP" or "ICMP" in (p.get("info") or "")))

    detections = []
    for ip, count in icmp_counts.items():
        if ip and count >= icmp_threshold:
            detections.append({
                "rule_id": "NET-008",
                "rule_name": "High ICMP Activity",
                "event_type": "HIGH_ICMP_ACTIVITY",
                "severity": "INFO",
                "source_ip": ip,
                "destination_ip": None,
                "protocol": "ICMP",
                "first_observed": None,
                "last_observed": None,
                "packet_count": count,
                "total_bytes": count * 84,
                "duration": 0.0,
                "evidence": {"icmp_packets": count, "threshold": icmp_threshold},
                "description": f"Host {ip} transmitted {count} ICMP packets, exceeding threshold.",
                "observation": f"Host {ip} transmitted {count} ICMP packets during the observation window.",
                "analysis": "Potentially unusual ICMP volume observed. While ping sweeps and network diagnostics generate ICMP bursts, excessive volume may indicate network path troubleshooting, keepalives, or ICMP flood testing.",
                "recommendation": "1. Identify the ICMP type (Echo Request vs Destination Unreachable).\n2. Verify if source host is an authorized monitoring agent.\n3. Check destination addresses to determine sweep patterns.",
            })
    return detections


# ─── NET-009, NET-010, NET-011: DNS Security Rules ────────────────────────────

def rule_net_dns(
    db: Optional[Session],
    investigation_id: Any,
    thresholds: dict,
    packets: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    NET-009: DNS Query Spike
    NET-010: High NXDOMAIN Activity
    NET-011: Long DNS Query
    """
    dns_threshold = thresholds.get("dns_query_threshold", settings.DNS_QUERY_THRESHOLD)
    long_dns_len = thresholds.get("long_dns_query_len", settings.LONG_DNS_QUERY_LEN)

    dns_records = []
    if db is not None:
        try:
            dns_records = db.query(DNSRecord).filter(DNSRecord.investigation_id == investigation_id).all()
        except Exception:
            dns_records = []

    if not dns_records and packets:
        for p in packets:
            info = p.get("info") or ""
            proto = (p.get("protocol") or "").upper()
            if proto == "DNS" or "standard query" in info.lower():
                qname = ""
                if "A " in info:
                    qname = info.split("A ")[-1].strip()
                elif "query" in info.lower():
                    parts = info.split()
                    qname = parts[-1].strip() if parts else ""
                if qname:
                    rec = type("MockDNSRecord", (), {
                        "src_ip": p.get("src_ip"),
                        "dst_ip": p.get("dst_ip"),
                        "query_name": qname,
                        "timestamp": p.get("timestamp", 0.0),
                        "is_response": 1 if "response" in info.lower() else 0,
                        "response_code": 3 if "nxdomain" in info.lower() else 0,
                        "response_code_name": "NXDOMAIN" if "nxdomain" in info.lower() else "NOERROR",
                    })()
                    dns_records.append(rec)

    if not dns_records:
        return []

    detections = []

    # NET-009: Query count per source
    client_counts = Counter(r.src_ip for r in dns_records if r.src_ip and r.is_response == 0)
    for ip, count in client_counts.items():
        if count >= dns_threshold:
            detections.append({
                "rule_id": "NET-009",
                "rule_name": "DNS Query Volume Spike",
                "event_type": "DNS_QUERY_SPIKE",
                "severity": "LOW",
                "source_ip": ip,
                "destination_ip": None,
                "protocol": "DNS",
                "first_observed": None,
                "last_observed": None,
                "packet_count": count,
                "total_bytes": count * 70,
                "duration": 0.0,
                "evidence": {"query_count": count, "threshold": dns_threshold},
                "description": f"Host {ip} issued {count} DNS queries exceeding threshold of {dns_threshold}.",
                "observation": f"Host {ip} generated {count} DNS queries.",
                "analysis": "High DNS query volume can occur during software updates, web crawlers, high-concurrency applications, or automated querying. Further inspection is advised.",
                "recommendation": "1. Review queried domains for repetitive or high-entropy patterns.\n2. Correlate with endpoint process execution.\n3. Verify if the host is an internal DNS forwarder or proxy.",
            })

    # NET-010: High NXDOMAIN Activity (rcode == 3 or NXDOMAIN)
    nxdomain_counts = Counter(r.src_ip for r in dns_records if str(getattr(r, "response_code", "")).upper() in ["3", "NXDOMAIN"])
    for ip, count in nxdomain_counts.items():
        if ip and count >= 10:
            detections.append({
                "rule_id": "NET-010",
                "rule_name": "High NXDOMAIN Activity",
                "event_type": "HIGH_NXDOMAIN_ACTIVITY",
                "severity": "MEDIUM",
                "source_ip": ip,
                "destination_ip": None,
                "protocol": "DNS",
                "first_observed": None,
                "last_observed": None,
                "packet_count": count,
                "total_bytes": count * 80,
                "duration": 0.0,
                "evidence": {"nxdomain_count": count, "threshold": 10},
                "description": f"Host {ip} received {count} NXDOMAIN responses for non-existent domains.",
                "observation": f"{count} DNS resolutions resulted in NXDOMAIN (Non-Existent Domain).",
                "analysis": "Frequent NXDOMAIN responses can occur when systems query retired servers, mistyped domains, or when algorithms test multiple randomized subdomains. Review queried domain patterns.",
                "recommendation": "1. Inspect queried domain names for randomized characters or DGA structure.\n2. Verify if hosts are trying to reach decommissioned internal hostnames.\n3. Check antivirus or EDR logs on the querying system.",
            })

    # NET-011: Long DNS Query
    for rec in dns_records:
        if rec.query_name and len(rec.query_name) >= long_dns_len:
            detections.append({
                "rule_id": "NET-011",
                "rule_name": "Unusually Long DNS Query",
                "event_type": "LONG_DNS_QUERY",
                "severity": "LOW",
                "source_ip": rec.src_ip,
                "destination_ip": rec.dst_ip,
                "protocol": "DNS",
                "first_observed": rec.timestamp,
                "last_observed": rec.timestamp,
                "packet_count": 1,
                "total_bytes": len(rec.query_name),
                "duration": 0.0,
                "evidence": {"query_name": rec.query_name, "length": len(rec.query_name), "threshold": long_dns_len},
                "description": f"DNS query length ({len(rec.query_name)} chars) exceeded threshold of {long_dns_len}.",
                "observation": f"Domain query string '{rec.query_name[:60]}...' measured {len(rec.query_name)} characters.",
                "analysis": "Unusually long domain labels can occur in anti-spam lookup services, CDN tracking, or structured encoded protocols. Investigate the parent domain owner.",
                "recommendation": "1. Analyze whether the domain string contains base32/base64 encoded content.\n2. Confirm whether parent domain belongs to an established service provider.\n3. Check destination DNS server resolution.",
            })
            break  # Cap to one per investigation to avoid spam

    return detections


# ─── NET-012: ARP Address Inconsistency ───────────────────────────────────────

def rule_net_012_arp(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NET-012: Potential ARP Address Inconsistency."""
    arp_ip_to_macs = defaultdict(set)
    first_ts = {}

    for p in packets:
        proto = (p.get("protocol") or "").upper()
        info = p.get("info") or ""
        src_ip = p.get("src_ip")
        src_mac = p.get("eth_src") or p.get("src_mac")
        ts = p.get("timestamp") or 0.0

        if proto == "ARP" or "ARP" in info:
            if src_ip and src_mac:
                arp_ip_to_macs[src_ip].add(src_mac)
                if src_ip not in first_ts:
                    first_ts[src_ip] = ts

    detections = []
    for ip, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            mac_list = sorted(list(macs))
            detections.append({
                "rule_id": "NET-012",
                "rule_name": "ARP Address Inconsistency",
                "event_type": "ARP_ADDRESS_INCONSISTENCY",
                "severity": "MEDIUM",
                "source_ip": ip,
                "destination_ip": None,
                "protocol": "ARP",
                "first_observed": first_ts.get(ip),
                "last_observed": None,
                "packet_count": len(mac_list),
                "total_bytes": len(mac_list) * 42,
                "duration": 0.0,
                "evidence": {"ip": ip, "observed_macs": mac_list, "distinct_mac_count": len(mac_list)},
                "description": f"IP {ip} was claimed by multiple MAC addresses ({', '.join(mac_list)}).",
                "observation": f"IP address {ip} was associated with {len(mac_list)} distinct hardware MAC addresses.",
                "analysis": "Potential ARP address inconsistency detected. This can occur in environments with high-availability failovers, virtual IP roaming, or address conflicts. Verify the IP/MAC mapping against the authorized network configuration.",
                "recommendation": "1. Inspect router and switch ARP tables for the target subnet.\n2. Verify if the IP belongs to a cluster (VRRP, CARP, HSRP).\n3. Check for unauthorized devices with duplicate IP assignment.",
            })
    return detections


# ─── NET-013: Unusual Protocol Activity ───────────────────────────────────────

def rule_net_013_unusual_protocol(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NET-013: Unusual protocol or sensitive port communication."""
    sensitive_ports = {
        21: ("FTP", "Cleartext File Transfer Protocol (FTP)"),
        23: ("Telnet", "Unencrypted Telnet terminal access"),
        445: ("SMB", "Server Message Block (SMB) network share"),
        3389: ("RDP", "Remote Desktop Protocol (RDP) connection"),
    }

    port_traffic = defaultdict(int)
    endpoints_seen = defaultdict(set)

    for p in packets:
        dp = p.get("dst_port")
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        if dp in sensitive_ports and src and dst:
            port_traffic[dp] += 1
            endpoints_seen[dp].add((src, dst))

    detections = []
    for port, (pname, pdesc) in sensitive_ports.items():
        if port_traffic[port] > 0:
            sample_endpoints = list(endpoints_seen[port])[:5]
            src = sample_endpoints[0][0] if sample_endpoints else None
            dst = sample_endpoints[0][1] if sample_endpoints else None
            detections.append({
                "rule_id": "NET-013",
                "rule_name": f"Sensitive Protocol Activity ({pname})",
                "event_type": "UNUSUAL_PROTOCOL_ACTIVITY",
                "severity": "INFO" if port == 445 else "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "source_port": None,
                "destination_port": port,
                "protocol": pname,
                "first_observed": None,
                "last_observed": None,
                "packet_count": port_traffic[port],
                "total_bytes": port_traffic[port] * 100,
                "duration": 0.0,
                "evidence": {"port": port, "protocol": pname, "packet_count": port_traffic[port], "endpoints": [f"{s}->{d}" for s, d in sample_endpoints]},
                "description": f"Observed communication using {pdesc} on port {port}.",
                "observation": f"{port_traffic[port]} packets observed on port {port} ({pname}).",
                "analysis": f"{pname} activity detected on port {port}. Review whether this protocol exposure is expected on the network and whether adequate transport security is enforced.",
                "recommendation": f"1. Verify if {pname} traffic is authorized between these endpoints.\n2. For cleartext protocols (Telnet/FTP), migrate to secure encrypted alternatives (SSH/SFTP).\n3. Confirm access controls restrict usage to trusted management subnets.",
            })

    return detections


# ─── Central Detection Engine Runner ──────────────────────────────────────────

def run_detection_engine(*args, **kwargs) -> Any:
    """
    Executes all 14 centralized detection rules (NET-001 through NET-014).
    Signatures supported:
      1. run_detection_engine(db, investigation_id, parsed_packets, thresholds=None)
      2. run_detection_engine(investigation_id, parsed_packets, db=None, thresholds=None)
    Persists results into `Alert` and `TrafficEvent` records when db is provided.
    Returns integer count when db is provided, or list of detection dicts when db is None.
    """
    db = None
    investigation_id = 0
    parsed_packets = []
    thresholds = kwargs.get("thresholds") or {}

    if len(args) >= 3:
        if hasattr(args[0], "query") or hasattr(args[0], "bulk_save_objects"):
            db = args[0]
            investigation_id = args[1]
            parsed_packets = args[2]
            if len(args) >= 4:
                thresholds = args[3]
        else:
            investigation_id = args[0]
            parsed_packets = args[1]
            db = args[2]
            if len(args) >= 4:
                thresholds = args[3]
    elif len(args) == 2:
        investigation_id = args[0]
        parsed_packets = args[1]
        db = kwargs.get("db")

    if not parsed_packets and "parsed_packets" in kwargs:
        parsed_packets = kwargs["parsed_packets"]
    if not investigation_id and "investigation_id" in kwargs:
        investigation_id = kwargs["investigation_id"]

    # Normalize packets whether passed as dicts or ORM/mock objects
    norm_packets = [_normalize_packet(p) for p in (parsed_packets or [])]

    all_detections: List[Dict[str, Any]] = []

    # Execute rules
    all_detections.extend(rule_net_001_port_scan(norm_packets, thresholds))
    all_detections.extend(rule_net_volumetric(norm_packets, thresholds))
    all_detections.extend(rule_net_tcp_behavior(norm_packets, thresholds))
    all_detections.extend(rule_net_008_icmp(norm_packets, thresholds))
    all_detections.extend(rule_net_dns(db, investigation_id, thresholds, norm_packets))
    all_detections.extend(rule_net_012_arp(norm_packets))
    all_detections.extend(rule_net_013_unusual_protocol(norm_packets))

    # Deduplicate by (rule_id, source_ip, destination_ip, protocol)
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for d in all_detections:
        key = (d["rule_id"], d.get("source_ip"), d.get("destination_ip"), d.get("protocol"))
        if key not in seen:
            seen.add(key)
            deduped.append(d)

    if db is None:
        return deduped

    # Persist as Alerts and TrafficEvents
    alert_objects: List[Alert] = []
    traffic_event_objects: List[TrafficEvent] = []

    inv_numeric_id = investigation_id if isinstance(investigation_id, int) else 1
    existing_alt_count = db.query(Alert).filter(Alert.investigation_id == inv_numeric_id).count()
    existing_tev_count = db.query(TrafficEvent).filter(TrafficEvent.investigation_id == investigation_id).count()
    counter = 0

    for raw in deduped:
        counter += 1
        alt_id = f"ALT-{inv_numeric_id:04d}-{existing_alt_count + counter:04d}"
        tev_id = f"TEV-{inv_numeric_id:04d}-{existing_tev_count + counter:04d}"

        # 1. Alert Record
        alert = Alert(
            investigation_id=inv_numeric_id,
            alert_id=alt_id,
            severity=raw["severity"].lower(),
            alert_type=raw["rule_name"],
            detection_rule=raw["rule_id"],
            src_ip=raw.get("source_ip"),
            dst_ip=raw.get("destination_ip"),
            first_seen=raw.get("first_observed"),
            last_seen=raw.get("last_observed"),
            first_seen_str=_format_ts(raw.get("first_observed")),
            reason=raw.get("description"),
            recommendations=raw.get("recommendation"),
            status="new",
        )
        alert.evidence = raw.get("evidence", {})
        alert_objects.append(alert)

        # 2. Centralized Security / Traffic Event
        ts_val = raw.get("first_observed") or 0.0
        tev = TrafficEvent(
            event_id=tev_id,
            investigation_id=investigation_id,
            timestamp=ts_val,
            timestamp_str=_format_ts(ts_val),
            event_type=raw.get("event_type", "SECURITY_FINDING"),
            severity=raw.get("severity", "INFO"),
            source_ip=raw.get("source_ip"),
            destination_ip=raw.get("destination_ip"),
            source_port=raw.get("source_port"),
            destination_port=raw.get("destination_port"),
            protocol=raw.get("protocol"),
            short_explanation=raw.get("description", ""),
            observation=raw.get("observation", raw.get("description", "")),
            analysis=raw.get("analysis"),
            recommendation=raw.get("recommendation"),
            packet_count=raw.get("packet_count", 0),
            total_bytes=raw.get("total_bytes", 0),
            duration=raw.get("duration", 0.0),
            packets_per_second=raw.get("packets_per_second", 0.0),
            bytes_per_second=raw.get("bytes_per_second", 0.0),
            evidence=raw.get("evidence", {}),
        )
        traffic_event_objects.append(tev)

    try:
        if alert_objects:
            db.bulk_save_objects(alert_objects)
        if traffic_event_objects:
            db.bulk_save_objects(traffic_event_objects)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Error persisting detection events: {e}")

    logger.info(f"Centralized Detection Engine evaluated {len(deduped)} events for Investigation {investigation_id}")
    return len(deduped)


def detect_port_scans(packets: List[Dict[str, Any]], thresholds: Optional[dict] = None) -> List[Dict[str, Any]]:
    """Backwards-compatibility wrapper for legacy tests and callers."""
    norm = [_normalize_packet(p) for p in packets]
    res = rule_net_001_port_scan(norm, thresholds or {})
    return [
        {
            "rule": "PORT_SCAN",
            "rule_id": d["rule_id"],
            "src_ip": d["source_ip"],
            "dst_ip": d["destination_ip"],
            "title": d["rule_name"],
            "severity": d["severity"],
            "description": d["description"],
            "evidence": d["evidence"],
        }
        for d in res
    ]


def detect_icmp_anomalies(packets: List[Dict[str, Any]], thresholds: Optional[dict] = None) -> List[Dict[str, Any]]:
    """Backwards-compatibility wrapper for legacy tests and callers."""
    norm = [_normalize_packet(p) for p in packets]
    res = rule_net_008_icmp(norm, thresholds or {})
    return [
        {
            "rule": "HIGH_ICMP",
            "rule_id": d["rule_id"],
            "src_ip": d["source_ip"],
            "title": d["rule_name"],
            "severity": d["severity"],
            "description": d["description"],
            "evidence": d["evidence"],
        }
        for d in res
    ]

