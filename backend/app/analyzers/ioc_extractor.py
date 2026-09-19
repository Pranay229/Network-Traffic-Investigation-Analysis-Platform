"""
IOC Extractor — extracts observed network indicators from traffic.

IMPORTANT: These are OBSERVED indicators from the analyzed traffic.
They are NOT confirmed malicious indicators without further threat intelligence enrichment.
"""
import re
import logging
from collections import defaultdict, Counter
from sqlalchemy.orm import Session
from app.models.ioc import IOC

logger = logging.getLogger(__name__)

# Simple URL pattern for HTTP records
URL_PATTERN = re.compile(r'^https?://', re.IGNORECASE)

# Well-known internal/private ranges (RFC 1918)
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in a private/loopback range."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False


def extract_iocs(
    db: Session,
    investigation_id: int,
    parsed_packets: list[dict],
    dns_stats: dict,
    http_stats: dict,
) -> dict:
    """
    Extract potential indicators of compromise from traffic data.
    Types: ipv4, ipv6, domain, url, port
    """
    ioc_data: dict[tuple, dict] = {}  # (type, value) -> {first_seen, last_seen, source, context, count}

    def add_ioc(ioc_type: str, value: str, ts: float | None, source_ip: str | None, context: str):
        key = (ioc_type, value.lower() if ioc_type in ("domain", "url") else value)
        if key not in ioc_data:
            ioc_data[key] = {
                "type": ioc_type, "value": value,
                "first_seen": ts, "last_seen": ts,
                "source_ip": source_ip, "context": context, "count": 0,
            }
        d = ioc_data[key]
        d["count"] += 1
        if ts:
            if d["first_seen"] is None or ts < d["first_seen"]:
                d["first_seen"] = ts
            if d["last_seen"] is None or ts > d["last_seen"]:
                d["last_seen"] = ts

    from datetime import datetime

    def ts_str(ts):
        if not ts:
            return None
        try:
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return None

    # Extract IPs from packets
    seen_ips: set[str] = set()
    for p in parsed_packets:
        ts = p.get("timestamp")
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        proto = p.get("protocol", "")

        if src and src not in seen_ips:
            seen_ips.add(src)
            ioc_type = "ipv6" if ":" in src else "ipv4"
            add_ioc(ioc_type, src, ts, src, f"Observed as source in {proto} traffic")

        if dst and dst not in seen_ips:
            seen_ips.add(dst)
            ioc_type = "ipv6" if ":" in dst else "ipv4"
            add_ioc(ioc_type, dst, ts, src, f"Observed as destination in {proto} traffic")

        # Extract destination ports as IOCs
        dport = p.get("dst_port")
        if dport and proto in ("TCP", "UDP"):
            add_ioc("port", f"{proto}/{dport}", ts, src, f"Destination port in {proto} traffic")

    # Extract domains from DNS queries (stored in DB)
    from app.models.record import DNSRecord
    dns_records = db.query(DNSRecord).filter(
        DNSRecord.investigation_id == investigation_id,
        DNSRecord.is_response == 0,
        DNSRecord.query_name != None,
    ).all()

    for rec in dns_records:
        if rec.query_name:
            add_ioc("domain", rec.query_name.rstrip("."), rec.timestamp, rec.src_ip,
                    f"DNS {rec.query_type or 'A'} query from {rec.src_ip}")

    # Extract URLs from HTTP records
    from app.models.record import HTTPRecord
    http_records = db.query(HTTPRecord).filter(
        HTTPRecord.investigation_id == investigation_id,
        HTTPRecord.is_request == 1,
        HTTPRecord.uri != None,
    ).all()

    for rec in http_records:
        if rec.host and rec.uri:
            url = f"http://{rec.host}{rec.uri}"
            add_ioc("url", url[:500], rec.timestamp, rec.src_ip,
                    f"HTTP {rec.method or 'GET'} request")

    # Store in DB
    ioc_objects = []
    for (ioc_type, value), data in ioc_data.items():
        ioc = IOC(
            investigation_id=investigation_id,
            ioc_type=ioc_type,
            value=str(data["value"])[:2000],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            first_seen_str=ts_str(data["first_seen"]),
            last_seen_str=ts_str(data["last_seen"]),
            source_ip=str(data["source_ip"])[:45] if data["source_ip"] else None,
            context=str(data["context"])[:500],
            occurrence_count=data["count"],
        )
        ioc_objects.append(ioc)

    if ioc_objects:
        db.bulk_save_objects(ioc_objects)
        db.commit()

    type_counts = Counter(d["type"] for d in ioc_data.values())
    logger.info(f"Extracted {len(ioc_objects)} IOCs for investigation {investigation_id}")

    return {
        "total_iocs": len(ioc_objects),
        "by_type": dict(type_counts),
    }


def extract_iocs_from_packets(packets: list) -> list[dict]:
    """Pure-memory extractor returning observed observable indicators from packet stream."""
    iocs = []
    seen = set()
    for p in packets:
        src = getattr(p, "src_ip", None) if not isinstance(p, dict) else p.get("src_ip")
        dst = getattr(p, "dst_ip", None) if not isinstance(p, dict) else p.get("dst_ip")
        dp = getattr(p, "dst_port", None) if not isinstance(p, dict) else p.get("dst_port")
        info = getattr(p, "info", "") if not isinstance(p, dict) else p.get("info", "")

        for ip in [src, dst]:
            if ip and ip not in seen:
                seen.add(ip)
                iocs.append({"type": "ipv6" if ":" in ip else "ipv4", "value": ip})
        if dp and str(dp) not in seen:
            seen.add(str(dp))
            iocs.append({"type": "port", "value": dp})
        if "A " in info:
            domain = info.split("A ")[-1].strip()
            if domain and domain not in seen:
                seen.add(domain)
                iocs.append({"type": "domain", "value": domain})
    return iocs

