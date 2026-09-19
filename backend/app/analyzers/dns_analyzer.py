"""
DNS analyzer — extracts DNS queries and responses from parsed TShark packets.
Detects potentially suspicious DNS patterns.
"""
import logging
from collections import defaultdict, Counter
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.record import DNSRecord
from app.config import settings

logger = logging.getLogger(__name__)

DNS_TYPE_MAP = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
    "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "99": "SPF",
    "255": "ANY",
}


def _extract_parent_domain(fqdn: str) -> str:
    """Extract parent domain (last 2 labels) from FQDN."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def analyze_dns(db: Session, investigation_id: int, parsed_packets: list[dict]) -> dict:
    """Extract DNS records from parsed packets and store in DB."""
    dns_records = []

    for p in parsed_packets:
        layers = p.get("_layers", {})
        if not layers:
            continue

        def g(key, default=None):
            val = layers.get(key, default)
            if isinstance(val, list):
                return val[0] if val else default
            return val

        query_name = g("dns.qry.name")
        if not query_name:
            continue

        is_response = g("dns.flags.response", "0")
        try:
            is_resp = int(is_response) == 1
        except Exception:
            is_resp = False

        qtype_raw = g("dns.qry.type", "1")
        query_type = DNS_TYPE_MAP.get(str(qtype_raw), str(qtype_raw))

        response_a = g("dns.a")
        response_aaaa = g("dns.aaaa")
        response_ips = []
        if response_a:
            response_ips = response_a if isinstance(response_a, list) else [response_a]
        elif response_aaaa:
            response_ips = response_aaaa if isinstance(response_aaaa, list) else [response_aaaa]

        ttl = g("dns.resp.ttl")
        try:
            ttl = int(ttl) if ttl else None
        except Exception:
            ttl = None

        txid = g("dns.id")
        try:
            txid = int(str(txid), 16) if txid else None
        except Exception:
            txid = None

        rcode_raw = g("dns.flags.rcode")
        rcodes = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN",
                  "4": "NOTIMP", "5": "REFUSED"}
        rcode = rcodes.get(str(rcode_raw), str(rcode_raw)) if rcode_raw else None

        rec = DNSRecord(
            investigation_id=investigation_id,
            timestamp=p.get("timestamp"),
            timestamp_str=p.get("timestamp_str"),
            src_ip=p.get("src_ip"),
            dst_ip=p.get("dst_ip"),
            query_name=str(query_name)[:255] if query_name else None,
            query_type=query_type[:20] if query_type else None,
            is_response=1 if is_resp else 0,
            response_code=rcode,
            ttl=ttl,
            transaction_id=txid,
        )
        rec.response_ips = response_ips
        dns_records.append(rec)

    if dns_records:
        db.bulk_save_objects(dns_records)
        db.commit()

    # Compute statistics
    queries_only = [r for r in dns_records if not r.is_response]
    unique_domains = set(r.query_name for r in queries_only if r.query_name)
    domain_counter = Counter(r.query_name for r in queries_only if r.query_name)
    client_counter = Counter(r.src_ip for r in queries_only if r.src_ip)

    logger.info(f"Extracted {len(dns_records)} DNS records for investigation {investigation_id}")

    return {
        "total_dns_packets": len(dns_records),
        "total_queries": len(queries_only),
        "unique_domains": len(unique_domains),
        "top_queried_domains": domain_counter.most_common(20),
        "top_dns_clients": client_counter.most_common(10),
    }
