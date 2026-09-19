"""
HTTP analyzer — extracts HTTP requests and responses from parsed TShark packets.
"""
import logging
from collections import Counter
from sqlalchemy.orm import Session
from app.models.record import HTTPRecord

logger = logging.getLogger(__name__)


def analyze_http(db: Session, investigation_id: int, parsed_packets: list[dict]) -> dict:
    """Extract HTTP records from parsed packets and store in DB."""
    http_records = []

    for p in parsed_packets:
        layers = p.get("_layers", {})
        if not layers:
            continue

        def g(key, default=None):
            val = layers.get(key, default)
            if isinstance(val, list):
                return val[0] if val else default
            return val

        method = g("http.request.method")
        host = g("http.host")
        uri = g("http.request.uri")
        status_code = g("http.response.code")
        user_agent = g("http.user_agent")
        content_type = g("http.content_type")
        content_length = g("http.content_length")

        # Only process packets that have HTTP data
        if not (method or status_code or host):
            continue

        is_request = 1 if method else 0

        try:
            status_int = int(status_code) if status_code else None
        except Exception:
            status_int = None

        try:
            cl_int = int(content_length) if content_length else None
        except Exception:
            cl_int = None

        rec = HTTPRecord(
            investigation_id=investigation_id,
            timestamp=p.get("timestamp"),
            timestamp_str=p.get("timestamp_str"),
            src_ip=p.get("src_ip"),
            dst_ip=p.get("dst_ip"),
            src_port=p.get("src_port"),
            dst_port=p.get("dst_port"),
            method=str(method)[:10] if method else None,
            host=str(host)[:255] if host else None,
            uri=str(uri)[:2000] if uri else None,
            user_agent=str(user_agent)[:500] if user_agent else None,
            status_code=status_int,
            content_type=str(content_type)[:100] if content_type else None,
            content_length=cl_int,
            is_request=is_request,
        )
        http_records.append(rec)

    if http_records:
        db.bulk_save_objects(http_records)
        db.commit()

    requests = [r for r in http_records if r.is_request]
    responses = [r for r in http_records if not r.is_request]

    host_counter = Counter(r.host for r in requests if r.host)
    uri_counter = Counter(r.uri for r in requests if r.uri)
    method_counter = Counter(r.method for r in requests if r.method)
    status_counter = Counter(r.status_code for r in responses if r.status_code)
    ua_counter = Counter(r.user_agent for r in requests if r.user_agent)

    logger.info(f"Extracted {len(http_records)} HTTP records for investigation {investigation_id}")

    return {
        "total_http_packets": len(http_records),
        "total_requests": len(requests),
        "total_responses": len(responses),
        "top_hosts": host_counter.most_common(10),
        "top_uris": uri_counter.most_common(10),
        "method_distribution": dict(method_counter),
        "status_distribution": dict(status_counter),
        "top_user_agents": ua_counter.most_common(5),
    }
