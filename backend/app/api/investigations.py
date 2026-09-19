"""
Investigation management API routes with strict RBAC and IDOR/BOLA authorization.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.base import get_db
from app.models.investigation import Investigation
from app.models.alert import Alert
from app.models.packet import Packet
from app.models.host import Host
from app.models.conversation import Conversation
from app.models.record import DNSRecord, HTTPRecord, ICMPRecord
from app.models.ioc import IOC
from app.models.event import TrafficEvent
from app.models.protocol import ARPRecord, TLSMetadata
from app.models.user import User
from app.analyzers.report_generator import generate_report
from app.services.audit_service import audit_service
from app.api.deps import (
    get_current_active_user,
    check_investigation_access,
    check_investigation_deletion_access,
    require_role,
    get_client_ip,
    get_user_agent
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _format_inv(inv: Investigation) -> dict:
    meta = inv.metadata_dict
    return {
        "id": inv.id,
        "inv_id": inv.inv_id,
        "user_id": inv.user_id,
        "owner_email": inv.owner.email if inv.owner else None,
        "filename": inv.original_filename,
        "file_size": inv.file_size,
        "file_hash": inv.file_hash,
        "status": inv.status,
        "progress": inv.progress,
        "current_stage": inv.current_stage,
        "error_message": inv.error_message,
        "total_packets": inv.total_packets,
        "total_bytes": inv.total_bytes,
        "unique_hosts": inv.unique_hosts,
        "total_alerts": inv.total_alerts,
        "capture_start": inv.capture_start,
        "capture_end": inv.capture_end,
        "capture_duration": inv.capture_duration,
        "investigation_status": inv.investigation_status or "OPEN",
        "severity": inv.severity or "INFO",
        "related_scan_id": inv.related_scan_id,
        "notes": inv.notes,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
    }


@router.get("")
def list_investigations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    List investigations.
    - ADMIN: Can see all investigations across the platform.
    - ANALYST / VIEWER: Can see their own investigations plus legacy unassigned records.
    """
    if current_user.role == "ADMIN":
        investigations = db.query(Investigation).order_by(Investigation.created_at.desc()).all()
    else:
        investigations = db.query(Investigation).filter(
            (Investigation.user_id == current_user.id) | (Investigation.user_id.is_(None))
        ).order_by(Investigation.created_at.desc()).all()

    return [_format_inv(i) for i in investigations]


@router.get("/{inv_id}")
def get_investigation(
    inv: Investigation = Depends(check_investigation_access)
):
    return _format_inv(inv)


@router.get("/{inv_id}/overview")
def get_overview(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    meta = inv.metadata_dict
    proto_counts = meta.get("protocol_counts", {})
    timeline = meta.get("timeline_buckets", {})

    # Build timeline as sorted list
    timeline_data = sorted([
        {"timestamp": int(k), "packets": v}
        for k, v in timeline.items()
    ], key=lambda x: x["timestamp"])

    # Protocol distribution for chart
    proto_chart = [
        {"protocol": k, "count": v}
        for k, v in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    # Alert counts by severity
    alert_severities = {}
    for sev in ("high", "medium", "low", "informational"):
        alert_severities[sev] = db.query(Alert).filter(
            Alert.investigation_id == inv.id,
            Alert.severity == sev,
        ).count()

    return {
        "investigation": _format_inv(inv),
        "kpi": {
            "total_packets": inv.total_packets,
            "total_bytes": inv.total_bytes,
            "unique_hosts": inv.unique_hosts,
            "total_alerts": inv.total_alerts,
            "capture_duration": inv.capture_duration,
            "dns_queries": meta.get("dns_summary", {}).get("total_queries", 0),
            "http_requests": meta.get("http_summary", {}).get("total_requests", 0),
            "tcp_packets": proto_counts.get("TCP", 0),
            "udp_packets": proto_counts.get("UDP", 0),
            "icmp_packets": proto_counts.get("ICMP", 0),
        },
        "protocol_distribution": proto_chart,
        "traffic_timeline": timeline_data,
        "alert_severities": alert_severities,
        "packets_per_second": meta.get("packet_summary", {}).get("packets_per_second", 0),
    }


@router.get("/{inv_id}/packets")
def get_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    protocol: str = Query(None),
    src_ip: str = Query(None),
    dst_ip: str = Query(None),
    src_port: int = Query(None),
    dst_port: int = Query(None),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    q = db.query(Packet).filter(Packet.investigation_id == inv.id)

    if protocol:
        q = q.filter(Packet.protocol.ilike(f"%{protocol}%"))
    if src_ip:
        q = q.filter(Packet.src_ip.contains(src_ip))
    if dst_ip:
        q = q.filter(Packet.dst_ip.contains(dst_ip))
    if src_port:
        q = q.filter(Packet.src_port == src_port)
    if dst_port:
        q = q.filter(Packet.dst_port == dst_port)

    total = q.count()
    packets = q.order_by(Packet.frame_number).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "packets": [
            {
                "id": p.id,
                "frame_number": p.frame_number,
                "timestamp": p.timestamp,
                "timestamp_str": p.timestamp_str,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "protocol": p.protocol,
                "length": p.length,
                "tcp_flags": p.tcp_flags,
                "info": p.info,
            }
            for p in packets
        ],
    }




@router.get("/{inv_id}/hosts")
def get_hosts(
    search: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: str = Query("total_packets"),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    q = db.query(Host).filter(Host.investigation_id == inv.id)

    if search:
        q = q.filter(Host.ip_address.contains(search))

    sort_col = getattr(Host, sort_by, Host.total_packets)
    total = q.count()
    hosts = q.order_by(sort_col.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "hosts": [
            {
                "id": h.id,
                "ip_address": h.ip_address,
                "role": h.role,
                "total_packets": h.total_packets,
                "total_bytes": h.total_bytes,
                "packets_sent": h.packets_sent,
                "packets_received": h.packets_received,
                "bytes_sent": h.bytes_sent,
                "bytes_received": h.bytes_received,
                "unique_dest_ips": h.unique_dest_ips,
                "unique_dest_ports": h.unique_dest_ports,
                "connection_count": h.connection_count,
                "alert_count": h.alert_count,
                "protocols": h.protocols,
                "top_ports": h.top_ports,
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
            }
            for h in hosts
        ],
    }


@router.get("/{inv_id}/hosts/{ip}")
def get_host_detail(
    ip: str,
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    host = db.query(Host).filter(Host.investigation_id == inv.id, Host.ip_address == ip).first()
    if not host:
        raise HTTPException(status_code=404, detail=f"Host {ip} not found in this investigation.")

    alerts = db.query(Alert).filter(
        Alert.investigation_id == inv.id,
        (Alert.src_ip == ip) | (Alert.dst_ip == ip)
    ).all()

    dns_queries = db.query(DNSRecord).filter(
        DNSRecord.investigation_id == inv.id,
        DNSRecord.src_ip == ip,
    ).limit(20).all()

    http_reqs = db.query(HTTPRecord).filter(
        HTTPRecord.investigation_id == inv.id,
        HTTPRecord.src_ip == ip,
    ).limit(20).all()

    conversations = db.query(Conversation).filter(
        Conversation.investigation_id == inv.id,
        (Conversation.src_ip == ip) | (Conversation.dst_ip == ip)
    ).limit(20).all()

    return {
        "host": {
            "ip_address": host.ip_address, "role": host.role,
            "total_packets": host.total_packets, "total_bytes": host.total_bytes,
            "protocols": host.protocols, "top_ports": host.top_ports,
            "first_seen": host.first_seen, "last_seen": host.last_seen,
            "connection_count": host.connection_count,
        },
        "alerts": [
            {"alert_id": a.alert_id, "severity": a.severity, "type": a.alert_type, "status": a.status}
            for a in alerts
        ],
        "dns_queries": [
            {"name": r.query_name, "type": r.query_type, "timestamp": r.timestamp_str}
            for r in dns_queries
        ],
        "http_requests": [
            {"method": r.method, "host": r.host, "uri": r.uri, "status": r.status_code}
            for r in http_reqs
        ],
        "conversations": [
            {
                "src_ip": c.src_ip, "dst_ip": c.dst_ip, "protocol": c.protocol,
                "dst_port": c.dst_port, "total_packets": c.total_packets,
            }
            for c in conversations
        ],
    }


@router.get("/{inv_id}/conversations")
def get_conversations(
    protocol: str = Query(None),
    ip: str = Query(None),
    port: int = Query(None),
    sort_by: str = Query("total_packets"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    q = db.query(Conversation).filter(Conversation.investigation_id == inv.id)

    if protocol:
        q = q.filter(Conversation.protocol.ilike(f"%{protocol}%"))
    if ip:
        q = q.filter((Conversation.src_ip.contains(ip)) | (Conversation.dst_ip.contains(ip)))
    if port:
        q = q.filter((Conversation.src_port == port) | (Conversation.dst_port == port))

    # Support all required sort dimensions
    sort_mapping = {
        "total_packets": Conversation.total_packets,
        "total_bytes": Conversation.total_bytes,
        "duration": Conversation.duration,
        "syn_count": Conversation.syn_count,
        "connection_count": Conversation.syn_count,
        "end_time": Conversation.end_time,
        "latest_activity": Conversation.end_time,
    }
    sort_col = sort_mapping.get(sort_by, Conversation.total_packets)
    total = q.count()
    convs = q.order_by(sort_col.desc()).offset((page - 1) * page_size).limit(page_size).all()

    formatted_convs = []
    for c in convs:
        dur = max(c.duration or 0.0, 0.001)
        pps = round(c.total_packets / dur, 2)
        bps = round(c.total_bytes / dur, 2)
        formatted_convs.append({
            "id": c.id,
            "src_ip": c.src_ip,
            "dst_ip": c.dst_ip,
            "src_port": c.src_port,
            "dst_port": c.dst_port,
            "protocol": c.protocol,
            "total_packets": c.total_packets,
            "total_bytes": c.total_bytes,
            "packets_a_to_b": c.packets_a_to_b,
            "packets_b_to_a": c.packets_b_to_a,
            "start_time": c.start_time,
            "end_time": c.end_time,
            "duration": c.duration,
            "syn_count": c.syn_count,
            "connection_count": max(c.syn_count, 1),
            "rst_count": c.rst_count,
            "fin_count": c.fin_count,
            "packets_per_second": pps,
            "bytes_per_second": bps,
        })

    return {
        "total": total,
        "page": page,
        "conversations": formatted_convs,
    }


@router.get("/{inv_id}/dns")
def get_dns(
    search: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    meta = inv.metadata_dict

    q = db.query(DNSRecord).filter(DNSRecord.investigation_id == inv.id)
    if search:
        q = q.filter(DNSRecord.query_name.contains(search))

    total = q.count()
    records = q.order_by(DNSRecord.timestamp).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "summary": {
            "total_dns_packets": meta.get("dns_summary", {}).get("total_dns_packets", 0),
            "total_queries": meta.get("dns_summary", {}).get("total_queries", 0),
            "unique_domains": meta.get("dns_summary", {}).get("unique_domains", 0),
            "top_queried_domains": meta.get("top_dns_domains", []),
            "top_dns_clients": meta.get("top_dns_clients", []),
        },
        "records": [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "timestamp_str": r.timestamp_str,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "query_name": r.query_name,
                "query_type": r.query_type,
                "is_response": bool(r.is_response),
                "response_code": r.response_code,
                "response_ips": r.response_ips,
                "ttl": r.ttl,
            }
            for r in records
        ],
    }


@router.get("/{inv_id}/http")
def get_http(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    meta = inv.metadata_dict

    q = db.query(HTTPRecord).filter(HTTPRecord.investigation_id == inv.id, HTTPRecord.is_request == 1)
    total = q.count()
    records = q.order_by(HTTPRecord.timestamp).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "summary": {
            "total_requests": meta.get("http_summary", {}).get("total_requests", 0),
            "total_responses": meta.get("http_summary", {}).get("total_responses", 0),
            "top_hosts": meta.get("top_http_hosts", []),
            "method_distribution": meta.get("http_summary", {}).get("method_distribution", {}),
        },
        "records": [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "timestamp_str": r.timestamp_str,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "method": r.method,
                "host": r.host,
                "uri": r.uri,
                "user_agent": r.user_agent,
                "status_code": r.status_code,
            }
            for r in records
        ],
    }


@router.get("/{inv_id}/tcp")
def get_tcp(
    inv: Investigation = Depends(check_investigation_access)
):
    meta = inv.metadata_dict
    tcp = meta.get("tcp_summary", {})
    return {
        "total_tcp_packets": tcp.get("total_tcp_packets", 0),
        "syn_count": tcp.get("syn_count", 0),
        "syn_ack_count": tcp.get("syn_ack_count", 0),
        "ack_count": tcp.get("ack_count", 0),
        "fin_count": tcp.get("fin_count", 0),
        "rst_count": tcp.get("rst_count", 0),
        "psh_count": tcp.get("psh_count", 0),
        "estimated_connections": tcp.get("estimated_connections", 0),
        "estimated_established": tcp.get("estimated_established", 0),
        "reset_connections": tcp.get("reset_connections", 0),
        "top_destination_ports": meta.get("tcp_top_ports", []),
    }


@router.get("/{inv_id}/icmp")
def get_icmp(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    meta = inv.metadata_dict
    icmp = meta.get("icmp_summary", {})

    records = db.query(ICMPRecord).filter(ICMPRecord.investigation_id == inv.id).limit(200).all()

    return {
        "summary": {
            "total_icmp_packets": icmp.get("total_icmp_packets", 0),
            "echo_requests": icmp.get("echo_requests", 0),
            "echo_replies": icmp.get("echo_replies", 0),
        },
        "records": [
            {
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "type": r.icmp_type,
                "code": r.icmp_code,
                "type_name": r.icmp_type_name,
                "timestamp": r.timestamp_str or str(r.timestamp),
            }
            for r in records
        ],
    }


@router.get("/{inv_id}/alerts")
def get_alerts(
    severity: str = Query(None),
    status: str = Query(None),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.investigation_id == inv.id)

    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)

    alerts = q.order_by(
        Alert.severity.desc(),
        Alert.created_at.desc(),
    ).all()

    return [
        {
            "id": a.id,
            "alert_id": a.alert_id,
            "severity": a.severity,
            "alert_type": a.alert_type,
            "detection_rule": a.detection_rule,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": a.src_port,
            "dst_port": a.dst_port,
            "protocol": a.protocol,
            "first_seen": a.first_seen,
            "first_seen_str": a.first_seen_str,
            "last_seen": a.last_seen,
            "evidence": a.evidence,
            "reason": a.reason,
            "recommendations": a.recommendations,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]


@router.patch("/{inv_id}/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    body: dict,
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    # Viewers cannot modify alerts
    if current_user.role == "VIEWER":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Viewers cannot update alert statuses.")

    alert = db.query(Alert).filter(
        Alert.investigation_id == inv.id,
        Alert.alert_id == alert_id,
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    allowed_statuses = {"new", "investigating", "resolved"}
    new_status = body.get("status")
    if new_status and new_status in allowed_statuses:
        alert.status = new_status
        db.commit()

    return {"alert_id": alert_id, "status": alert.status}


@router.get("/{inv_id}/timeline")
def get_timeline(
    category: str = Query("all"),
    severity: str = Query("all"),
    src_ip: str = Query(None),
    dst_ip: str = Query(None),
    protocol: str = Query(None),
    start_time: float = Query(None),
    end_time: float = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    """
    Returns ordered, chronological security and network events from TrafficEvent table.
    Supports filtering by category, severity, IP endpoints, protocol, and time range.
    """
    q = db.query(TrafficEvent).filter(TrafficEvent.investigation_id == inv.id)

    # Category filter
    cat = (category or "all").lower()
    if cat == "network":
        q = q.filter(TrafficEvent.event_type.in_(["HOST_DISCOVERED", "PORT_DISCOVERED", "SERVICE_DETECTED"]))
    elif cat == "dns":
        q = q.filter(TrafficEvent.event_type.in_(["DNS_ACTIVITY", "UNUSUAL_DNS_ACTIVITY"]))
    elif cat == "http":
        q = q.filter(TrafficEvent.event_type == "HTTP_ACTIVITY")
    elif cat == "tcp":
        q = q.filter(TrafficEvent.event_type.in_(["TCP_CONNECTION", "TCP_RESET", "EXCESSIVE_CONNECTIONS"]))
    elif cat == "icmp":
        q = q.filter(TrafficEvent.event_type == "ICMP_ACTIVITY")
    elif cat in ("findings", "alerts"):
        q = q.filter(TrafficEvent.event_type.in_(["SECURITY_FINDING", "POTENTIAL_PORT_SCAN", "UNUSUAL_DNS_ACTIVITY", "HIGH_TRAFFIC"]))
    elif cat == "iocs":
        q = q.filter(TrafficEvent.event_type == "IOC_DETECTED")
    elif cat in ("traffic", "high_traffic"):
        q = q.filter(TrafficEvent.event_type.in_(["HIGH_TRAFFIC", "HIGH_PACKET_RATE", "EXCESSIVE_CONNECTIONS"]))

    # Severity filter
    sev = (severity or "all").upper()
    if sev != "ALL":
        q = q.filter(TrafficEvent.severity == sev)

    # IP Filters
    if src_ip:
        q = q.filter(TrafficEvent.source_ip.contains(src_ip))
    if dst_ip:
        q = q.filter(TrafficEvent.destination_ip.contains(dst_ip))
    if protocol:
        q = q.filter(TrafficEvent.protocol.ilike(f"%{protocol}%"))

    # Time range
    if start_time is not None:
        q = q.filter(TrafficEvent.timestamp >= start_time)
    if end_time is not None:
        q = q.filter(TrafficEvent.timestamp <= end_time)

    traffic_events = q.order_by(TrafficEvent.timestamp.asc()).limit(limit).all()

    # Fallback to packets and alerts for legacy investigations
    if not traffic_events:
        fallback_events = []
        pq = db.query(Packet).filter(Packet.investigation_id == inv.id)
        if src_ip:
            pq = pq.filter(Packet.src_ip.contains(src_ip))
        if dst_ip:
            pq = pq.filter(Packet.dst_ip.contains(dst_ip))
        if protocol:
            pq = pq.filter(Packet.protocol.ilike(f"%{protocol}%"))
        sample_packets = pq.order_by(Packet.timestamp.asc()).limit(150).all()

        for p in sample_packets:
            fallback_events.append({
                "id": p.id,
                "event_id": f"PKT-{p.id}",
                "type": "packet",
                "event_type": f"{p.protocol}_PACKET",
                "timestamp": p.timestamp,
                "timestamp_str": p.timestamp_str,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "source_ip": p.src_ip,
                "destination_ip": p.dst_ip,
                "protocol": p.protocol,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "short_explanation": p.info or f"{p.protocol} packet",
                "description": p.info or f"{p.protocol} packet",
                "observation": f"Observed {p.protocol} packet of length {p.length} bytes.",
                "analysis": "Standard captured packet frame.",
                "recommendation": "Inspect protocol headers and payload hash if anomaly suspected.",
                "severity": "INFO",
                "packet_count": 1,
                "total_bytes": p.length,
                "duration": 0.0,
            })

        for a in db.query(Alert).filter(Alert.investigation_id == inv.id).all():
            fallback_events.append({
                "id": a.id,
                "event_id": a.alert_id,
                "type": "alert",
                "event_type": "SECURITY_FINDING",
                "timestamp": a.first_seen,
                "timestamp_str": a.first_seen_str,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "source_ip": a.src_ip,
                "destination_ip": a.dst_ip,
                "protocol": a.protocol,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "short_explanation": a.alert_type,
                "description": f"[ALERT] {a.alert_type}: {a.src_ip or 'N/A'}",
                "observation": a.reason,
                "analysis": "Heuristic detection rule triggered based on empirical pattern.",
                "recommendation": a.recommendations,
                "severity": a.severity.upper() if a.severity else "MEDIUM",
                "packet_count": 0,
                "total_bytes": 0,
                "duration": 0.0,
            })

        fallback_events.sort(key=lambda x: x["timestamp"] or 0.0)
        return {"total": len(fallback_events), "events": fallback_events}

    return {
        "total": len(traffic_events),
        "events": [e.to_dict() for e in traffic_events]
    }


@router.get("/{inv_id}/traffic-activity")
def get_traffic_activity(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """
    Returns real, calculated traffic activity metrics, top flows, and rate statistics.
    """
    meta = inv.metadata_dict
    traffic_summary = meta.get("traffic_summary")
    top_flows = meta.get("top_traffic_flows", [])

    # If traffic_summary is missing (legacy investigation), calculate on the fly
    if not traffic_summary:
        from app.analyzers.traffic_analyzer import analyze_traffic_activity
        packets = db.query(Packet).filter(Packet.investigation_id == inv.id).all()
        parsed_mock = [
            {
                "src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port,
                "dst_port": p.dst_port, "protocol": p.protocol, "length": p.length,
                "timestamp": p.timestamp, "tcp_flags": p.tcp_flags
            }
            for p in packets
        ]
        res = analyze_traffic_activity(db, inv.id, parsed_mock)
        traffic_summary = {k: v for k, v in res.items() if k != "flows"}
        top_flows = res.get("flows", [])[:20]

    from app.config import settings as s
    return {
        "summary": traffic_summary,
        "top_flows": top_flows,
        "thresholds": {
            "high_packet_rate": s.HIGH_PACKET_RATE_THRESHOLD,
            "high_byte_rate": s.HIGH_BYTE_RATE_THRESHOLD,
            "high_connection_rate": s.HIGH_CONNECTION_RATE_THRESHOLD,
            "large_data_transfer": s.LARGE_DATA_TRANSFER_THRESHOLD,
        }
    }


@router.get("/{inv_id}/iocs")
def get_iocs(
    ioc_type: str = Query(None),
    search: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
):
    q = db.query(IOC).filter(IOC.investigation_id == inv.id)

    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)
    if search:
        q = q.filter(IOC.value.contains(search))

    total = q.count()
    iocs = q.order_by(IOC.occurrence_count.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "note": "These are OBSERVED indicators only. NOT confirmed malicious without threat intelligence enrichment.",
        "iocs": [
            {
                "id": i.id,
                "type": i.ioc_type,
                "value": i.value,
                "first_seen": i.first_seen_str,
                "last_seen": i.last_seen_str,
                "source_ip": i.source_ip,
                "context": i.context,
                "occurrences": i.occurrence_count,
            }
            for i in iocs
        ],
    }


@router.get("/{inv_id}/report")
def get_report(
    request: Request,
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    if inv.status != "completed":
        raise HTTPException(status_code=400, detail="Investigation is not yet complete.")

    report_md = generate_report(db, inv.id)
    
    # Audit log report access
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit_service.log_event(
        db=db,
        event_type="REPORT_GENERATION",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="Investigation",
        resource_id=str(inv.id),
        metadata={"inv_id": inv.inv_id, "filename": inv.original_filename}
    )
    db.commit()

    return {
        "inv_id": inv.inv_id,
        "filename": inv.original_filename,
        "report": report_md,
    }


@router.get("/{inv_id}/protocols")
def get_protocols(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """
    Returns full protocol analysis for the investigation.
    Includes distribution, core network breakdown, application protocols, ARP table, and TLS metadata.
    """
    from app.analyzers.protocol_analyzer import analyze_protocol_activity
    packets = db.query(Packet).filter(Packet.investigation_id == inv.id).all()
    parsed_pkts = [
        {
            "src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port,
            "dst_port": p.dst_port, "protocol": p.protocol, "app_protocol": p.app_protocol,
            "length": p.length, "timestamp": p.timestamp, "tcp_flags": p.tcp_flags,
            "info": p.info,
        }
        for p in packets
    ]
    res = analyze_protocol_activity(db, inv.id, parsed_pkts)
    dist = res.get("distribution", [])
    total_pkts = res["summary"]["total_packets"]

    res["protocols"] = [
        {
            "protocol": d["protocol"],
            "packets": d["packet_count"],
            "bytes": d["total_bytes"],
            "percentage": d["packet_percentage"],
            "first_seen": d["first_observed_str"],
            "last_seen": d["last_observed_str"],
        }
        for d in dist
    ]
    res["total_packets"] = total_pkts
    res["total_bytes"] = res["summary"]["total_bytes"]

    core_list = [d for d in res["protocols"] if d["protocol"] in ["IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"]]
    web_list = [d for d in res["protocols"] if d["protocol"] in ["HTTP", "HTTPS/TLS"]]
    srv_list = [d for d in res["protocols"] if d["protocol"] in ["DNS", "DHCP", "NTP", "SNMP"]]
    rem_list = [d for d in res["protocols"] if d["protocol"] in ["SSH", "FTP", "SMTP", "SMB"]]
    oth_list = [d for d in res["protocols"] if d not in core_list and d not in web_list and d not in srv_list and d not in rem_list]

    res["categories"] = {
        "core_network": core_list,
        "web_traffic": web_list,
        "network_services": srv_list,
        "remote_access": rem_list,
        "other": oth_list,
    }

    proto_map = {d["protocol"]: d["packets"] for d in res["protocols"]}
    res["summary"]["tcp_packets"] = proto_map.get("TCP", 0)
    res["summary"]["udp_packets"] = proto_map.get("UDP", 0)
    res["summary"]["icmp_packets"] = proto_map.get("ICMP", 0)
    res["summary"]["arp_packets"] = proto_map.get("ARP", 0)
    res["summary"]["dns_packets"] = proto_map.get("DNS", 0)
    res["summary"]["http_packets"] = proto_map.get("HTTP", 0)
    res["summary"]["tls_packets"] = proto_map.get("HTTPS/TLS", 0)
    res["summary"]["ssh_packets"] = proto_map.get("SSH", 0)

    meta = inv.metadata_dict
    proto_counts = meta.get("protocol_counts", {})
    timeline = meta.get("timeline_buckets", {})
    res["protocol_counts"] = proto_counts
    res["timeline"] = sorted([
        {"timestamp": int(k), "packets": v}
        for k, v in timeline.items()
    ], key=lambda x: x["timestamp"])
    res["packets_per_second"] = meta.get("packet_summary", {}).get("packets_per_second", 0)
    res["capture_duration"] = inv.capture_duration

    return res


@router.get("/{inv_id}/traffic-engine")
def get_traffic_engine(
    window: str = Query("30s"),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """
    Returns reusable traffic engine metrics with sliding time-window slicing (5s, 30s, 1m, 5m).
    """
    from app.analyzers.traffic_engine import compute_traffic_engine_metrics
    packets = db.query(Packet).filter(Packet.investigation_id == inv.id).all()
    parsed_pkts = [
        {
            "src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port,
            "dst_port": p.dst_port, "protocol": p.protocol, "length": p.length,
            "timestamp": p.timestamp, "tcp_flags": p.tcp_flags
        }
        for p in packets
    ]
    return compute_traffic_engine_metrics(parsed_pkts, window=window)


@router.get("/{inv_id}/security-events")
def get_security_events(
    severity: str = Query(None),
    event_type: str = Query(None),
    protocol: str = Query(None),
    source_ip: str = Query(None),
    destination_ip: str = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """
    Returns centralized security events with multi-field filtering.
    """
    q = db.query(TrafficEvent).filter(TrafficEvent.investigation_id == inv.id)
    if severity and severity.upper() != "ALL":
        q = q.filter(TrafficEvent.severity == severity.upper())
    if event_type and event_type.upper() != "ALL":
        q = q.filter(TrafficEvent.event_type == event_type.upper())
    if protocol:
        q = q.filter(TrafficEvent.protocol.ilike(f"%{protocol}%"))
    if source_ip:
        q = q.filter(TrafficEvent.source_ip.contains(source_ip))
    if destination_ip:
        q = q.filter(TrafficEvent.destination_ip.contains(destination_ip))

    events = q.order_by(TrafficEvent.timestamp.asc()).limit(limit).all()
    return {
        "total": len(events),
        "events": [e.to_dict() for e in events]
    }


@router.patch("/{inv_id}/status")
def update_investigation_status(
    body: dict,
    request: Request,
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Updates investigation workflow status: OPEN | INVESTIGATING | CONTAINED | RESOLVED | CLOSED
    """
    if current_user.role == "VIEWER":
        raise HTTPException(status_code=403, detail="Viewers cannot update investigation status.")

    allowed = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}
    new_status = (body.get("status") or "").upper()
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {sorted(list(allowed))}")

    old_status = inv.investigation_status
    inv.investigation_status = new_status
    db.commit()

    # Log audit event
    audit_service.log_event(
        db=db,
        event_type="INVESTIGATION_STATUS_CHANGED",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        resource_type="Investigation",
        resource_id=str(inv.id),
        metadata={"old_status": old_status, "new_status": new_status}
    )

    return {"inv_id": inv.inv_id, "investigation_status": inv.investigation_status}


@router.post("/{inv_id}/notes")
def add_investigation_note(
    body: dict,
    request: Request,
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Adds an analyst note to the investigation workspace.
    """
    if current_user.role == "VIEWER":
        raise HTTPException(status_code=403, detail="Viewers cannot add investigation notes.")

    note_text = (body.get("text") or body.get("note") or "").strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="Note text cannot be empty.")

    current_notes = inv.notes
    import uuid
    new_note = {
        "id": f"note_{uuid.uuid4().hex[:8]}",
        "author": current_user.full_name or current_user.email,
        "author_email": current_user.email,
        "text": note_text,
        "note": note_text,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    current_notes.append(new_note)
    inv.notes = current_notes
    db.commit()

    # Audit log
    audit_service.log_event(
        db=db,
        event_type="INVESTIGATION_NOTE_ADDED",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        resource_type="Investigation",
        resource_id=str(inv.id),
        metadata={"note_id": new_note["id"]}
    )

    return {
        "message": "Note added successfully.",
        "inv_id": inv.inv_id,
        "note": new_note,
        "notes": inv.notes,
        "total_notes": len(inv.notes)
    }


@router.get("/{inv_id}/arp")
def get_arp_records(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """Returns ARP telemetry and address resolution history."""
    records = db.query(ARPRecord).filter(ARPRecord.investigation_id == inv.id).order_by(ARPRecord.timestamp.asc()).all()
    dict_records = [r.to_dict() for r in records]
    return {
        "total": len(dict_records),
        "arp_records": dict_records,
    }


@router.get("/{inv_id}/tls")
def get_tls_metadata(
    inv: Investigation = Depends(check_investigation_access),
    db: Session = Depends(get_db)
):
    """Returns TLS handshakes, SNIs, and version metadata."""
    records = db.query(TLSMetadata).filter(TLSMetadata.investigation_id == inv.id).order_by(TLSMetadata.timestamp.asc()).all()
    dict_records = [r.to_dict() for r in records]
    return {
        "total": len(dict_records),
        "tls_metadata": dict_records,
    }


@router.get("/{inv_id}/pcap")
def download_pcap(
    inv: Investigation = Depends(check_investigation_access),
    current_user: User = Depends(get_current_active_user)
):
    """
    Secure download endpoint for the uploaded PCAP file.
    Enforces authorization check and serves via FileResponse with attachment disposition.
    """
    pcap_path = Path(inv.pcap_path)
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail="PCAP file not found on disk.")
    
    return FileResponse(
        path=str(pcap_path),
        filename=inv.original_filename,
        media_type="application/vnd.tcpdump.pcap"
    )


@router.delete("/{inv_id}")
def delete_investigation(
    request: Request,
    inv: Investigation = Depends(check_investigation_deletion_access),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Deletes an investigation.
    Only the owner (creator) or an ADMIN can delete an investigation.
    """
    # Delete PCAP file from disk safely
    try:
        pcap = Path(inv.pcap_path)
        if pcap.exists():
            pcap.unlink()
    except Exception as e:
        logger.warning(f"Could not delete PCAP file: {e}")

    inv_id_str = inv.inv_id
    db_id = inv.id
    db.delete(inv)
    
    # Audit log
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit_service.log_event(
        db=db,
        event_type="INVESTIGATION_DELETED",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="Investigation",
        resource_id=str(db_id),
        metadata={"inv_id": inv_id_str}
    )
    
    db.commit()
    return {"message": f"Investigation {inv_id_str} deleted."}


# ─── Settings ────────────────────────────────────────────────────────────────

settings_router = APIRouter()


@settings_router.get("")
def get_settings(
    current_user: User = Depends(get_current_active_user)
):
    from app.config import settings as s
    return {
        "port_scan_min_ports": s.PORT_SCAN_MIN_PORTS,
        "port_scan_time_window": s.PORT_SCAN_TIME_WINDOW,
        "dns_query_threshold": s.DNS_QUERY_THRESHOLD,
        "icmp_threshold": s.ICMP_THRESHOLD,
        "tcp_conn_threshold": s.TCP_CONN_THRESHOLD,
        "high_conn_threshold": s.HIGH_CONN_THRESHOLD,
        "long_dns_query_len": s.LONG_DNS_QUERY_LEN,
        "high_subdomain_count": s.HIGH_SUBDOMAIN_COUNT,
        "high_packet_rate_threshold": s.HIGH_PACKET_RATE_THRESHOLD,
        "high_byte_rate_threshold": s.HIGH_BYTE_RATE_THRESHOLD,
        "high_connection_rate_threshold": s.HIGH_CONNECTION_RATE_THRESHOLD,
        "large_data_transfer_threshold": s.LARGE_DATA_TRANSFER_THRESHOLD,
        "tshark_path": s.TSHARK_PATH,
        "tshark_available": s.tshark_available(),
        "max_upload_size_mb": s.MAX_UPLOAD_SIZE_MB,
    }


@settings_router.put("")
def update_settings(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["ADMIN"]))
):
    """
    Only administrators can modify detection heuristics settings.
    """
    from app.config import settings as s
    allowed = [
        "port_scan_min_ports", "port_scan_time_window", "dns_query_threshold",
        "icmp_threshold", "tcp_conn_threshold", "high_conn_threshold",
        "long_dns_query_len", "high_subdomain_count",
        "high_packet_rate_threshold", "high_byte_rate_threshold",
        "high_connection_rate_threshold", "large_data_transfer_threshold",
    ]
    changes = {}
    for key in allowed:
        env_key = key.upper()
        if key in body:
            try:
                val = int(body[key])
                setattr(s, env_key, val)
                changes[key] = val
            except Exception:
                pass

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit_service.log_event(
        db=db,
        event_type="DETECTION_SETTINGS_UPDATED",
        user_id=admin_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"changes": changes}
    )
    db.commit()

    return get_settings(current_user=admin_user)
