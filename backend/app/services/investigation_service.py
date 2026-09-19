"""
Investigation Service — orchestrates the full PCAP analysis pipeline.

Pipeline stages:
1. Validate PCAP
2. Run TShark to extract packets
3. Parse and store packets
4. Analyze hosts
5. Analyze conversations
6. Analyze DNS
7. Analyze HTTP
8. Analyze TCP/ICMP
9. Run detection engine
10. Extract IOCs
11. Update investigation with summary stats
"""
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.investigation import Investigation
from app.analyzers.pcap_validator import validate_pcap_file
from app.analyzers.tshark_runner import run_tshark_json, get_pcap_summary
from app.analyzers.packet_analyzer import store_packets
from app.analyzers.host_analyzer import analyze_hosts
from app.analyzers.conversation_analyzer import analyze_conversations
from app.analyzers.dns_analyzer import analyze_dns
from app.analyzers.http_analyzer import analyze_http
from app.analyzers.tcp_icmp_analyzer import analyze_tcp, analyze_icmp
from app.analyzers.detection_engine import run_detection_engine
from app.analyzers.ioc_extractor import extract_iocs
from app.analyzers.traffic_analyzer import analyze_traffic_activity
from app.analyzers.protocol_analyzer import analyze_protocol_activity
from app.models.event import TrafficEvent
from app.models.host import Host
from app.models.alert import Alert
from app.models.record import DNSRecord, HTTPRecord, ICMPRecord
from app.models.ioc import IOC
from app.database.base import SessionLocal

logger = logging.getLogger(__name__)


def _update_status(db: Session, investigation_id: int, status: str, stage: str, progress: int) -> None:
    db.query(Investigation).filter(Investigation.id == investigation_id).update({
        "status": status,
        "current_stage": stage,
        "progress": progress,
        "updated_at": datetime.utcnow(),
    })
    db.commit()


def _update_error(db: Session, investigation_id: int, error_msg: str) -> None:
    db.query(Investigation).filter(Investigation.id == investigation_id).update({
        "status": "failed",
        "error_message": str(error_msg)[:1000],
        "progress": 0,
        "updated_at": datetime.utcnow(),
    })
    db.commit()


def run_analysis_pipeline(investigation_id: int, pcap_path: str, original_filename: str) -> None:
    """
    Full analysis pipeline — runs as a background task.
    Each stage updates the investigation's progress.
    """
    # Use a separate DB session for background tasks
    db = SessionLocal()
    try:
        logger.info(f"Starting analysis pipeline for investigation {investigation_id}")

        # Stage 1: Validate
        _update_status(db, investigation_id, "processing", "Validating PCAP file", 5)
        validation = validate_pcap_file(pcap_path, original_filename)
        if not validation["valid"]:
            _update_error(db, investigation_id, validation["error"])
            return

        # Update hash
        if validation.get("file_hash"):
            db.query(Investigation).filter(Investigation.id == investigation_id).update({
                "file_hash": validation["file_hash"]
            })
            db.commit()

        # Stage 2: Run TShark
        _update_status(db, investigation_id, "processing", "Parsing PCAP with TShark", 15)
        try:
            raw_packets = run_tshark_json(pcap_path)
        except Exception as e:
            _update_error(db, investigation_id, f"TShark parsing failed: {str(e)}")
            return

        if not raw_packets:
            _update_error(db, investigation_id, "No packets found in PCAP file. File may be empty or corrupt.")
            return

        # Stage 3: Store packets
        _update_status(db, investigation_id, "processing", "Storing packet data", 25)
        parsed_packets, packet_summary = store_packets(db, investigation_id, raw_packets)

        # Stage 4: Analyze hosts
        _update_status(db, investigation_id, "processing", "Analyzing hosts", 40)
        host_summary = analyze_hosts(db, investigation_id, parsed_packets)

        # Stage 5: Analyze conversations
        _update_status(db, investigation_id, "processing", "Building conversation flows", 50)
        conv_summary = analyze_conversations(db, investigation_id, parsed_packets)

        # Stage 6: DNS analysis
        _update_status(db, investigation_id, "processing", "Analyzing DNS traffic", 60)
        dns_summary = analyze_dns(db, investigation_id, parsed_packets)

        # Stage 7: HTTP analysis
        _update_status(db, investigation_id, "processing", "Analyzing HTTP traffic", 68)
        http_summary = analyze_http(db, investigation_id, parsed_packets)

        # Stage 8: TCP/ICMP analysis & Protocol breakdown
        _update_status(db, investigation_id, "processing", "Analyzing TCP, ICMP, and Protocol Layers", 75)
        tcp_summary = analyze_tcp(parsed_packets)
        icmp_summary = analyze_icmp(db, investigation_id, parsed_packets)
        protocol_summary = analyze_protocol_activity(db, investigation_id, parsed_packets)

        # Stage 9: Traffic activity analysis & high traffic detection
        _update_status(db, investigation_id, "processing", "Analyzing traffic throughput and rates", 80)
        traffic_summary = analyze_traffic_activity(db, investigation_id, parsed_packets)

        # Stage 10: Detection engine
        _update_status(db, investigation_id, "processing", "Running detection engine", 85)
        alert_count = run_detection_engine(db, investigation_id, parsed_packets)

        # Stage 11: IOC extraction
        _update_status(db, investigation_id, "processing", "Extracting indicators", 90)
        ioc_summary = extract_iocs(db, investigation_id, parsed_packets, dns_summary, http_summary)

        # Stage 12: Populate comprehensive timeline events
        _update_status(db, investigation_id, "processing", "Compiling timeline events", 94)
        _populate_investigation_events(
            db=db,
            investigation_id=investigation_id,
            parsed_packets=parsed_packets,
            host_summary=host_summary,
            traffic_summary=traffic_summary,
            dns_summary=dns_summary,
            http_summary=http_summary,
        )

        # Stage 13: Finalize investigation record
        _update_status(db, investigation_id, "processing", "Finalizing report", 98)

        import json
        metadata = {
            "packet_summary": {k: v for k, v in packet_summary.items() if k != "timeline_buckets"},
            "host_summary": host_summary,
            "conv_summary": conv_summary,
            "traffic_summary": {k: v for k, v in traffic_summary.items() if k != "flows"},
            "top_traffic_flows": traffic_summary.get("flows", [])[:20],
            "protocol_summary": protocol_summary.get("summary", {}),
            "protocol_distribution": protocol_summary.get("distribution", [])[:25],
            "arp_summary": protocol_summary.get("arp_analysis", {}),
            "tls_summary": protocol_summary.get("tls_analysis", {}),
            "dns_summary": {k: v for k, v in dns_summary.items() if not isinstance(v, list)},
            "http_summary": {k: v for k, v in http_summary.items() if not isinstance(v, list)},
            "tcp_summary": {k: v for k, v in tcp_summary.items() if not isinstance(v, list)},
            "icmp_summary": {k: v for k, v in icmp_summary.items() if not isinstance(v, list)},
            "ioc_summary": ioc_summary,
            "protocol_counts": packet_summary.get("protocol_counts", {}),
            "timeline_buckets": packet_summary.get("timeline_buckets", {}),
            # DNS sub-summaries with lists
            "top_dns_domains": dns_summary.get("top_queried_domains", [])[:20],
            "top_dns_clients": dns_summary.get("top_dns_clients", [])[:10],
            "top_http_hosts": http_summary.get("top_hosts", [])[:10],
            "tcp_top_ports": tcp_summary.get("top_destination_ports", [])[:15],
        }

        db.query(Investigation).filter(Investigation.id == investigation_id).update({
            "status": "completed",
            "progress": 100,
            "current_stage": "Analysis complete",
            "total_packets": packet_summary["total_packets"],
            "total_bytes": packet_summary["total_bytes"],
            "unique_hosts": host_summary["unique_hosts"],
            "total_alerts": alert_count + traffic_summary.get("high_traffic_events_count", 0),
            "capture_start": str(packet_summary["capture_start"]) if packet_summary.get("capture_start") else None,
            "capture_end": str(packet_summary["capture_end"]) if packet_summary.get("capture_end") else None,
            "capture_duration": packet_summary.get("capture_duration", 0.0),
            "_metadata_json": json.dumps(metadata),
            "completed_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })
        db.commit()

        logger.info(f"Analysis pipeline completed for investigation {investigation_id}: "
                    f"{packet_summary['total_packets']} packets, {alert_count} alerts")

    except Exception as e:
        logger.exception(f"Unexpected error in analysis pipeline for investigation {investigation_id}: {e}")
        _update_error(db, investigation_id, f"Unexpected analysis error: {str(e)}")
    finally:
        db.close()


def _populate_investigation_events(
    db: Session,
    investigation_id: int,
    parsed_packets: list,
    host_summary: dict,
    traffic_summary: dict,
    dns_summary: dict,
    http_summary: dict,
) -> None:
    """Populates indexed TrafficEvents for the investigation timeline."""
    events_to_save = []
    evt_counter = 100
    base_ts = parsed_packets[0]["timestamp"] if parsed_packets and parsed_packets[0].get("timestamp") else datetime.utcnow().timestamp()

    # 1. Discovered Hosts
    hosts = db.query(Host).filter(Host.investigation_id == investigation_id).all()
    for h in hosts:
        evt_counter += 1
        ts = h.first_seen if h.first_seen else base_ts
        ts_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""
        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=ts,
            timestamp_str=ts_str,
            event_type="HOST_DISCOVERED",
            severity="INFO",
            source_ip="Network",
            destination_ip=h.ip_address,
            protocol=h.protocols[0] if h.protocols else "IP",
            short_explanation=f"Host identified: {h.ip_address} ({h.role or 'Active Endpoint'}).",
            observation=f"Host {h.ip_address} participated in network communication: {h.total_packets} packets, {h.total_bytes} bytes.",
            analysis="Host actively exchanging packets on monitored network segment.",
            recommendation="Review asset inventory records to verify authorized endpoint ownership.",
            packet_count=h.total_packets,
            total_bytes=h.total_bytes,
            duration=0.0,
            evidence={"ip": h.ip_address, "role": h.role, "top_ports": h.top_ports},
        ))

    # 2. Port & Service Discovered from Host Top Ports
    for h in hosts:
        for p in (h.top_ports or []):
            evt_counter += 1
            ts = h.first_seen if h.first_seen else base_ts
            ts_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""
            events_to_save.append(TrafficEvent(
                event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
                investigation_id=investigation_id,
                timestamp=ts,
                timestamp_str=ts_str,
                event_type="PORT_DISCOVERED",
                severity="INFO",
                source_ip="Client",
                destination_ip=h.ip_address,
                destination_port=p,
                protocol="TCP",
                short_explanation=f"Port {p} observed in communication with host {h.ip_address}.",
                observation=f"Traffic directed toward port {p} on {h.ip_address}.",
                analysis=f"Port {p} active on host {h.ip_address}.",
                recommendation=f"Review if service on port {p} is operationally necessary.",
                evidence={"host": h.ip_address, "port": p},
            ))

    # 3. DNS Activity Events
    dns_records = db.query(DNSRecord).filter(DNSRecord.investigation_id == investigation_id).limit(40).all()
    for d in dns_records:
        evt_counter += 1
        ts = d.timestamp or base_ts
        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=ts,
            timestamp_str=d.timestamp_str or datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            event_type="DNS_ACTIVITY",
            severity="INFO",
            source_ip=d.src_ip,
            destination_ip=d.dst_ip,
            destination_port=53,
            protocol="DNS",
            short_explanation=f"DNS {d.query_type or 'A'} query for '{d.query_name or 'domain'}'.",
            observation=f"Client {d.src_ip} queried DNS resolver {d.dst_ip} for {d.query_name}.",
            analysis="Standard DNS resolution query observed.",
            recommendation="Monitor for unauthorized external DNS resolvers or unexpected queries.",
            evidence={"query_name": d.query_name, "query_type": d.query_type, "response_ips": d.response_ips},
        ))

    # 4. HTTP Activity Events
    http_records = db.query(HTTPRecord).filter(HTTPRecord.investigation_id == investigation_id).limit(30).all()
    for h in http_records:
        evt_counter += 1
        ts = h.timestamp or base_ts
        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=ts,
            timestamp_str=h.timestamp_str or datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            event_type="HTTP_ACTIVITY",
            severity="INFO",
            source_ip=h.src_ip,
            destination_ip=h.dst_ip,
            source_port=h.src_port,
            destination_port=h.dst_port or 80,
            protocol="HTTP",
            short_explanation=f"HTTP {h.method or 'GET'} request to {h.host or h.dst_ip}.",
            observation=f"Client requested {h.method} {h.uri or '/'} on host {h.host}.",
            analysis="Unencrypted HTTP web traffic observed.",
            recommendation="Verify whether web endpoints enforce TLS encryption (HTTPS).",
            evidence={"host": h.host, "method": h.method, "uri": h.uri, "status_code": h.status_code},
        ))

    # 5. ICMP Activity Events
    icmp_records = db.query(ICMPRecord).filter(ICMPRecord.investigation_id == investigation_id).limit(20).all()
    for ic in icmp_records:
        evt_counter += 1
        ts = ic.timestamp or base_ts
        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=ts,
            timestamp_str=ic.timestamp_str or datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            event_type="ICMP_ACTIVITY",
            severity="INFO",
            source_ip=ic.src_ip,
            destination_ip=ic.dst_ip,
            protocol="ICMP",
            short_explanation=f"ICMP {ic.icmp_type_name or 'Message'} from {ic.src_ip} to {ic.dst_ip}.",
            observation=f"ICMP type {ic.icmp_type} code {ic.icmp_code} ({ic.icmp_type_name}) transmitted.",
            analysis="ICMP diagnostic or reachability test message.",
            recommendation="Review whether excessive ping probing is authorized.",
            evidence={"type": ic.icmp_type, "type_name": ic.icmp_type_name},
        ))

    # 6. Detection Engine Alerts -> Security Finding & Anomaly Events
    alerts = db.query(Alert).filter(Alert.investigation_id == investigation_id).all()
    for a in alerts:
        evt_counter += 1
        ts = a.first_seen or base_ts
        
        etype = "SECURITY_FINDING"
        if "PORT_SCAN" in (a.detection_rule or ""):
            etype = "POTENTIAL_PORT_SCAN"
        elif "DNS" in (a.detection_rule or ""):
            etype = "UNUSUAL_DNS_ACTIVITY"
        elif "HIGH_TRAFFIC" in (a.detection_rule or ""):
            etype = "HIGH_TRAFFIC"

        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=ts,
            timestamp_str=a.first_seen_str or datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            event_type=etype,
            severity=a.severity.upper() if a.severity else "MEDIUM",
            source_ip=a.src_ip,
            destination_ip=a.dst_ip,
            source_port=a.src_port,
            destination_port=a.dst_port,
            protocol=a.protocol or "TCP",
            short_explanation=a.alert_type,
            observation=a.reason,
            analysis="Heuristic detection rule triggered based on empirical packet patterns.",
            recommendation=a.recommendations,
            evidence=a.evidence or {},
        ))

    # 7. IOC Events
    iocs = db.query(IOC).filter(IOC.investigation_id == investigation_id).limit(30).all()
    for i in iocs:
        evt_counter += 1
        events_to_save.append(TrafficEvent(
            event_id=f"TEV-{investigation_id:04d}-{evt_counter:04d}",
            investigation_id=investigation_id,
            timestamp=base_ts,
            timestamp_str=i.first_seen_str or datetime.utcfromtimestamp(base_ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            event_type="IOC_DETECTED",
            severity="LOW",
            source_ip=i.source_ip,
            destination_ip=None,
            protocol="IP",
            short_explanation=f"Observable indicator ({i.ioc_type}): {i.value}",
            observation=f"Extracted {i.ioc_type} indicator '{i.value}' observed {i.occurrence_count} time(s).",
            analysis="Observable network indicator identified for threat intelligence correlation.",
            recommendation="Correlate indicator against threat intelligence feeds (e.g. AlienVault, VirusTotal).",
            evidence={"type": i.ioc_type, "value": i.value, "occurrences": i.occurrence_count},
        ))

    if events_to_save:
        db.bulk_save_objects(events_to_save)
        db.commit()

