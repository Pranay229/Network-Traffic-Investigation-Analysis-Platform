"""
Traffic Activity Analyzer & High Traffic Detection Engine
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Calculates real empirical flow telemetry and identifies high-traffic anomalies
with strictly evidence-based, non-alarmist security analysis.
"""
import logging
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.event import TrafficEvent
from app.models.alert import Alert
from app.config import settings

logger = logging.getLogger(__name__)


def _format_bytes(size: float) -> str:
    """Format bytes into readable units."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _format_rate(bytes_per_sec: float) -> str:
    return f"{_format_bytes(bytes_per_sec)}/s"


def _ts_to_iso(ts: float | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def analyze_traffic_activity(
    db: Session,
    investigation_id: int,
    parsed_packets: List[Dict[str, Any]],
    thresholds: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Analyzes bidirectional packet streams to compute exact flow telemetry
    and detect high-traffic occurrences against configurable thresholds.
    """
    if thresholds is None:
        thresholds = {}

    byte_rate_limit = thresholds.get("high_byte_rate", settings.HIGH_BYTE_RATE_THRESHOLD)
    packet_rate_limit = thresholds.get("high_packet_rate", settings.HIGH_PACKET_RATE_THRESHOLD)
    large_transfer_limit = thresholds.get("large_data_transfer", settings.LARGE_DATA_TRANSFER_THRESHOLD)
    conn_rate_limit = thresholds.get("high_connection_rate", settings.HIGH_CONNECTION_RATE_THRESHOLD)

    # 1. Group packets by bidirectional socket flow (src_ip, dst_ip, protocol, src_port, dst_port)
    flows: Dict[Tuple, Dict[str, Any]] = {}
    host_syn_counter: Dict[str, List[float]] = defaultdict(list)

    total_bytes = 0
    min_overall_ts = None
    max_overall_ts = None

    for p in parsed_packets:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        if not src or not dst:
            continue

        proto = p.get("protocol", "UNKNOWN")
        sp = p.get("src_port")
        dp = p.get("dst_port")
        length = p.get("length", 0)
        ts = p.get("timestamp", 0.0)
        flags = p.get("tcp_flags") or ""

        total_bytes += length
        if ts > 0:
            if min_overall_ts is None or ts < min_overall_ts:
                min_overall_ts = ts
            if max_overall_ts is None or ts > max_overall_ts:
                max_overall_ts = ts

        # Track SYN connection attempts
        if "SYN" in flags and "ACK" not in flags and ts > 0:
            host_syn_counter[src].append(ts)

        # Normalize flow pair
        ep1 = (src, sp or 0)
        ep2 = (dst, dp or 0)
        if ep1 > ep2:
            ep1, ep2 = ep2, ep1
        flow_key = (ep1[0], ep2[0], proto, ep1[1], ep2[1])

        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": ep1[0],
                "dst_ip": ep2[0],
                "src_port": ep1[1] if ep1[1] != 0 else None,
                "dst_port": ep2[1] if ep2[1] != 0 else None,
                "protocol": proto,
                "packet_count": 0,
                "total_bytes": 0,
                "first_observed": ts if ts > 0 else None,
                "last_observed": ts if ts > 0 else None,
            }

        f = flows[flow_key]
        f["packet_count"] += 1
        f["total_bytes"] += length
        if ts > 0:
            if f["first_observed"] is None or ts < f["first_observed"]:
                f["first_observed"] = ts
            if f["last_observed"] is None or ts > f["last_observed"]:
                f["last_observed"] = ts

    # 2. Compute metrics for each flow
    flow_metrics: List[Dict[str, Any]] = []
    generated_events: List[TrafficEvent] = []
    generated_alerts: List[Alert] = []
    event_counter = 0

    for flow_key, f in flows.items():
        first_ts = f["first_observed"] or 0.0
        last_ts = f["last_observed"] or first_ts
        duration = max(last_ts - first_ts, 0.001) if (first_ts and last_ts and last_ts > first_ts) else 1.0

        pps = round(f["packet_count"] / duration, 2)
        bps = round(f["total_bytes"] / duration, 2)

        flow_entry = {
            "source_ip": f["src_ip"],
            "destination_ip": f["dst_ip"],
            "source_port": f["src_port"],
            "destination_port": f["dst_port"],
            "protocol": f["protocol"],
            "first_observed": first_ts,
            "first_observed_str": _ts_to_iso(first_ts),
            "last_observed": last_ts,
            "last_observed_str": _ts_to_iso(last_ts),
            "duration": round(duration, 2),
            "duration_seconds": round(duration, 2),
            "packet_count": f["packet_count"],
            "total_bytes": f["total_bytes"],
            "total_bytes_str": _format_bytes(f["total_bytes"]),
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "average_rate_str": _format_rate(bps),
        }
        flow_metrics.append(flow_entry)

        # 3. Check for High Traffic Conditions
        is_high_bytes = bps >= byte_rate_limit
        is_high_pps = pps >= packet_rate_limit
        is_large_transfer = f["total_bytes"] >= large_transfer_limit

        if is_high_bytes or is_high_pps or is_large_transfer:
            event_counter += 1
            evt_id = f"TEV-{investigation_id:04d}-{event_counter:04d}"

            reasons = []
            if is_high_bytes:
                reasons.append(f"Transfer rate ({_format_rate(bps)}) exceeded threshold ({_format_rate(byte_rate_limit)})")
            if is_high_pps:
                reasons.append(f"Packet frequency ({pps:,.0f} pps) exceeded threshold ({packet_rate_limit:,.0f} pps)")
            if is_large_transfer:
                reasons.append(f"Cumulative volume ({_format_bytes(f['total_bytes'])}) exceeded threshold ({_format_bytes(large_transfer_limit)})")

            short_expl = f"Traffic volume exceeded the configured threshold: {', '.join(reasons)}."
            obs = (
                f"Observed {f['packet_count']:,} packets ({_format_bytes(f['total_bytes'])}) "
                f"between {f['src_ip']}:{f['src_port'] or 'any'} and {f['dst_ip']}:{f['dst_port'] or 'any'} "
                f"across {round(duration, 1)} seconds (average throughput: {_format_rate(bps)}, {pps:,.1f} pps)."
            )
            analysis = (
                "Potentially unusual traffic volume detected. This may represent legitimate high-bandwidth "
                "data transfer (e.g. database backup, media streaming, patch distribution, large file copy) "
                "or abnormal network activity (e.g. bulk data exfiltration, automated flooding). "
                "Additional context is required before determining whether it represents a security incident."
            )
            rec = (
                "1. Verify the business purpose and identity of the source and destination endpoints.\n"
                "2. Correlate with scheduled operational backups or scheduled system updates.\n"
                "3. Inspect session content or host network sockets if authorization permits.\n"
                "4. Check whether the destination endpoint is a known internal repository or untrusted external IP."
            )

            severity = "HIGH" if (is_high_bytes and is_large_transfer) else "MEDIUM"

            evt = TrafficEvent(
                event_id=evt_id,
                investigation_id=investigation_id,
                timestamp=first_ts,
                timestamp_str=_ts_to_iso(first_ts),
                event_type="HIGH_TRAFFIC",
                severity=severity,
                source_ip=f["src_ip"],
                destination_ip=f["dst_ip"],
                source_port=f["src_port"],
                destination_port=f["dst_port"],
                protocol=f["protocol"],
                short_explanation=short_expl,
                observation=obs,
                analysis=analysis,
                recommendation=rec,
                packet_count=f["packet_count"],
                total_bytes=f["total_bytes"],
                duration=round(duration, 2),
                packets_per_second=pps,
                bytes_per_second=bps,
                evidence={
                    "threshold_byte_rate": byte_rate_limit,
                    "threshold_packet_rate": packet_rate_limit,
                    "threshold_large_transfer": large_transfer_limit,
                    "observed_byte_rate": bps,
                    "observed_packet_rate": pps,
                    "observed_total_bytes": f["total_bytes"],
                },
            )
            generated_events.append(evt)

            # Mirror to Alert table for SOC investigation
            alt = Alert(
                investigation_id=investigation_id,
                alert_id=f"ALT-TRF-{investigation_id:04d}-{event_counter:04d}",
                severity=severity.lower(),
                alert_type="High Traffic Volume Exceeded",
                detection_rule="HIGH_TRAFFIC_VOLUME",
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                src_port=f["src_port"],
                dst_port=f["dst_port"],
                protocol=f["protocol"],
                first_seen=first_ts,
                last_seen=last_ts,
                first_seen_str=_ts_to_iso(first_ts),
                reason=f"{short_expl} {analysis}",
                recommendations=rec,
                status="new",
            )
            alt.evidence = evt.evidence
            generated_alerts.append(alt)

    # 4. Connection Rate Anomaly Check
    for host_ip, syn_times in host_syn_counter.items():
        if len(syn_times) >= conn_rate_limit:
            syn_times.sort()
            window_duration = max(syn_times[-1] - syn_times[0], 0.001)
            conn_rate = round(len(syn_times) / window_duration, 2)
            if conn_rate >= 5.0 or len(syn_times) >= conn_rate_limit:
                event_counter += 1
                evt_id = f"TEV-{investigation_id:04d}-{event_counter:04d}"
                short_expl = f"Connection attempt rate from {host_ip} exceeded configured threshold."
                obs = f"Host {host_ip} initiated {len(syn_times)} TCP connection attempts within {round(window_duration, 1)}s."
                analysis = (
                    "High connection rates can be caused by aggressive multi-threaded applications, "
                    "benchmarking utilities, API load testing, or scanning/reconnaissance activity. "
                    "Analyst review is recommended to establish context."
                )
                rec = (
                    "1. Confirm if the client host is running authorized automated tools or microservice communication.\n"
                    "2. Check destination ports targeted by the connections.\n"
                    "3. Review corresponding firewall or service connection logs."
                )
                evt = TrafficEvent(
                    event_id=evt_id,
                    investigation_id=investigation_id,
                    timestamp=syn_times[0],
                    timestamp_str=_ts_to_iso(syn_times[0]),
                    event_type="EXCESSIVE_CONNECTIONS",
                    severity="LOW",
                    source_ip=host_ip,
                    destination_ip=None,
                    source_port=None,
                    destination_port=None,
                    protocol="TCP",
                    short_explanation=short_expl,
                    observation=obs,
                    analysis=analysis,
                    recommendation=rec,
                    packet_count=len(syn_times),
                    total_bytes=len(syn_times) * 60,
                    duration=round(window_duration, 2),
                    packets_per_second=conn_rate,
                    bytes_per_second=round(conn_rate * 60, 2),
                    evidence={"syn_count": len(syn_times), "duration": window_duration, "rate": conn_rate},
                )
                generated_events.append(evt)

    # Persist generated high-traffic events and alerts
    if generated_events:
        db.bulk_save_objects(generated_events)
        db.commit()

    if generated_alerts:
        db.bulk_save_objects(generated_alerts)
        db.commit()

    # Sort flow metrics by total bytes descending
    flow_metrics.sort(key=lambda x: x["total_bytes"], reverse=True)

    overall_duration = (max_overall_ts - min_overall_ts) if (min_overall_ts and max_overall_ts) else 1.0
    overall_pps = round(len(parsed_packets) / overall_duration, 2) if overall_duration > 0 else 0.0
    overall_bps = round(total_bytes / overall_duration, 2) if overall_duration > 0 else 0.0

    return {
        "flows": flow_metrics,
        "total_flows": len(flow_metrics),
        "total_packets": len(parsed_packets),
        "total_bytes": total_bytes,
        "total_bytes_str": _format_bytes(total_bytes),
        "capture_duration": round(overall_duration, 2),
        "packets_per_second": overall_pps,
        "bytes_per_second": overall_bps,
        "average_throughput_str": _format_rate(overall_bps),
        "high_traffic_events_count": len(generated_events),
        "first_observed": min_overall_ts,
        "first_observed_str": _ts_to_iso(min_overall_ts),
        "last_observed": max_overall_ts,
        "last_observed_str": _ts_to_iso(max_overall_ts),
    }
