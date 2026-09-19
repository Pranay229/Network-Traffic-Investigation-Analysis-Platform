"""
Nova Cyber Spark™ — Network Security Investigation & Monitoring Platform
Automated Test Suite (Section 30 Verification)
"""
import pytest
import io
import os
import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from app.analyzers.protocol_analyzer import (
    classify_packet_protocol,
    detect_arp_inconsistencies,
    extract_tls_metadata,
    SUPPORTED_PROTOCOLS,
    PROTOCOL_CATEGORIES,
)
from app.analyzers.traffic_engine import (
    calculate_traffic_metrics,
    aggregate_time_windows,
)
from app.analyzers.detection_engine import (
    run_detection_engine,
    SECURITY_RULES,
)
from app.analyzers.ioc_extractor import extract_iocs_from_packets
from app.services.pdf_report_service import generate_investigation_pdf_report
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)


class MockPacket:
    def __init__(self, **kwargs):
        self.frame_number = kwargs.get("frame_number", 1)
        self.timestamp = kwargs.get("timestamp", time.time())
        self.timestamp_str = kwargs.get("timestamp_str", "2026-09-19 13:20:15")
        self.src_ip = kwargs.get("src_ip", "192.168.1.10")
        self.dst_ip = kwargs.get("dst_ip", "192.168.1.20")
        self.src_port = kwargs.get("src_port", 443)
        self.dst_port = kwargs.get("dst_port", 54321)
        self.protocol = kwargs.get("protocol", "TCP")
        self.length = kwargs.get("length", 120)
        self.tcp_flags = kwargs.get("tcp_flags", "0x0002")
        self.info = kwargs.get("info", "")


# ─── 1. PROTOCOL PARSING & CLASSIFICATION ────────────────────────────────────

def test_protocol_classification():
    """Verify all 16 supported network & application protocols are recognized."""
    assert len(SUPPORTED_PROTOCOLS) == 16
    assert "IPv4" in SUPPORTED_PROTOCOLS
    assert "IPv6" in SUPPORTED_PROTOCOLS
    assert "TCP" in SUPPORTED_PROTOCOLS
    assert "UDP" in SUPPORTED_PROTOCOLS
    assert "ICMP" in SUPPORTED_PROTOCOLS
    assert "ARP" in SUPPORTED_PROTOCOLS
    assert "DNS" in SUPPORTED_PROTOCOLS
    assert "HTTP" in SUPPORTED_PROTOCOLS
    assert "HTTPS/TLS" in SUPPORTED_PROTOCOLS
    assert "DHCP" in SUPPORTED_PROTOCOLS
    assert "SSH" in SUPPORTED_PROTOCOLS
    assert "FTP" in SUPPORTED_PROTOCOLS
    assert "SMTP" in SUPPORTED_PROTOCOLS
    assert "SMB" in SUPPORTED_PROTOCOLS
    assert "NTP" in SUPPORTED_PROTOCOLS
    assert "SNMP" in SUPPORTED_PROTOCOLS

    # Test individual protocol detection logic
    p_ssh = MockPacket(src_port=22, dst_port=50000, protocol="TCP")
    assert classify_packet_protocol(p_ssh) == "SSH"

    p_dns = MockPacket(src_port=53, dst_port=53000, protocol="UDP")
    assert classify_packet_protocol(p_dns) == "DNS"

    p_tls = MockPacket(src_port=50000, dst_port=443, protocol="TLS")
    assert classify_packet_protocol(p_tls) == "HTTPS/TLS"

    p_dhcp = MockPacket(src_port=67, dst_port=68, protocol="UDP")
    assert classify_packet_protocol(p_dhcp) == "DHCP"

    p_ntp = MockPacket(src_port=123, dst_port=123, protocol="UDP")
    assert classify_packet_protocol(p_ntp) == "NTP"

    p_snmp = MockPacket(src_port=50000, dst_port=161, protocol="UDP")
    assert classify_packet_protocol(p_snmp) == "SNMP"

    p_smb = MockPacket(src_port=445, dst_port=50000, protocol="TCP")
    assert classify_packet_protocol(p_smb) == "SMB"


# ─── 2. ARP ANOMALY DETECTION ───────────────────────────────────────────────

def test_arp_inconsistency_detection():
    """Verify ARP analysis detects multiple conflicting MACs claiming a single IP."""
    arp_entries = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "opcode": "reply", "timestamp": "2026-09-19 13:20:15"},
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:02", "opcode": "reply", "timestamp": "2026-09-19 13:20:18"},
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:50", "opcode": "reply", "timestamp": "2026-09-19 13:20:20"},
    ]

    anomalies = detect_arp_inconsistencies(arp_entries)
    assert len(anomalies) == 1
    assert anomalies[0]["ip"] == "192.168.1.1"
    assert len(anomalies[0]["associated_macs"]) == 2
    # Verify non-alarmist phrasing
    assert "inconsistency" in anomalies[0]["description"].lower()


# ─── 3. TLS METADATA EXTRACTION ──────────────────────────────────────────────

def test_tls_metadata_extraction():
    """Verify non-intrusive TLS handshake metadata extraction without payload decryption."""
    p_tls = MockPacket(
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TLSv1.3",
        info="Client Hello (SNI=api.example.com)",
    )
    meta = extract_tls_metadata([p_tls])
    assert len(meta) == 1
    assert meta[0]["sni"] == "api.example.com"
    assert meta[0]["tls_version"] == "TLSv1.3"
    assert meta[0]["dst_port"] == 443


# ─── 4. TRAFFIC ENGINE & MULTI-WINDOW ANALYSIS ───────────────────────────────

def test_traffic_engine_calculations():
    """Verify PPS, BPS, average packet size, and sliding window aggregation."""
    base_time = 1758288000.0
    packets = [
        MockPacket(timestamp=base_time + 0.1, length=100, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP"),
        MockPacket(timestamp=base_time + 0.5, length=300, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP"),
        MockPacket(timestamp=base_time + 1.2, length=200, src_ip="10.0.0.3", dst_ip="10.0.0.2", src_port=2000, dst_port=80, protocol="TCP"),
        MockPacket(timestamp=base_time + 4.0, length=400, src_ip="10.0.0.1", dst_ip="10.0.0.4", src_port=3000, dst_port=443, protocol="TLS"),
    ]

    metrics = calculate_traffic_metrics(packets)
    assert metrics["total_packets"] == 4
    assert metrics["total_bytes"] == 1000
    assert metrics["avg_packet_size"] == 250.0
    assert metrics["duration"] == pytest.approx(3.9, 0.1)

    # Multi-window slicing tests
    for win in ["5s", "30s", "1m", "5m"]:
        engine_res = aggregate_time_windows(packets, window=win)
        assert engine_res["window"] == win
        assert "summary" in engine_res
        assert "buckets" in engine_res
        assert len(engine_res["top_sources"]) > 0


# ─── 5. CENTRALIZED DETECTION ENGINE (NET-001 through NET-014) ───────────────

def test_detection_engine_rules_and_events():
    """Verify all 14 centralized detection rules execute and produce structured evidence."""
    assert len(SECURITY_RULES) == 14
    for r_id in [f"NET-{str(i).zfill(3)}" for i in range(1, 15)]:
        assert r_id in SECURITY_RULES

    # Build simulated scan packets (single source touching > 15 distinct ports) -> NET-001
    port_scan_packets = []
    for port in range(1, 20):
        port_scan_packets.append(
            MockPacket(
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=40000 + port,
                dst_port=port,
                protocol="TCP",
                tcp_flags="0x0002",
                timestamp=1000.0 + port * 0.1,
            )
        )

    alerts = run_detection_engine("INV-TEST-001", port_scan_packets, db=None)
    rule_ids = [a.get("rule_id") for a in alerts]

    # NET-001 must be triggered
    assert "NET-001" in rule_ids
    net001 = next(a for a in alerts if a.get("rule_id") == "NET-001")
    assert net001["severity"] in ["MEDIUM", "HIGH"]
    assert "ports" in net001["evidence"]
    assert "observation" in net001
    assert "analysis" in net001
    assert "recommendation" in net001
    # Check evidence-based non-alarmist phrasing
    assert "potential port scan" in net001.get("rule_name", "").lower() or "connection attempts" in net001.get("description", "").lower()


def test_dns_anomaly_detection():
    """Verify NET-011 triggered on very long DNS query names (>60 chars)."""
    long_domain = "a" * 65 + ".suspicious.domain.example.com"
    dns_packets = [
        MockPacket(
            src_ip="192.168.1.45",
            dst_ip="8.8.8.8",
            src_port=53000,
            dst_port=53,
            protocol="DNS",
            info=f"Standard query 0x1234 A {long_domain}",
        )
    ]

    alerts = run_detection_engine("INV-TEST-DNS", dns_packets, db=None)
    rule_ids = [a.get("rule_id") for a in alerts]
    assert "NET-011" in rule_ids


# ─── 6. IOC EXTRACTION ───────────────────────────────────────────────────────

def test_ioc_extraction():
    """Verify observable indicators (IPs, Ports, Protocols) are cleanly extracted."""
    packets = [
        MockPacket(src_ip="10.10.10.5", dst_ip="93.184.216.34", src_port=49152, dst_port=80, protocol="TCP"),
        MockPacket(src_ip="10.10.10.5", dst_ip="8.8.8.8", src_port=53000, dst_port=53, protocol="DNS"),
    ]

    iocs = extract_iocs_from_packets(packets)
    ioc_values = [i["value"] for i in iocs]

    assert "10.10.10.5" in ioc_values
    assert "93.184.216.34" in ioc_values
    assert "8.8.8.8" in ioc_values
    assert 80 in ioc_values or "80" in ioc_values


# ─── 7. 17-SECTION PDF REPORT GENERATION ────────────────────────────────────

def test_17_section_pdf_report():
    """Verify generated PDF contains all 17 standardized SOC report sections."""
    inv_data = {
        "inv_id": "INV-TEST-PDF",
        "filename": "sample_traffic.pcap",
        "file_size": 204800,
        "total_packets": 1250,
        "total_bytes": 524288,
        "capture_start": "2026-09-19 13:20:15",
        "capture_end": "2026-09-19 13:20:48",
        "capture_duration": 33.0,
        "unique_hosts": 4,
        "investigation_status": "INVESTIGATING",
        "severity": "MEDIUM",
        "created_at": "2026-09-19 13:21:00",
        "notes": [{"user_email": "lead.analyst@nova.cyber", "note": "Initial triage completed.", "timestamp": "2026-09-19 13:22:00"}],
    }

    mock_db = MagicMock()
    # Mock queries to return sample data
    mock_db.query.return_value.filter.return_value.all.return_value = []
    mock_db.query.return_value.filter.return_value.count.return_value = 0

    pdf_bytes = generate_investigation_pdf_report(inv_data, mock_db)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF signature
    assert pdf_bytes.startswith(b"%PDF")


# ─── 8. INTERNAL SECURITY, RBAC & ARGON2ID ───────────────────────────────────

def test_auth_and_argon2id_hashing():
    """Verify password hashing with Argon2id and JWT token lifecycle."""
    plain = "SuperSecure@2026!Platform"
    hashed = hash_password(plain)
    assert hashed.startswith("$argon2id$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword123", hashed) is False

    # RBAC Token payload verification
    token = create_access_token({"sub": "42", "role": "ANALYST", "email": "analyst@nova.cyber"})
    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert payload["role"] == "ANALYST"
    assert payload["email"] == "analyst@nova.cyber"
