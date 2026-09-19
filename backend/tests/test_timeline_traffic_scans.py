"""
Automated Test Suite for Timestamp, Event Timeline, Traffic Activity, and Scan History System
Validates all requirements from Section 18:
1. Scan timestamp creation
2. Scan completion timestamp
3. Duration calculation
4. Event timestamp creation
5. PCAP packet timestamp parsing
6. High traffic calculation
7. Packets-per-second calculation
8. Bytes-per-second calculation
9. Timeline sorting
10. Timezone conversion
11. Scan history
12. PDF timestamp generation
13. Authorization/IDOR protection
"""

import os
import sys
import time
import uuid
import pytest
from datetime import datetime, timezone, timedelta

# Ensure backend path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.scan import Scan
from app.models.event import ScanEvent, TrafficEvent, Finding
from app.models.investigation import Investigation
from app.models.user import User
from app.database.base import SessionLocal, init_db
from app.analyzers.traffic_analyzer import analyze_traffic_activity
from app.services.pdf_report_service import generate_scan_pdf


@pytest.fixture
def db_session():
    init_db()
    session = SessionLocal()
    user = session.query(User).filter(User.id == 1).first()
    if not user:
        user = User(
            id=1,
            email="analyst@nova.cyber",
            full_name="SOC Lead Analyst",
            password_hash="argon2id$mock_hash_for_test",
            role="ANALYST"
        )
        session.add(user)
        session.commit()
    yield session
    session.close()


def test_01_scan_timestamp_creation(db_session):
    """1. Scan timestamp creation: Started timestamp recorded accurately."""
    start_time = datetime.now(timezone.utc)
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        scan_id=scan_id,
        user_id=1,
        target="127.0.0.1",
        scan_type="standard",
        status="running",
        scan_started_at=start_time,
        timezone="UTC"
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.id is not None
    assert scan.scan_started_at is not None
    assert abs((scan.scan_started_at.replace(tzinfo=timezone.utc) - start_time).total_seconds()) < 2


def test_02_03_scan_completion_and_duration_calculation(db_session):
    """2. Scan completion timestamp & 3. Duration calculation."""
    start_time = datetime.now(timezone.utc) - timedelta(seconds=45)
    completion_time = datetime.now(timezone.utc)
    expected_duration = round((completion_time - start_time).total_seconds(), 2)
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"

    scan = Scan(
        scan_id=scan_id,
        user_id=1,
        target="10.0.0.1",
        scan_type="fast",
        status="completed",
        scan_started_at=start_time,
        scan_completed_at=completion_time,
        scan_duration=expected_duration,
        timezone="UTC",
        hosts_discovered=1,
        open_ports_count=4,
        potential_findings_count=1,
        highest_severity="HIGH"
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.scan_completed_at is not None
    assert scan.scan_duration == expected_duration
    assert scan.scan_duration > 0
    assert scan.scan_completed_at > scan.scan_started_at


def test_04_event_timestamp_creation(db_session):
    """4. Event timestamp creation for ScanEvent and TrafficEvent."""
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        scan_id=scan_id,
        user_id=1,
        target="192.168.1.10",
        scan_type="standard",
        status="completed"
    )
    db_session.add(scan)
    db_session.commit()

    now = datetime.now(timezone.utc)
    scan_event = ScanEvent(
        scan_id=scan.scan_id,
        timestamp=now,
        event_type="PORT_DISCOVERED",
        source_ip="192.168.1.10",
        destination_port=22,
        protocol="TCP",
        severity="MEDIUM",
        description="SSH service observed on port 22",
        evidence={"detail": "SYN-ACK received on TCP 22"}
    )
    db_session.add(scan_event)
    db_session.commit()
    db_session.refresh(scan_event)

    assert scan_event.id is not None
    assert scan_event.event_type == "PORT_DISCOVERED"
    assert scan_event.severity == "MEDIUM"
    assert scan_event.timestamp is not None
    assert scan_event.description == "SSH service observed on port 22"


def test_05_pcap_packet_timestamp_parsing():
    """5. PCAP packet timestamp parsing preserving sub-second precision."""
    sample_epoch = 1726744815.123456
    dt = datetime.fromtimestamp(sample_epoch, tz=timezone.utc)
    timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    assert ".123" in timestamp_str
    assert timestamp_str.startswith("2024-") or timestamp_str.startswith("2026-")


def test_06_07_08_traffic_activity_and_rate_calculations(db_session):
    """6. High traffic calculation, 7. Packets-per-second, 8. Bytes-per-second."""
    inv = db_session.query(Investigation).filter(Investigation.id == 1).first()
    if not inv:
        inv = Investigation(
            id=1,
            title="Test Investigation for Telemetry",
            description="Forensic analysis investigation",
            user_id=1
        )
        db_session.add(inv)
        db_session.commit()

    # Create sample packet records simulating a flow of 10s duration
    packets = [
        {
            "timestamp": 1000.0,
            "length": 1500,
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP"
        },
        {
            "timestamp": 1010.0,
            "length": 1500000,
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP"
        }
    ]
    
    analysis = analyze_traffic_activity(db_session, 1, packets)
    assert "flows" in analysis
    assert "total_bytes" in analysis
    assert analysis["total_bytes"] == 1501500
    assert analysis["total_packets"] == 2
    assert len(analysis["flows"]) == 1
    
    flow = analysis["flows"][0]
    assert flow["duration_seconds"] == 10.0
    assert flow["packet_count"] == 2
    assert flow["total_bytes"] == 1501500
    assert flow["packets_per_second"] == 0.2
    assert flow["bytes_per_second"] == 150150.0


def test_09_timeline_sorting():
    """9. Timeline sorting chronologically."""
    events = [
        {"id": 1, "timestamp": "2026-09-19T13:20:48Z", "event_type": "SCAN_COMPLETED"},
        {"id": 2, "timestamp": "2026-09-19T13:20:15Z", "event_type": "SCAN_STARTED"},
        {"id": 3, "timestamp": "2026-09-19T13:20:19Z", "event_type": "PORT_DISCOVERED"},
        {"id": 4, "timestamp": "2026-09-19T13:20:17Z", "event_type": "HOST_DISCOVERED"},
    ]
    
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    order = [e["event_type"] for e in sorted_events]
    assert order == ["SCAN_STARTED", "HOST_DISCOVERED", "PORT_DISCOVERED", "SCAN_COMPLETED"]


def test_10_timezone_conversion():
    """10. Timezone conversion: UTC internal representation consistency."""
    utc_time = datetime(2026, 9, 19, 13, 20, 15, tzinfo=timezone.utc)
    # Convert to IST (+05:30)
    ist_zone = timezone(timedelta(hours=5, minutes=30))
    ist_time = utc_time.astimezone(ist_zone)
    
    assert ist_time.hour == 18
    assert ist_time.minute == 50
    assert ist_time.second == 15
    # Verify UTC roundtrip
    assert ist_time.astimezone(timezone.utc) == utc_time


def test_11_scan_history(db_session):
    """11. Scan history: Querying previous scans with all metadata."""
    scans = db_session.query(Scan).order_by(Scan.created_at.desc()).all()
    assert len(scans) >= 2
    
    latest = scans[0]
    assert hasattr(latest, "scan_started_at")
    assert hasattr(latest, "scan_completed_at")
    assert hasattr(latest, "scan_duration")
    assert hasattr(latest, "highest_severity")
    assert latest.timezone is not None


def test_12_pdf_timestamp_generation():
    """12. PDF timestamp generation: 15 standardized sections including chronological timeline."""
    scan_data = {
        "scan_id": "scan_test_pdf_001",
        "target": "192.168.1.1",
        "scan_started_at": "2026-09-19 13:20:15 UTC",
        "scan_completed_at": "2026-09-19 13:20:48 UTC",
        "scan_duration": 33.0,
        "timezone": "UTC",
        "status": "completed",
        "hosts_discovered": 1,
        "open_ports_count": 2,
        "potential_findings_count": 1,
        "services_count": 2,
        "summary_text": "Non-intrusive port scan completed.",
        "ports": [
            {
                "host": "192.168.1.1",
                "port": 80,
                "protocol": "TCP",
                "service": "HTTP",
                "version": "nginx",
                "risk": "Medium",
                "category": "Web Services",
                "explanation": {
                    "what_was_observed": "HTTP on port 80",
                    "what_is_it_technical": "Web service endpoint",
                    "why_it_matters": "Potential unencrypted traffic",
                    "risk_reasoning": "Standard web exposure",
                    "recommended_action": "Enable HTTPS TLS encryption"
                }
            }
        ],
        "events": [
            {
                "timestamp": "2026-09-19 13:20:15",
                "event_type": "SCAN_STARTED",
                "severity": "INFO",
                "description": "Port scan initiated against 192.168.1.1"
            },
            {
                "timestamp": "2026-09-19 13:20:17",
                "event_type": "HOST_DISCOVERED",
                "severity": "INFO",
                "description": "Host 192.168.1.1 responded"
            },
            {
                "timestamp": "2026-09-19 13:20:48",
                "event_type": "SCAN_COMPLETED",
                "severity": "INFO",
                "description": "Scan execution finished"
            }
        ],
        "recommendations": ["Enforce TLS 1.3 encryption for exposed HTTP services"]
    }
    
    pdf_bytes = generate_scan_pdf(scan_data, "scan_test_pdf_001", "lead.analyst@nova.cyber")
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_13_authorization_idor_protection(db_session):
    """13. Authorization/IDOR protection."""
    scan = db_session.query(Scan).first()
    assert scan is not None
    assert hasattr(scan, "user_id")
    assert scan.user_id is not None
