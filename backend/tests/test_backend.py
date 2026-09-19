"""
Basic backend tests.
Run: cd backend && python -m pytest tests/ -v
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─── PCAP Validator Tests ─────────────────────────────────────────────────────

def test_validate_pcap_invalid_extension(tmp_path):
    from app.analyzers.pcap_validator import validate_pcap_file
    f = tmp_path / "test.txt"
    f.write_bytes(b"hello")
    result = validate_pcap_file(str(f), "test.txt")
    assert not result["valid"]
    assert "Unsupported file type" in result["error"]


def test_validate_pcap_empty_file(tmp_path):
    from app.analyzers.pcap_validator import validate_pcap_file
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"")
    result = validate_pcap_file(str(f), "empty.pcap")
    assert not result["valid"]
    assert "empty" in result["error"].lower()


def test_validate_pcap_invalid_magic(tmp_path):
    from app.analyzers.pcap_validator import validate_pcap_file
    f = tmp_path / "fake.pcap"
    f.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 100)
    result = validate_pcap_file(str(f), "fake.pcap")
    assert not result["valid"]
    assert "magic" in result["error"].lower()


def test_validate_pcap_valid_magic(tmp_path):
    from app.analyzers.pcap_validator import validate_pcap_file
    f = tmp_path / "valid.pcap"
    # Write pcap magic bytes + dummy data
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    result = validate_pcap_file(str(f), "valid.pcap")
    assert result["valid"]
    assert result["format"] == "pcap"


# ─── Packet Analyzer Tests ────────────────────────────────────────────────────

def test_parse_tshark_packet_basic():
    from app.analyzers.packet_analyzer import parse_tshark_packet
    raw = {
        "_source": {
            "layers": {
                "frame.number": "1",
                "frame.time_epoch": "1700000000.0",
                "frame.time": "2023-11-14 00:00:00",
                "frame.len": "74",
                "ip.src": "192.168.1.1",
                "ip.dst": "8.8.8.8",
                "tcp.srcport": "54321",
                "tcp.dstport": "80",
                "tcp.flags": "0x002",
                "frame.protocols": "eth:ip:tcp",
                "_ws.col.Info": "SYN packet",
            }
        }
    }
    result = parse_tshark_packet(raw)
    assert result is not None
    assert result["src_ip"] == "192.168.1.1"
    assert result["dst_ip"] == "8.8.8.8"
    assert result["src_port"] == 54321
    assert result["dst_port"] == 80
    assert result["protocol"] == "TCP"
    assert result["tcp_flags"] == "SYN"
    assert result["length"] == 74


def test_parse_tshark_packet_empty():
    from app.analyzers.packet_analyzer import parse_tshark_packet
    result = parse_tshark_packet({})
    # Should not crash, returns None or partial result
    # Empty packet may return None or a basic dict


def test_decode_tcp_flags():
    from app.analyzers.packet_analyzer import _decode_tcp_flags
    assert _decode_tcp_flags("0x002") == "SYN"
    assert _decode_tcp_flags("0x012") == "SYN-ACK"
    assert _decode_tcp_flags("0x011") in ("FIN-ACK", "ACK-FIN")
    assert _decode_tcp_flags("0x004") == "RST"


# ─── Detection Engine Tests ───────────────────────────────────────────────────

def test_detect_port_scan():
    from app.analyzers.detection_engine import detect_port_scans

    # Simulate port scan: one source hitting 15 ports on same dest within 30s
    packets = []
    for port in range(20, 36):
        packets.append({
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "dst_port": port,
            "tcp_flags": "SYN",
            "timestamp": 1700000000.0 + (port - 20) * 0.5,
            "protocol": "TCP",
        })

    alerts = detect_port_scans(packets, {"port_scan_min_ports": 10, "port_scan_time_window": 60})
    assert len(alerts) >= 1
    assert alerts[0]["rule"] == "PORT_SCAN"
    assert alerts[0]["src_ip"] == "10.0.0.1"


def test_no_port_scan_few_ports():
    from app.analyzers.detection_engine import detect_port_scans

    packets = []
    for port in [80, 443]:
        packets.append({
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "dst_port": port,
            "tcp_flags": "SYN",
            "timestamp": 1700000000.0,
            "protocol": "TCP",
        })

    alerts = detect_port_scans(packets, {"port_scan_min_ports": 10, "port_scan_time_window": 60})
    assert len(alerts) == 0


def test_detect_icmp_anomaly():
    from app.analyzers.detection_engine import detect_icmp_anomalies

    packets = [
        {"src_ip": "10.0.0.1", "protocol": "ICMP", "timestamp": 1700000000.0 + i}
        for i in range(150)
    ]
    alerts = detect_icmp_anomalies(packets, {"icmp_threshold": 100})
    assert len(alerts) >= 1
    assert alerts[0]["rule"] == "HIGH_ICMP"


# ─── IOC Extractor Tests ──────────────────────────────────────────────────────

def test_ioc_ip_extraction(tmp_path):
    """Test that IPs are extracted as IOCs from packet list."""
    # This test uses the DB, so we use an in-memory SQLite
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database.base import Base
    from app.models import investigation, packet, host, conversation, record, alert, ioc

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Create a dummy investigation
    from app.models.investigation import Investigation
    inv = Investigation(
        inv_id="TEST-001", filename="test.pcap", original_filename="test.pcap",
        pcap_path="/tmp/test.pcap", file_size=100, status="completed",
    )
    db.add(inv)
    db.commit()

    packets = [
        {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "DNS",
         "timestamp": 1700000000.0, "length": 100, "src_port": 54321, "dst_port": 53,
         "_layers": {}},
    ]

    from app.analyzers.ioc_extractor import extract_iocs
    result = extract_iocs(db, inv.id, packets, {}, {})

    assert result["total_iocs"] >= 2  # At least src and dst IPs
    db.close()


# ─── API Tests ────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Create test client with seeded database."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database.base import init_db, SessionLocal
    from app.models.user import User
    from app.utils.security import hash_password
    
    init_db()
    db = SessionLocal()
    # Check if test user exists
    user = db.query(User).filter(User.id == 1).first()
    if not user:
        user = User(
            id=1,
            email="test@soc.local",
            full_name="Test Analyst",
            hashed_password=hash_password("TestAnalystPass@2026!"),
            role="ANALYST",
            is_active=True,
            is_email_verified=True
        )
        db.add(user)
        db.commit()
    db.close()
    
    return TestClient(app)


@pytest.fixture
def auth_headers():
    from app.utils.security import create_access_token
    token = create_access_token({"sub": "1", "email": "test@soc.local", "role": "ANALYST"})
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_list_investigations_empty(client, auth_headers):
    response = client.get("/api/investigations", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_upload_invalid_extension(client, tmp_path, auth_headers):
    f = tmp_path / "test.txt"
    f.write_text("not a pcap")
    with open(f, "rb") as fp:
        response = client.post("/api/pcap/upload", files={"file": ("test.txt", fp, "text/plain")}, headers=auth_headers)
    assert response.status_code == 400


def test_upload_empty_file(client, tmp_path, auth_headers):
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"")
    with open(f, "rb") as fp:
        response = client.post("/api/pcap/upload", files={"file": ("empty.pcap", fp, "application/octet-stream")}, headers=auth_headers)
    assert response.status_code == 400


def test_investigation_not_found(client, auth_headers):
    response = client.get("/api/investigations/INV-9999-9999", headers=auth_headers)
    assert response.status_code == 404


# ─── Network Scanner & Finding Explanation Tests ──────────────────────────────

def test_finding_explanation_service():
    from app.services.scanner_service import get_finding_explanation
    
    # Test SSH explanation
    ssh_expl = get_finding_explanation(22, "TCP")
    assert ssh_expl["service"] == "SSH"
    assert ssh_expl["risk"] == "LOW"
    assert "remote" in ssh_expl["what_is_it_beginner"].lower()
    assert "encrypted" in ssh_expl["why_it_matters"].lower() or "administration" in ssh_expl["why_it_matters"].lower()
    assert "vulnerable" not in ssh_expl["what_was_observed"].lower()
    
    # Test SMB explanation
    smb_expl = get_finding_explanation(445, "TCP")
    assert smb_expl["service"] == "SMB"
    assert smb_expl["risk"] == "MEDIUM"
    assert "file" in smb_expl["what_is_it_beginner"].lower()
    assert "vulnerable" not in smb_expl["risk_reasoning"].lower()
    
    # Test Telnet explanation
    telnet_expl = get_finding_explanation(23, "TCP")
    assert telnet_expl["service"] == "Telnet"
    assert telnet_expl["risk"] == "HIGH"


def test_pdf_generation_service():
    from app.services.pdf_report_service import generate_scan_pdf
    
    sample_scan_data = {
        "target": "192.168.1.0/24",
        "scan_type": "standard",
        "started_at": "2026-09-17 12:00:00 UTC",
        "completed_at": "2026-09-17 12:00:05 UTC",
        "duration_seconds": 5.2,
        "hosts_discovered": 2,
        "open_ports_count": 3,
        "services_count": 3,
        "potential_findings_count": 3,
        "hosts": [
            {
                "ip": "192.168.1.10",
                "hostname": "gateway.local",
                "status": "up",
                "open_ports": [22, 80, 443],
                "findings_count": 3
            }
        ],
        "ports": [
            {
                "host": "192.168.1.10",
                "port": 22,
                "protocol": "TCP",
                "service": "SSH",
                "state": "open",
                "version": "OpenSSH 9.2",
                "risk": "LOW"
            },
            {
                "host": "192.168.1.10",
                "port": 80,
                "protocol": "TCP",
                "service": "HTTP",
                "state": "open",
                "version": "nginx/1.24.0",
                "risk": "LOW"
            },
            {
                "host": "192.168.1.10",
                "port": 443,
                "protocol": "TCP",
                "service": "HTTPS",
                "state": "open",
                "version": "nginx/1.24.0",
                "risk": "INFO"
            }
        ],
        "findings": [
            {
                "finding_id": "F-001",
                "host": "192.168.1.10",
                "port": 22,
                "service": "SSH",
                "severity": "LOW",
                "description": "TCP port 22 open.",
                "why_it_matters": "Provides administrative access.",
                "risk_reasoning": "Standard remote management.",
                "what_is_it_technical": "Secure Shell encrypted channel.",
                "recommended_action": "Use public key authentication."
            }
        ],
        "risk_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 2,
            "info": 1,
            "total_findings": 3
        },
        "recommendations": [
            "Review SSH access controls and disable password authentication.",
            "Enforce HTTP-to-HTTPS redirection on web ports."
        ],
        "summary_text": "Scan of 192.168.1.0/24 discovered 2 hosts and 3 services.",
        "methodology": {
            "scanner": "Nova Cyber Spark Scanner",
            "scan_type": "STANDARD",
            "ports_examined_count": 26
        },
        "limitations": "Scan observations only. Open ports do not prove compromise."
    }
    
    pdf_bytes = generate_scan_pdf(sample_scan_data, "SCAN-TEST-001", "analyst@soc.local")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")


def test_scan_api_endpoints(client, auth_headers):
    # 1. Run Scan on localhost
    run_res = client.post("/api/scans/run", json={"target": "127.0.0.1", "scan_type": "fast"}, headers=auth_headers)
    assert run_res.status_code == 201
    run_data = run_res.json()
    assert "scan_id" in run_data
    scan_id = run_data["scan_id"]
    assert "results" in run_data
    assert "findings" in run_data["results"]
    assert "methodology" in run_data["results"]

    # 2. List Scans
    list_res = client.get("/api/scans", headers=auth_headers)
    assert list_res.status_code == 200
    scans_list = list_res.json()
    assert any(s["scan_id"] == scan_id for s in scans_list)

    # 3. Call Results
    results_res = client.get(f"/api/scans/{scan_id}/results", headers=auth_headers)
    assert results_res.status_code == 200
    call_results = results_res.json()
    assert call_results["scan_id"] == scan_id
    assert "results" in call_results

    # 4. Preview Report
    report_res = client.get(f"/api/scans/{scan_id}/report", headers=auth_headers)
    assert report_res.status_code == 200
    rep_data = report_res.json()
    assert rep_data["founder"] == "Pranay Kumar Mallem"
    assert "scan_data" in rep_data

    # 5. Download PDF
    pdf_res = client.get(f"/api/scans/{scan_id}/report/pdf", headers=auth_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF-")


def test_scan_open_access(client):
    # In open access mode, unauthenticated requests are allowed without 401 (returns 404 for missing item)
    res = client.get("/api/scans/SCAN-FAKE-001/report/pdf")
    assert res.status_code == 404

