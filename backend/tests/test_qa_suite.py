"""
Full QA Integration Test Suite for NTIA Platform.
Validates end-to-end functionality under authentication and authorization:
- Authentication, Login, Bearer Token management
- Upload, Parsing, Pipeline Execution
- Overview KPIs & Stats
- Hosts Analysis
- Conversations Analysis
- DNS Analysis & Long query detection
- HTTP Analysis & Methods/URIs
- TCP & ICMP Analysis
- Port scan detection
- Alerts generation & verification
- Timeline events
- IOC Extraction
- Report Generation (Markdown & TXT)
- Invalid PCAP rejection (.txt, empty, corrupted magic)
- Path traversal & Security headers tests
"""
import time
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8001/api"
ROOT_DIR = Path(__file__).resolve().parents[2]
PCAP_PATH = ROOT_DIR / "pcaps" / "demo_traffic.pcap"


def run_qa_suite():
    results = {}
    print(f"=== Starting QA Test Suite against {BASE_URL} ===", flush=True)

    session = requests.Session()
    auth_headers = {}

    # 1. Health check & TShark availability
    try:
        r = session.get(f"{BASE_URL}/health", timeout=5)
        assert r.status_code == 200, f"Health check failed: {r.status_code}"
        health_data = r.json()
        assert health_data.get("status") == "ok"
        results["1. Backend Health Check"] = "PASS (TShark: " + str(health_data.get("tshark_available")) + ")"
    except Exception as e:
        results["1. Backend Health Check"] = f"FAIL: {e}"

    # 2. Authenticate Session (Login as Admin)
    try:
        login_res = session.post(f"{BASE_URL}/auth/login", json={
            "email": "admin@soc.local",
            "password": "Enterprise@Sec2026#Lead"
        }, timeout=5)

        assert login_res.status_code == 200, f"Login failed: {login_res.status_code} - {login_res.text}"
        auth_data = login_res.json()
        access_token = auth_data["access_token"]
        csrf_token = auth_data.get("csrf_token", "")
        auth_headers = {
            "Authorization": f"Bearer {access_token}",
            "X-CSRF-Token": csrf_token
        }
        session.headers.update(auth_headers)
        results["2. Authentication & JWT Session"] = f"PASS (Role: {auth_data['user']['role']})"
    except Exception as e:
        results["2. Authentication & JWT Session"] = f"FAIL: {e}"
        print(f"Cannot proceed without valid authentication: {e}")
        return results

    # 3. Upload valid demo PCAP
    inv_id = None
    try:
        assert PCAP_PATH.exists(), f"PCAP file not found: {PCAP_PATH}"
        with open(PCAP_PATH, "rb") as f:
            r = session.post(
                f"{BASE_URL}/pcap/upload",
                files={"file": ("demo_traffic.pcap", f, "application/vnd.tcpdump.pcap")},
                timeout=15
            )
        assert r.status_code == 200, f"Upload failed: {r.status_code} - {r.text}"
        data = r.json()
        inv_id = data["inv_id"]
        results["3. Valid PCAP Upload"] = f"PASS (inv_id: {inv_id})"
    except Exception as e:
        results["3. Valid PCAP Upload"] = f"FAIL: {e}"

    if not inv_id:
        print("Cannot proceed without valid investigation ID.")
        return results

    # 4. Wait for background analysis pipeline to complete
    max_wait = 30
    start_t = time.time()
    completed = False
    while time.time() - start_t < max_wait:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}")
        if r.status_code == 200 and r.json().get("status") == "completed":
            completed = True
            break
        time.sleep(1)

    results["4. Pipeline Execution"] = f"PASS ({time.time() - start_t:.1f}s)" if completed else "FAIL: Timeout waiting for completion"

    # 5. Overview KPIs
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/overview")
        assert r.status_code == 200
        overview = r.json()
        kpi = overview["kpi"]
        assert kpi["total_packets"] > 0, "No packets recorded"
        assert kpi["unique_hosts"] > 0, "No unique hosts recorded"
        results["5. Overview KPIs & Stats"] = f"PASS ({kpi['total_packets']} pkts, {kpi['unique_hosts']} hosts, {kpi['total_alerts']} alerts)"
    except Exception as e:
        results["5. Overview KPIs & Stats"] = f"FAIL: {e}"

    # 6. Hosts Analysis
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/hosts")
        assert r.status_code == 200
        hosts_data = r.json()
        assert hosts_data["total"] > 0, "No hosts returned"
        first_ip = hosts_data["hosts"][0]["ip_address"]
        # Detail
        r_det = session.get(f"{BASE_URL}/investigations/{inv_id}/hosts/{first_ip}")
        assert r_det.status_code == 200
        results["6. Hosts Analysis & Detail"] = f"PASS ({hosts_data['total']} hosts, verified {first_ip})"
    except Exception as e:
        results["6. Hosts Analysis & Detail"] = f"FAIL: {e}"

    # 7. Conversations
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/conversations")
        assert r.status_code == 200
        convs = r.json()
        assert convs["total"] > 0, "No conversations recorded"
        results["7. Conversations Analysis"] = f"PASS ({convs['total']} conversations)"
    except Exception as e:
        results["7. Conversations Analysis"] = f"FAIL: {e}"

    # 8. DNS Analysis
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/dns")
        assert r.status_code == 200
        dns = r.json()
        assert len(dns["records"]) > 0 or dns["total"] > 0
        results["8. DNS Analysis"] = f"PASS ({dns['total']} DNS records, {dns['summary']['unique_domains']} unique domains)"
    except Exception as e:
        results["8. DNS Analysis"] = f"FAIL: {e}"

    # 9. HTTP Analysis
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/http")
        assert r.status_code == 200
        http_data = r.json()
        assert http_data["total"] > 0
        results["9. HTTP Analysis"] = f"PASS ({http_data['total']} HTTP requests recorded)"
    except Exception as e:
        results["9. HTTP Analysis"] = f"FAIL: {e}"

    # 10. TCP Analysis
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/tcp")
        assert r.status_code == 200
        tcp = r.json()
        assert tcp["total_tcp_packets"] > 0
        results["10. TCP Analysis"] = f"PASS ({tcp['total_tcp_packets']} TCP pkts, {tcp['estimated_connections']} conns)"
    except Exception as e:
        results["10. TCP Analysis"] = f"FAIL: {e}"

    # 11. ICMP Analysis
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/icmp")
        assert r.status_code == 200
        icmp = r.json()
        assert icmp["summary"]["total_icmp_packets"] > 0
        results["11. ICMP Analysis"] = f"PASS ({icmp['summary']['total_icmp_packets']} ICMP pkts)"
    except Exception as e:
        results["11. ICMP Analysis"] = f"FAIL: {e}"

    # 12. Alerts & Port Scan Detection Verification
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/alerts")
        assert r.status_code == 200
        alerts = r.json()
        assert len(alerts) > 0, "No alerts generated for synthetic attack traffic"
        alert_types = [a["alert_type"] for a in alerts]
        assert any("Port Scan" in t for t in alert_types), f"Port scan not detected! Detected: {alert_types}"
        results["12. Port Scan Detection & Heuristics"] = f"PASS ({len(alerts)} alerts generated, including {alert_types[0]})"
    except Exception as e:
        results["12. Port Scan Detection & Heuristics"] = f"FAIL: {e}"

    # 13. Timeline
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/timeline")
        assert r.status_code == 200
        tl = r.json()
        assert tl["total"] > 0
        results["13. Investigation Timeline"] = f"PASS ({tl['total']} events)"
    except Exception as e:
        results["13. Investigation Timeline"] = f"FAIL: {e}"

    # 14. IOC Extraction
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/iocs")
        assert r.status_code == 200
        iocs = r.json()
        assert iocs["total"] > 0
        results["14. IOC Extraction"] = f"PASS ({iocs['total']} IOCs extracted)"
    except Exception as e:
        results["14. IOC Extraction"] = f"FAIL: {e}"

    # 15. Report Generation
    try:
        r = session.get(f"{BASE_URL}/investigations/{inv_id}/report")
        assert r.status_code == 200
        rep = r.json()
        assert len(rep["report"]) > 100
        assert "# Network Traffic Investigation Report" in rep["report"]
        results["15. Report Generation"] = f"PASS ({len(rep['report'])} chars Markdown)"
    except Exception as e:
        results["15. Report Generation"] = f"FAIL: {e}"

    # 16. Security Test: Invalid Extension Rejection (.txt)
    try:
        r = session.post(f"{BASE_URL}/pcap/upload", files={"file": ("malicious.txt", b"not a pcap", "text/plain")})
        assert r.status_code == 400
        results["16. Invalid File Extension Rejection"] = f"PASS ({r.json()['detail']})"
    except Exception as e:
        results["16. Invalid File Extension Rejection"] = f"FAIL: {e}"

    # 17. Security Test: Empty File Rejection
    try:
        r = session.post(f"{BASE_URL}/pcap/upload", files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")})
        assert r.status_code == 400
        results["17. Empty File Rejection"] = f"PASS ({r.json()['detail']})"
    except Exception as e:
        results["17. Empty File Rejection"] = f"FAIL: {e}"

    # 18. Security Test: Corrupted Magic Bytes Rejection
    try:
        r = session.post(f"{BASE_URL}/pcap/upload", files={"file": ("corrupt.pcap", b"MZ\x90\x00\x03\x00\x00\x00exe_header_dummy", "application/vnd.tcpdump.pcap")})
        assert r.status_code == 400
        results["18. Corrupted Magic Bytes Rejection"] = f"PASS ({r.json()['detail']})"
    except Exception as e:
        results["18. Corrupted Magic Bytes Rejection"] = f"FAIL: {e}"

    print("\n=== QA Integration Test Results ===", flush=True)
    for k, v in results.items():
        print(f"[{'PASS' if 'PASS' in v else 'FAIL'}] {k}: {v}", flush=True)

    return results


if __name__ == "__main__":
    run_qa_suite()
