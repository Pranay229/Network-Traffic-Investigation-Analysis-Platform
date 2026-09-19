"""
Demo PCAP Generator — creates synthetic network traffic for testing.

This generates a PCAP labeled as DEMO DATA containing:
- Regular HTTP web browsing traffic
- DNS queries (including some long/suspicious ones)
- ICMP ping traffic
- TCP SYN scanning activity (for alert testing)
- Mixed protocol traffic

Usage: python tools/create_demo_pcap.py
Output: ../pcaps/demo_traffic.pcap

DISCLAIMER: This is synthetic test data only. No real network traffic.
"""
import sys
import os
import random
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import scapy.config
    scapy.config.conf.use_pcap = False
    from scapy.utils import wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "pcaps"
OUTPUT_FILE = OUTPUT_DIR / "demo_traffic.pcap"

# Demo hosts
CLIENT1 = "192.168.1.100"
CLIENT2 = "192.168.1.101"
CLIENT3 = "192.168.1.150"
SCANNER = "192.168.1.200"   # Will trigger port scan alert
DNS_SERVER = "8.8.8.8"
WEB_SERVER = "93.184.216.34"   # example.com
INTERNAL_SERVER = "192.168.1.10"
GATEWAY = "192.168.1.1"

MAC_SRC = "aa:bb:cc:dd:ee:ff"
MAC_DST = "00:11:22:33:44:55"

packets = []
base_time = 1700000000.0  # Fixed base timestamp for reproducibility
t = base_time


def pkt(p, delay=0.01):
    global t
    p.time = t
    t += delay
    packets.append(p)


print("🔧 Generating DEMO PCAP traffic...")

# ─── 1. DNS Queries ──────────────────────────────────────────────────────────
print("  DNS queries...")
dns_domains = [
    "example.com", "google.com", "github.com", "microsoft.com",
    "update.microsoft.com", "cdn.cloudflare.com", "api.github.com",
    "www.example.com", "mail.example.com", "ftp.example.com",
]

for domain in dns_domains:
    # Query
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=DNS_SERVER) /
        UDP(sport=random.randint(50000, 65000), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain)),
        delay=0.05)
    # Response
    pkt(Ether(src=MAC_DST, dst=MAC_SRC) /
        IP(src=DNS_SERVER, dst=CLIENT1) /
        UDP(sport=53, dport=random.randint(50000, 65000)) /
        DNS(qr=1, aa=1, qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, rdata=WEB_SERVER)),
        delay=0.02)

# ─── 2. Long DNS Query (triggers long-DNS alert) ─────────────────────────────
print("  Long DNS query (alert trigger)...")
long_domain = "aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz.suspicious-domain.com"
pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
    IP(src=CLIENT2, dst=DNS_SERVER) /
    UDP(sport=54321, dport=53) /
    DNS(rd=1, qd=DNSQR(qname=long_domain)),
    delay=0.1)

# ─── 3. Many subdomains of same parent (triggers high-subdomain alert) ───────
print("  Subdomain enumeration (alert trigger)...")
for i in range(25):
    sub = f"{''.join(random.choices('abcdefghijklmnop0123456789', k=12))}.data-exfil-test.com"
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT3, dst=DNS_SERVER) /
        UDP(sport=random.randint(50000, 65000), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=sub)),
        delay=0.05)

# ─── 4. HTTP Traffic ─────────────────────────────────────────────────────────
print("  HTTP traffic...")
http_paths = ["/", "/index.html", "/about", "/api/data", "/login", "/static/main.js"]
for path in http_paths:
    # HTTP GET request
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=WEB_SERVER) /
        TCP(sport=random.randint(50000, 65000), dport=80, flags="PA") /
        Raw(load=f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0) Chrome/120.0\r\n\r\n".encode()),
        delay=0.1)
    # HTTP 200 response
    pkt(Ether(src=MAC_DST, dst=MAC_SRC) /
        IP(src=WEB_SERVER, dst=CLIENT1) /
        TCP(sport=80, dport=random.randint(50000, 65000), flags="PA") /
        Raw(load=f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\n\r\n<html>Demo</html>".encode()),
        delay=0.05)

# ─── 5. ICMP Pings ───────────────────────────────────────────────────────────
print("  ICMP pings...")
for i in range(20):
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=INTERNAL_SERVER) /
        ICMP(type=8, code=0),
        delay=0.1)
    pkt(Ether(src=MAC_DST, dst=MAC_SRC) /
        IP(src=INTERNAL_SERVER, dst=CLIENT1) /
        ICMP(type=0, code=0),
        delay=0.05)

# ─── 6. Port Scan (triggers port-scan alert) ─────────────────────────────────
print("  Port scan activity (alert trigger)...")
scan_ports = list(range(20, 26)) + [80, 443, 445, 3389, 8080, 8443, 22, 23, 25, 110, 143, 3306, 5432, 6379]
for port in scan_ports:
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=SCANNER, dst=INTERNAL_SERVER) /
        TCP(sport=random.randint(50000, 65000), dport=port, flags="S"),
        delay=0.02)
    # Most ports get RST response (closed)
    if port != 80:
        pkt(Ether(src=MAC_DST, dst=MAC_SRC) /
            IP(src=INTERNAL_SERVER, dst=SCANNER) /
            TCP(sport=port, dport=random.randint(50000, 65000), flags="RA"),
            delay=0.01)

# ─── 7. Normal TCP Connections ───────────────────────────────────────────────
print("  Normal TCP connections...")
for i in range(10):
    sport = random.randint(50000, 65000)
    # SYN
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=WEB_SERVER) /
        TCP(sport=sport, dport=443, flags="S", seq=1000),
        delay=0.05)
    # SYN-ACK
    pkt(Ether(src=MAC_DST, dst=MAC_SRC) /
        IP(src=WEB_SERVER, dst=CLIENT1) /
        TCP(sport=443, dport=sport, flags="SA", seq=2000, ack=1001),
        delay=0.02)
    # ACK
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=WEB_SERVER) /
        TCP(sport=sport, dport=443, flags="A", seq=1001, ack=2001),
        delay=0.02)
    # FIN
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=WEB_SERVER) /
        TCP(sport=sport, dport=443, flags="FA", seq=2000, ack=2001),
        delay=0.05)

# ─── 8. Additional DNS for volume ────────────────────────────────────────────
print("  Additional DNS volume...")
for i in range(60):
    domain = random.choice(dns_domains)
    pkt(Ether(src=MAC_SRC, dst=MAC_DST) /
        IP(src=CLIENT1, dst=DNS_SERVER) /
        UDP(sport=random.randint(50000, 65000), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain)),
        delay=0.03)

# ─── Write PCAP ──────────────────────────────────────────────────────────────
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print(f"\n📦 Writing {len(packets)} packets to {OUTPUT_FILE}...")
wrpcap(str(OUTPUT_FILE), packets)

print(f"""
✅ Demo PCAP created: {OUTPUT_FILE}
   Packets: {len(packets)}
   
⚠️  DEMO DATA — This is synthetic test traffic, not real network captures.

Expected alerts when analyzed:
  🟠 Potential Port Scan: {SCANNER} → {INTERNAL_SERVER}
  🟡 Excessive DNS Queries: {CLIENT1} (volume + long query)
  🟡 Unusually Long DNS Query: {CLIENT2} → {long_domain[:40]}...
  🟠 High Unique Subdomain Count: {CLIENT3}

Upload this file at: http://localhost:5173
""")
