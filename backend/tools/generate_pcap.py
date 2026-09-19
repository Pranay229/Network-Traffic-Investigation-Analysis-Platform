"""
Pure Python Safe PCAP Generator (0 dependencies, instant execution)
Generates valid libpcap files containing:
- HTTP web traffic
- DNS queries & responses (normal, long query, suspicious subdomain count)
- ICMP echo requests and replies
- TCP SYN port scan (targeting multiple ports to trigger port scan detection)
- TCP connections with SYN/ACK/FIN
- Multiple client and server hosts
"""
import struct
import socket
from pathlib import Path

def create_ethernet_frame(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload

def ip_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def create_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int = 1, ttl: int = 64) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    version_ihl = 0x45
    dscp_ecn = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000  # DF flag
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, ident, flags_frag,
        ttl, proto, 0, src_bytes, dst_bytes
    )
    chk = ip_checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, ident, flags_frag,
        ttl, proto, chk, src_bytes, dst_bytes
    )
    return header + payload

def create_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return header + payload

def create_tcp_packet(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    data_offset_res = (5 << 4)
    header = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_res, flags, window, 0, 0
    )
    return header + payload

def create_icmp_echo(type_: int, code: int, ident: int, seq: int, payload: bytes = b"abcdefghijklmnopqrstuvwabcdefghi") -> bytes:
    header = struct.pack("!BBHHH", type_, code, 0, ident, seq)
    chk = ip_checksum(header + payload)
    header = struct.pack("!BBHHH", type_, code, chk, ident, seq)
    return header + payload

def encode_dns_name(name: str) -> bytes:
    parts = name.strip(".").split(".")
    res = b""
    for p in parts:
        res += struct.pack("B", len(p)) + p.encode("ascii")
    return res + b"\x00"

def create_dns_query(tx_id: int, qname: str, qtype: int = 1) -> bytes:
    # Flags: 0x0100 (Standard query, RD=1)
    flags = 0x0100
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    q = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)  # Class IN
    return header + q

def create_dns_response(tx_id: int, qname: str, ans_ip: str, qtype: int = 1, ttl: int = 300) -> bytes:
    # Flags: 0x8180 (Standard response, No error, RD=1, RA=1)
    flags = 0x8180
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 1, 0, 0)
    q = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    ans_name = b"\xc0\x0c"  # pointer to query name
    rdata = socket.inet_aton(ans_ip)
    ans = ans_name + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return header + q + ans

class PCAPWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self.packets = []

    def add_packet(self, data: bytes, ts_sec: int, ts_usec: int):
        self.packets.append((ts_sec, ts_usec, data))

    def write(self):
        Path(self.filename).parent.mkdir(parents=True, exist_ok=True)
        with open(self.filename, "wb") as f:
            # PCAP Global Header: magic 0xa1b2c3d4 (little-endian: 0xd4c3b2a1)
            # version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts_sec, ts_usec, data in self.packets:
                f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
                f.write(data)

def generate_demo_traffic(output_path: str):
    writer = PCAPWriter(output_path)
    base_ts = 1700000000
    current_ts = base_ts
    usec = 0

    def step(delta_ms=20):
        nonlocal current_ts, usec
        usec += delta_ms * 1000
        if usec >= 1000000:
            current_ts += usec // 1000000
            usec %= 1000000
        return current_ts, usec

    mac_c1 = b"\x00\x0c\x29\x1a\x2b\x3c"
    mac_c2 = b"\x00\x0c\x29\x4d\x5e\x6f"
    mac_scan = b"\x00\x0c\x29\x99\x88\x77"
    mac_gw = b"\x00\x50\x56\xfd\x88\x99"

    c1_ip = "192.168.1.100"
    c2_ip = "192.168.1.101"
    c3_ip = "192.168.1.150"
    scanner_ip = "192.168.1.200"
    target_ip = "192.168.1.10"
    dns_srv = "8.8.8.8"
    web_srv = "93.184.216.34"

    # 1. DNS Queries and Responses
    domains = [
        ("example.com", "93.184.216.34"),
        ("api.internal.corp", "192.168.1.50"),
        ("auth.login.portal", "192.168.1.51"),
        ("cdn.assets.soc.local", "192.168.1.52"),
        ("updates.security.org", "104.244.42.1"),
        # Long suspicious domain (>50 chars)
        ("a" * 55 + ".tunnel.exfiltration-lab.net", "198.51.100.25"),
    ]

    for tx_id, (dom, resp_ip) in enumerate(domains, 1000):
        # Query
        s, u = step(15)
        dns_p = create_dns_query(tx_id, dom)
        udp_p = create_udp_packet(53000 + tx_id % 1000, 53, dns_p)
        ip_p = create_ipv4_packet(c1_ip, dns_srv, 17, udp_p, ident=tx_id)
        eth_p = create_ethernet_frame(mac_c1, mac_gw, 0x0800, ip_p)
        writer.add_packet(eth_p, s, u)

        # Response
        s, u = step(10)
        dns_resp = create_dns_response(tx_id, dom, resp_ip)
        udp_resp = create_udp_packet(53, 53000 + tx_id % 1000, dns_resp)
        ip_resp = create_ipv4_packet(dns_srv, c1_ip, 17, udp_resp, ident=tx_id+500)
        eth_resp = create_ethernet_frame(mac_gw, mac_c1, 0x0800, ip_resp)
        writer.add_packet(eth_resp, s, u)

    # 2. High subdomain queries (subdomain flood / tunneling heuristic test)
    for i in range(25):
        sub = f"sub{i}.data-sync.tunnel-demo.org"
        s, u = step(5)
        dns_p = create_dns_query(2000 + i, sub)
        udp_p = create_udp_packet(54000 + i, 53, dns_p)
        ip_p = create_ipv4_packet(c3_ip, dns_srv, 17, udp_p, ident=2000+i)
        eth_p = create_ethernet_frame(mac_c1, mac_gw, 0x0800, ip_p)
        writer.add_packet(eth_p, s, u)

    # 3. HTTP Traffic
    http_requests = [
        ("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n",
         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body><h1>NTIA Analysis</h1></body></html>"),
        ("GET /api/v1/telemetry HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Python-requests/2.31.0\r\n\r\n",
         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"status\":\"active\"}"),
        ("POST /upload/beacon HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nContent-Length: 14\r\n\r\nbeacon=running",
         "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
    ]

    for port_offset, (req_text, resp_text) in enumerate(http_requests):
        c_port = 49152 + port_offset
        # Handshake: SYN
        s, u = step(10)
        tcp_syn = create_tcp_packet(c_port, 80, seq=100, ack=0, flags=0x02) # SYN
        ip_p = create_ipv4_packet(c2_ip, web_srv, 6, tcp_syn)
        writer.add_packet(create_ethernet_frame(mac_c2, mac_gw, 0x0800, ip_p), s, u)

        # Handshake: SYN-ACK
        s, u = step(15)
        tcp_synack = create_tcp_packet(80, c_port, seq=1000, ack=101, flags=0x12) # SYN-ACK
        ip_p = create_ipv4_packet(web_srv, c2_ip, 6, tcp_synack)
        writer.add_packet(create_ethernet_frame(mac_gw, mac_c2, 0x0800, ip_p), s, u)

        # Handshake: ACK
        s, u = step(5)
        tcp_ack = create_tcp_packet(c_port, 80, seq=101, ack=1001, flags=0x10) # ACK
        ip_p = create_ipv4_packet(c2_ip, web_srv, 6, tcp_ack)
        writer.add_packet(create_ethernet_frame(mac_c2, mac_gw, 0x0800, ip_p), s, u)

        # Request
        s, u = step(10)
        req_bytes = req_text.encode("utf-8")
        tcp_data = create_tcp_packet(c_port, 80, seq=101, ack=1001, flags=0x18, payload=req_bytes) # PSH-ACK
        ip_p = create_ipv4_packet(c2_ip, web_srv, 6, tcp_data)
        writer.add_packet(create_ethernet_frame(mac_c2, mac_gw, 0x0800, ip_p), s, u)

        # Response
        s, u = step(20)
        resp_bytes = resp_text.encode("utf-8")
        tcp_resp = create_tcp_packet(80, c_port, seq=1001, ack=101 + len(req_bytes), flags=0x18, payload=resp_bytes)
        ip_p = create_ipv4_packet(web_srv, c2_ip, 6, tcp_resp)
        writer.add_packet(create_ethernet_frame(mac_gw, mac_c2, 0x0800, ip_p), s, u)

        # Teardown: FIN
        s, u = step(5)
        tcp_fin = create_tcp_packet(c_port, 80, seq=101 + len(req_bytes), ack=1001 + len(resp_bytes), flags=0x11)
        ip_p = create_ipv4_packet(c2_ip, web_srv, 6, tcp_fin)
        writer.add_packet(create_ethernet_frame(mac_c2, mac_gw, 0x0800, ip_p), s, u)

    # 4. ICMP Echo (Ping)
    for seq in range(1, 6):
        # Echo Request
        s, u = step(100)
        icmp_req = create_icmp_echo(8, 0, ident=0x1234, seq=seq)
        ip_p = create_ipv4_packet(c1_ip, "192.168.1.1", 1, icmp_req)
        writer.add_packet(create_ethernet_frame(mac_c1, mac_gw, 0x0800, ip_p), s, u)

        # Echo Reply
        s, u = step(10)
        icmp_rep = create_icmp_echo(0, 0, ident=0x1234, seq=seq)
        ip_p = create_ipv4_packet("192.168.1.1", c1_ip, 1, icmp_rep)
        writer.add_packet(create_ethernet_frame(mac_gw, mac_c1, 0x0800, ip_p), s, u)

    # 5. Port Scan Activity (SYN scan against 22 distinct ports on target)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    for sp in scan_ports:
        s, u = step(10)
        tcp_scan = create_tcp_packet(40000 + sp, sp, seq=5000 + sp, ack=0, flags=0x02) # SYN
        ip_p = create_ipv4_packet(scanner_ip, target_ip, 6, tcp_scan)
        writer.add_packet(create_ethernet_frame(mac_scan, mac_gw, 0x0800, ip_p), s, u)

        # Target responds RST for closed ports or SYN-ACK for open ports
        s, u = step(5)
        if sp in (22, 80, 443):
            # Open port response
            resp_flags = 0x12 # SYN-ACK
        else:
            # Closed port response
            resp_flags = 0x14 # RST-ACK
        tcp_target_resp = create_tcp_packet(sp, 40000 + sp, seq=0, ack=5001 + sp, flags=resp_flags)
        ip_p = create_ipv4_packet(target_ip, scanner_ip, 6, tcp_target_resp)
        writer.add_packet(create_ethernet_frame(mac_gw, mac_scan, 0x0800, ip_p), s, u)

    writer.write()
    print(f"Generated {len(writer.packets)} packets to {output_path}")

if __name__ == "__main__":
    out = Path(__file__).resolve().parents[2] / "pcaps" / "demo_traffic.pcap"
    generate_demo_traffic(str(out))
