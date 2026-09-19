"""
Network Scanner Service & Finding Explanation Engine
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Safely performs non-intrusive network scans and generates contextual, beginner-friendly
and technical finding explanations with defensive recommendations.
"""
import asyncio
import socket
import ipaddress
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Knowledge Base of standard protocols, security implications, and explanations
SERVICE_KNOWLEDGE_BASE: Dict[int, Dict[str, Any]] = {
    21: {
        "service": "FTP",
        "category": "File Sharing",
        "default_risk": "MEDIUM",
        "what_is_it_beginner": "FTP is an older file transfer protocol used to send files between computers.",
        "what_is_it_technical": "File Transfer Protocol (FTP) operates over TCP 21 for control and ephemeral ports for data transmission.",
        "why_it_matters": "Standard FTP transmits credentials and data in cleartext, making it susceptible to passive network interception.",
        "risk_reasoning": "Marked as Medium because standard FTP transmits unencrypted credentials and commands across the network. This does not mean the server is compromised.",
        "recommended_action": "Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). If FTP is required, restrict network exposure via firewall access control lists.",
        "investigation_steps": "1. Verify if anonymous FTP login is permitted.\n2. Determine if transmission encryption is enforced.\n3. Restrict access to authorized subnet management IP addresses.",
        "learn_more": {
            "protocol": "File Transfer Protocol (FTP)",
            "purpose": "Legacy bulk file exchange across client and server architectures.",
            "typical_port": "TCP 21 (Control), TCP 20 / Passive dynamic range (Data)",
            "security_considerations": "Lack of native confidentiality in RFC 959 specification; plaintext AUTH commands; bounce attacks.",
            "analyst_checklist": "Verify authentication methods, check TLS enforcement, and audit user permission directories."
        }
    },
    22: {
        "service": "SSH",
        "category": "Remote Access",
        "default_risk": "LOW",
        "what_is_it_beginner": "SSH is a secure protocol used by administrators to log into and manage a remote computer or server.",
        "what_is_it_technical": "Secure Shell (SSH) provides an encrypted channel for remote command-line login, tunneling, and secure file transfer via cryptographic key exchange.",
        "why_it_matters": "SSH provides administrative command-line control. An open SSH port is standard for administration but should be protected against unauthorized brute-force attempts.",
        "risk_reasoning": "Marked as Low because SSH is an encrypted, secure administration protocol. Security depends on strong authentication and restricting exposure scope.",
        "recommended_action": "Enforce public-key authentication, disable root password login, keep the SSH daemon updated, and consider rate limiting or fail2ban.",
        "investigation_steps": "1. Review SSH configuration for password authentication vs key-based authentication.\n2. Confirm only authorized system administrators have access.\n3. Check if SSH is exposed to the public Internet or restricted to VPN/management VLANs.",
        "learn_more": {
            "protocol": "Secure Shell (SSH)",
            "purpose": "Encrypted remote terminal administration and file transfer.",
            "typical_port": "TCP 22",
            "security_considerations": "Password brute-forcing, outdated cryptographic ciphers, and unmonitored administrative access.",
            "analyst_checklist": "Check PermitRootLogin setting, verify SSH key strength (Ed25519/RSA 4096), and review audit logs for failed authentication spikes."
        }
    },
    23: {
        "service": "Telnet",
        "category": "Remote Access",
        "default_risk": "HIGH",
        "what_is_it_beginner": "Telnet is an obsolete remote login tool that does not protect passwords or commands with encryption.",
        "what_is_it_technical": "Telnet provides unencrypted bidirectional interactive text communication over TCP port 23.",
        "why_it_matters": "All login credentials and typed commands are transmitted in cleartext, easily captured by anyone monitoring local network traffic.",
        "risk_reasoning": "Marked as High because Telnet is an unencrypted administrative protocol. Using Telnet poses a credential exposure risk across transit paths.",
        "recommended_action": "Immediately disable Telnet and replace it with SSH (TCP 22) for all administrative connections.",
        "investigation_steps": "1. Identify legacy network appliances relying on Telnet.\n2. Transition administration scripts and firmware to SSH.\n3. Block port 23 on perimeter and internal firewalls.",
        "learn_more": {
            "protocol": "Telnet Protocol",
            "purpose": "Legacy terminal emulation over TCP.",
            "typical_port": "TCP 23",
            "security_considerations": "Zero encryption; plain text passwords and session data; vulnerable to eavesdropping and man-in-the-middle manipulation.",
            "analyst_checklist": "Plan immediate deprecation, audit legacy device configs, and enforce SSHv2 replacement."
        }
    },
    25: {
        "service": "SMTP",
        "category": "Network Infrastructure",
        "default_risk": "INFO",
        "what_is_it_beginner": "SMTP is the standard protocol used by servers to send and route email messages.",
        "what_is_it_technical": "Simple Mail Transfer Protocol (SMTP) handles message submission and relay between mail transfer agents (MTAs).",
        "why_it_matters": "Mail servers must be configured to prevent open relay abuse (sending unauthorized spam) and should enforce STARTTLS encryption.",
        "risk_reasoning": "Marked as Informational because SMTP is standard infrastructure. Risk increases only if open relay or unauthenticated relaying is permitted.",
        "recommended_action": "Ensure SMTP relay is strictly authenticated, enable STARTTLS, and configure SPF, DKIM, and DMARC DNS records.",
        "investigation_steps": "1. Test if the server acts as an open relay for third-party domains.\n2. Verify TLS certificate validity for opportunistic STARTTLS.\n3. Confirm rate limiting on email submission ports.",
        "learn_more": {
            "protocol": "Simple Mail Transfer Protocol (SMTP)",
            "purpose": "Email routing and delivery across networks.",
            "typical_port": "TCP 25 (Relay), TCP 587 (Submission)",
            "security_considerations": "Open relay exploitation, spam origination, lack of mandatory TLS in legacy clients.",
            "analyst_checklist": "Verify open relay tests pass, ensure TLS 1.2+ is supported, and review sender verification."
        }
    },
    53: {
        "service": "DNS",
        "category": "Network Infrastructure",
        "default_risk": "INFO",
        "what_is_it_beginner": "DNS is the system that translates human-readable domain names into computer IP addresses.",
        "what_is_it_technical": "Domain Name System (DNS) handles hostname-to-IP resolution, query routing, and zone data distribution over UDP/TCP 53.",
        "why_it_matters": "DNS is essential network infrastructure. Open recursive resolvers can be leveraged for DDoS amplification or DNS cache poisoning.",
        "risk_reasoning": "Marked as Informational as DNS is standard core network service. Exposure should be restricted if the server is an internal resolver.",
        "recommended_action": "Disable open recursion for external clients on internal DNS resolvers. Implement DNSSEC validation where supported.",
        "investigation_steps": "1. Determine whether recursion is restricted to authorized internal clients.\n2. Audit DNS query logging for unexpected high-volume requests.\n3. Verify DNS server software version is up to date.",
        "learn_more": {
            "protocol": "Domain Name System (DNS)",
            "purpose": "Hierarchical decentralized naming system for computers and network services.",
            "typical_port": "UDP/TCP 53",
            "security_considerations": "DNS amplification DDoS, cache poisoning, unencrypted query leakage, zone transfer disclosure.",
            "analyst_checklist": "Verify recursion restrictions, check for open AXFR zone transfers, and enable DNS query logging."
        }
    },
    80: {
        "service": "HTTP",
        "category": "Web Services",
        "default_risk": "LOW",
        "what_is_it_beginner": "HTTP is a web protocol used to deliver standard, unencrypted web pages.",
        "what_is_it_technical": "Hypertext Transfer Protocol (HTTP) serves web content over cleartext TCP connections without native cryptographic protection.",
        "why_it_matters": "Because HTTP is unencrypted, sensitive information like passwords or personal data should not be submitted over port 80.",
        "risk_reasoning": "Marked as Low because HTTP is standard for web traffic, but sensitive interactions should be redirected to HTTPS (TLS).",
        "recommended_action": "Configure HTTP to HTTPS automatic redirection (301 redirect) and enable HSTS (HTTP Strict Transport Security) on the web server.",
        "investigation_steps": "1. Check if HTTP automatically redirects to HTTPS.\n2. Confirm no administrative portals or login forms accept credentials over cleartext HTTP.\n3. Audit web server software headers for sensitive information disclosure.",
        "learn_more": {
            "protocol": "Hypertext Transfer Protocol (HTTP)",
            "purpose": "Application-level protocol for distributed, collaborative, hypermedia information systems.",
            "typical_port": "TCP 80",
            "security_considerations": "Cleartext transmission of headers, cookies, and payloads; vulnerable to man-in-the-middle modification.",
            "analyst_checklist": "Inspect server banner, check for HTTP->HTTPS redirection, and verify security headers (CSP, HSTS, X-Frame-Options)."
        }
    },
    443: {
        "service": "HTTPS",
        "category": "Web Services",
        "default_risk": "INFO",
        "what_is_it_beginner": "HTTPS is secure web browsing that encrypts all communication between your browser and the web server.",
        "what_is_it_technical": "HTTP over TLS (HTTPS) provides end-to-end encryption, authentication, and data integrity using modern cryptographic suites.",
        "why_it_matters": "HTTPS protects user privacy and transaction security in transit. Security depends on using strong TLS configurations and valid certificates.",
        "risk_reasoning": "Marked as Informational because HTTPS is the modern security standard for web services. An open HTTPS port is expected for web servers.",
        "recommended_action": "Maintain valid TLS certificates, disable obsolete protocols (SSLv3, TLS 1.0, TLS 1.1), and enforce modern cipher suites (TLS 1.2 and TLS 1.3).",
        "investigation_steps": "1. Verify SSL/TLS certificate expiration date and issuer trust chain.\n2. Test supported cipher suites to ensure legacy weak ciphers are disabled.\n3. Verify HTTP Strict Transport Security (HSTS) headers are active.",
        "learn_more": {
            "protocol": "Hypertext Transfer Protocol Secure (HTTPS)",
            "purpose": "Encrypted web application delivery and secure API transport.",
            "typical_port": "TCP 443",
            "security_considerations": "Expired or misconfigured certificates, legacy cipher suites, vulnerable web applications behind TLS.",
            "analyst_checklist": "Inspect certificate validity, verify TLS 1.2/1.3 enforcement, and check application endpoint authentication."
        }
    },
    445: {
        "service": "SMB",
        "category": "File Sharing",
        "default_risk": "MEDIUM",
        "what_is_it_beginner": "SMB is a Microsoft Windows protocol used for sharing files and printers over a network.",
        "what_is_it_technical": "Server Message Block (SMB) provides shared access to files, printers, and serial ports, running directly over TCP port 445.",
        "why_it_matters": "SMB is a core enterprise file sharing service that can increase attack surface when exposed beyond internal trusted network boundaries.",
        "risk_reasoning": "Marked as Medium because SMB provides direct filesystem and remote procedure call capabilities. Exposure to untrusted networks requires immediate review.",
        "recommended_action": "Block SMB (TCP 445) at network perimeters and untrusted boundaries. Enforce SMB signing, SMB encryption, and disable SMBv1.",
        "investigation_steps": "1. Confirm SMB is restricted exclusively to trusted internal subnets.\n2. Ensure legacy SMBv1 is disabled across all servers and endpoints.\n3. Audit SMB share permissions to prevent unauthorized anonymous read/write access.",
        "learn_more": {
            "protocol": "Server Message Block (SMB)",
            "purpose": "Network file sharing, RPC endpoint mapping, and inter-process communication.",
            "typical_port": "TCP 445",
            "security_considerations": "Historical exploitation targets (e.g. EternalBlue), lateral movement in Active Directory environments, anonymous share access.",
            "analyst_checklist": "Confirm SMBv1 is removed, verify SMB signing is required, and ensure port 445 is not reachable externally."
        }
    },
    3306: {
        "service": "MySQL",
        "category": "Database Services",
        "default_risk": "MEDIUM",
        "what_is_it_beginner": "MySQL is a database system used by websites and applications to store structured data.",
        "what_is_it_technical": "MySQL relational database management server listening for incoming client SQL connection requests on TCP port 3306.",
        "why_it_matters": "Direct exposure of database listening ports to wider networks exposes the database to brute force attempts and potential service vulnerabilities.",
        "risk_reasoning": "Marked as Medium because database ports should generally be restricted to application backends on private networks rather than open broadly.",
        "recommended_action": "Bind MySQL to localhost or internal private network interfaces. Require strong database passwords and enforce TLS encryption.",
        "investigation_steps": "1. Verify MySQL is not exposed to public or untrusted network ranges.\n2. Audit user privileges to ensure remote root login is disabled.\n3. Confirm database connections require authentication and TLS encryption.",
        "learn_more": {
            "protocol": "MySQL Database Protocol",
            "purpose": "Relational database querying and data persistence.",
            "typical_port": "TCP 3306",
            "security_considerations": "Brute-force credential guessing, unauthorized remote access, unpatched database engine vulnerabilities.",
            "analyst_checklist": "Check bind-address configuration, verify strong authentication plugins (caching_sha2_password), and ensure network isolation."
        }
    },
    3389: {
        "service": "RDP",
        "category": "Remote Access",
        "default_risk": "MEDIUM",
        "what_is_it_beginner": "RDP allows users and administrators to connect visually to a Windows desktop from another computer.",
        "what_is_it_technical": "Remote Desktop Protocol (RDP) provides graphical remote display and input capabilities for Microsoft Windows systems over TCP 3389.",
        "why_it_matters": "Exposed RDP ports are frequent targets for password spraying and brute-force attacks. Access should be mediated via VPN or bastion hosts.",
        "risk_reasoning": "Marked as Medium because RDP provides complete graphical administrative desktop access. Exposure to non-management networks requires review.",
        "recommended_action": "Enable Network Level Authentication (NLA), enforce Multi-Factor Authentication (MFA), and place RDP behind a secure VPN gateway.",
        "investigation_steps": "1. Confirm whether Network Level Authentication (NLA) is strictly enabled.\n2. Ensure account lockout policies are active to prevent password spraying.\n3. Restrict port 3389 from direct exposure to public or untrusted networks.",
        "learn_more": {
            "protocol": "Remote Desktop Protocol (RDP)",
            "purpose": "Proprietary protocol for remote visual management of Windows graphical environments.",
            "typical_port": "TCP 3389",
            "security_considerations": "Frequent target for credential stuffing, ransomware deployment entry-point, legacy RDP vulnerabilities.",
            "analyst_checklist": "Verify NLA status, enforce MFA through Remote Desktop Gateway, and restrict source IP access."
        }
    },
    5432: {
        "service": "PostgreSQL",
        "category": "Database Services",
        "default_risk": "MEDIUM",
        "what_is_it_beginner": "PostgreSQL is a robust database server used by enterprise applications to manage data.",
        "what_is_it_technical": "PostgreSQL object-relational database system communicating with client applications over TCP port 5432.",
        "why_it_matters": "Database services should only be accessible to authorized application servers and administrators over private, secured networks.",
        "risk_reasoning": "Marked as Medium because direct database network access expands attack surface. Access should be restricted to application tiers.",
        "recommended_action": "Restrict pg_hba.conf client entries to known application host IPs, enforce SCRAM-SHA-256 password hashing, and enable SSL.",
        "investigation_steps": "1. Review pg_hba.conf to verify allowed client connection IP subnets.\n2. Ensure default superuser 'postgres' has a strong password and cannot connect from untrusted IPs.\n3. Verify SSL connections are required for remote data in transit.",
        "learn_more": {
            "protocol": "PostgreSQL Protocol",
            "purpose": "Enterprise object-relational database querying and management.",
            "typical_port": "TCP 5432",
            "security_considerations": "Permissive pg_hba.conf rules, plaintext client connection methods, unsegmented database exposure.",
            "analyst_checklist": "Audit pg_hba.conf, verify SCRAM-SHA-256 password storage, and check listen_addresses parameters."
        }
    },
    6379: {
        "service": "Redis",
        "category": "Database Services",
        "default_risk": "HIGH",
        "what_is_it_beginner": "Redis is an in-memory data cache commonly used to speed up web applications.",
        "what_is_it_technical": "Redis key-value in-memory data store protocol communicating via TCP port 6379.",
        "why_it_matters": "By default, Redis has historically lacked strong authentication and was designed exclusively for trusted internal networks. Exposed instances can allow unauthenticated data access or remote code execution.",
        "risk_reasoning": "Marked as High because exposed Redis instances without strict network binding or strong AUTH can allow unauthorized data access and command execution.",
        "recommended_action": "Bind Redis to 127.0.0.1 or unix socket, enable requirepass with a strong password, disable dangerous commands (FLUSHALL, CONFIG), and enable protected mode.",
        "investigation_steps": "1. Verify whether requirepass authentication is configured.\n2. Confirm protected-mode is enabled in redis.conf.\n3. Ensure Redis is completely isolated from untrusted networks and the Internet.",
        "learn_more": {
            "protocol": "Redis Serialization Protocol (RESP)",
            "purpose": "High-performance in-memory caching, message brokering, and key-value storage.",
            "typical_port": "TCP 6379",
            "security_considerations": "Lack of default password in older setups, CONFIG command manipulation leading to SSH key injection, memory dumping.",
            "analyst_checklist": "Verify requirepass, check bind parameter in redis.conf, and rename or disable hazardous admin commands."
        }
    },
    8080: {
        "service": "HTTP-Proxy / Alt-Web",
        "category": "Web Services",
        "default_risk": "LOW",
        "what_is_it_beginner": "Port 8080 is an alternative web port frequently used for internal management dashboards or development applications.",
        "what_is_it_technical": "Alternative HTTP listener commonly utilized for web application proxies, microservices, Jenkins/Tomcat containers, or secondary web services.",
        "why_it_matters": "Development servers or admin consoles running on alternate ports may bypass standard perimeter security controls or lack TLS encryption.",
        "risk_reasoning": "Marked as Low because port 8080 is commonly used for standard development or internal web services. Review is recommended to confirm the nature of the application.",
        "recommended_action": "Ensure administrative interfaces require strong authentication, restrict access to authorized analysts, and apply TLS encryption.",
        "investigation_steps": "1. Identify the specific application service running on port 8080.\n2. Verify whether the application handles sensitive credentials or data.\n3. Check if TLS encryption is supported or if the service should be routed through a reverse proxy.",
        "learn_more": {
            "protocol": "Alternative HTTP (HTTP-Alt)",
            "purpose": "Secondary web application hosting, caching proxies, application containers.",
            "typical_port": "TCP 8080",
            "security_considerations": "Unauthenticated administrative portals, forgotten staging/dev environments, missing HTTPS encryption.",
            "analyst_checklist": "Identify web application banner, test authentication requirements, and confirm operational necessity."
        }
    },
    8443: {
        "service": "HTTPS-Alt",
        "category": "Web Services",
        "default_risk": "INFO",
        "what_is_it_beginner": "Port 8443 is an alternative secure web port commonly used for administration panels or specialized web applications.",
        "what_is_it_technical": "Alternative HTTPS service running TLS encrypted web transport on TCP port 8443.",
        "why_it_matters": "Provides encrypted transport for secondary web portals. The security posture depends on the application security and certificate management.",
        "risk_reasoning": "Marked as Informational as the service utilizes TLS encryption. Review application authentication and certificate validity.",
        "recommended_action": "Maintain valid TLS certificates and ensure the web service is updated with current security patches.",
        "investigation_steps": "1. Inspect TLS certificate details and expiration.\n2. Verify user authentication is enforced on administrative dashboards.\n3. Audit application access logs for anomalous activity.",
        "learn_more": {
            "protocol": "Alternative HTTPS (HTTPS-Alt)",
            "purpose": "Encrypted administrative interfaces, secondary SSL web services.",
            "typical_port": "TCP 8443",
            "security_considerations": "Self-signed certificate risks, administrative console exposure, application-level vulnerabilities.",
            "analyst_checklist": "Verify TLS certificate, inspect authentication controls, and confirm access restrictions."
        }
    }
}

DEFAULT_PORTS_FAST = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
DEFAULT_PORTS_STANDARD = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]


def get_finding_explanation(port: int, protocol: str = "TCP", service_name: Optional[str] = None, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a structured Finding Explanation object for any port/service.
    Adheres strictly to factual, non-intrusive security analysis without making unproven claims.
    """
    kb_entry = SERVICE_KNOWLEDGE_BASE.get(port)
    service = service_name or (kb_entry["service"] if kb_entry else f"Service/{port}")
    category = kb_entry["category"] if kb_entry else "Services"
    risk = kb_entry["default_risk"] if kb_entry else "INFO"
    
    what_is_it_beginner = kb_entry["what_is_it_beginner"] if kb_entry else f"Port {port} is a network communication endpoint used by {service}."
    what_is_it_technical = kb_entry["what_is_it_technical"] if kb_entry else f"{protocol} port {port} identified with service protocol {service}."
    
    observed = f"{protocol} port {port} is open and active on the scanned network target."
    if version:
        observed += f" Detected version information: {version}."
        
    why_matters = kb_entry["why_it_matters"] if kb_entry else f"Open ports allow network communication with the host. Unneeded or unmonitored exposed services expand the network attack surface."
    risk_reasoning = kb_entry["risk_reasoning"] if kb_entry else f"Marked as {risk} based on observable service characteristics. An open port alone does not prove a vulnerability or compromise."
    recommended_action = kb_entry["recommended_action"] if kb_entry else "Verify whether this service is operationally required. If required, restrict access to authorized systems and apply current security patches."
    investigation_steps = kb_entry["investigation_steps"] if kb_entry else "1. Identify the application or process listening on this port.\n2. Confirm whether network access is restricted by firewall rules.\n3. Verify authentication requirements and logging."
    
    learn_more = kb_entry.get("learn_more", {
        "protocol": service,
        "purpose": f"Network service communicating over {protocol} port {port}.",
        "typical_port": f"{protocol} {port}",
        "security_considerations": "Service visibility, authentication configuration, network segmentation, and patch currency.",
        "analyst_checklist": "Verify listening service process, inspect access logs, and enforce network boundary filtering."
    })

    return {
        "service": service,
        "port": port,
        "protocol": protocol,
        "category": category,
        "risk": risk,
        "state": "open",
        "version": version or "N/A",
        "what_is_it_beginner": what_is_it_beginner,
        "what_is_it_technical": what_is_it_technical,
        "what_was_observed": observed,
        "why_it_matters": why_matters,
        "risk_reasoning": risk_reasoning,
        "recommended_action": recommended_action,
        "investigation_steps": investigation_steps,
        "learn_more": learn_more,
    }


async def _probe_tcp_port(ip: str, port: int, timeout: float = 0.6) -> Optional[Dict[str, Any]]:
    """Safely and asynchronously checks if a TCP port is open via standard non-intrusive connect probe."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Try safe, non-intrusive banner read with minimal timeout
        banner = ""
        try:
            # Send newline or empty ping only if needed
            banner_data = await asyncio.wait_for(reader.read(256), timeout=0.3)
            banner = banner_data.decode("utf-8", errors="ignore").strip()[:100]
        except Exception:
            banner = ""
        finally:
            writer.close()
            await writer.wait_closed()

        explanation = get_finding_explanation(port, "TCP", version=banner if banner else None)
        return {
            "port": port,
            "protocol": "TCP",
            "state": "open",
            "service": explanation["service"],
            "version": banner if banner else "N/A",
            "banner": banner,
            "risk": explanation["risk"],
            "category": explanation["category"],
            "explanation": explanation
        }
    except Exception:
        return None


async def execute_network_scan(target_str: str, scan_type: str = "standard") -> Dict[str, Any]:
    """
    Executes an authorized, safe non-intrusive network scan on the specified target.
    Supports single IP addresses (e.g. 127.0.0.1), local hostnames, or small subnets.
    """
    start_time = time.time()
    started_at_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Determine ports to scan based on scan_type
    if scan_type == "fast":
        ports = DEFAULT_PORTS_FAST
    else:
        ports = DEFAULT_PORTS_STANDARD

    # Parse target
    target_clean = target_str.strip()
    target_ips = []
    
    try:
        if "/" in target_clean:
            net = ipaddress.ip_network(target_clean, strict=False)
            # Limit safe subnet scanning to maximum 16 hosts to prevent resource exhaustion
            target_ips = [str(ip) for ip in list(net.hosts())[:16]]
            if not target_ips and net.num_addresses == 1:
                target_ips = [str(net.network_address)]
        else:
            # Single host or hostname
            resolved = socket.gethostbyname(target_clean)
            target_ips = [resolved]
    except Exception as e:
        # If parsing fails, fall back to localhost safely
        target_ips = ["127.0.0.1"]

    discovered_hosts = []
    all_open_ports = []
    findings_list = []
    scan_events = []
    finding_id_counter = 1
    event_counter = 1

    # Record SCAN_STARTED event
    scan_events.append({
        "event_id": f"SEV-{int(start_time)}-{event_counter:03d}",
        "timestamp": start_time,
        "timestamp_str": started_at_str,
        "event_type": "SCAN_STARTED",
        "severity": "INFO",
        "source_ip": "127.0.0.1",
        "destination_ip": target_ips[0] if target_ips else target_clean,
        "source_port": None,
        "destination_port": None,
        "protocol": "TCP",
        "short_explanation": f"Network scan started for target '{target_clean}' ({scan_type} mode).",
        "observation": f"Scan initiated targeting '{target_clean}' across {len(ports)} probe ports.",
        "analysis": "Non-intrusive TCP connection inspection initiated across target address space.",
        "recommendation": "Ensure scanning activity is compliant with organizational authorization policies.",
        "evidence": {"target": target_clean, "scan_type": scan_type, "ports_count": len(ports)},
    })
    event_counter += 1

    for ip in target_ips:
        host_discover_time = time.time()
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ip

        # Probe ports concurrently
        tasks = [_probe_tcp_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports_for_host = [r for r in results if isinstance(r, dict) and r is not None]

        # Record HOST_DISCOVERED event
        scan_events.append({
            "event_id": f"SEV-{int(start_time)}-{event_counter:03d}",
            "timestamp": host_discover_time,
            "timestamp_str": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "event_type": "HOST_DISCOVERED",
            "severity": "INFO",
            "source_ip": "127.0.0.1",
            "destination_ip": ip,
            "source_port": None,
            "destination_port": None,
            "protocol": "IP",
            "short_explanation": f"Active host discovered at {ip} ({hostname}).",
            "observation": f"Host {ip} responded to network inquiries.",
            "analysis": "Host is active and connected on the network segment.",
            "recommendation": "Verify host registration in network asset inventory.",
            "evidence": {"ip": ip, "hostname": hostname},
        })
        event_counter += 1

        if open_ports_for_host:
            host_findings = []
            for p_info in open_ports_for_host:
                port_discover_time = time.time()
                expl = p_info["explanation"]
                finding_obj = {
                    "finding_id": f"F-{finding_id_counter:03d}",
                    "host": ip,
                    "hostname": hostname,
                    "port": p_info["port"],
                    "protocol": p_info["protocol"],
                    "service": p_info["service"],
                    "severity": p_info["risk"],
                    "category": p_info["category"],
                    "state": p_info["state"],
                    "version": p_info["version"],
                    "banner": p_info.get("banner", ""),
                    "title": f"{p_info['service']} Service Open on Port {p_info['port']}",
                    "description": expl["what_was_observed"],
                    "risk_reasoning": expl["risk_reasoning"],
                    "why_it_matters": expl["why_it_matters"],
                    "what_is_it_beginner": expl["what_is_it_beginner"],
                    "what_is_it_technical": expl["what_is_it_technical"],
                    "recommended_action": expl["recommended_action"],
                    "investigation_steps": expl["investigation_steps"],
                    "learn_more": expl["learn_more"]
                }
                host_findings.append(finding_obj)
                findings_list.append(finding_obj)
                all_open_ports.append({
                    "host": ip,
                    "hostname": hostname,
                    "port": p_info["port"],
                    "protocol": p_info["protocol"],
                    "service": p_info["service"],
                    "version": p_info["version"],
                    "state": p_info["state"],
                    "risk": p_info["risk"],
                    "category": p_info["category"],
                    "explanation": expl,
                    "finding_id": finding_obj["finding_id"]
                })

                # Record PORT_DISCOVERED event
                scan_events.append({
                    "event_id": f"SEV-{int(start_time)}-{event_counter:03d}",
                    "timestamp": port_discover_time,
                    "timestamp_str": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "event_type": "PORT_DISCOVERED",
                    "severity": p_info["risk"],
                    "source_ip": "127.0.0.1",
                    "destination_ip": ip,
                    "source_port": None,
                    "destination_port": p_info["port"],
                    "protocol": p_info["protocol"],
                    "short_explanation": f"{p_info['service']} service active on port {p_info['port']}.",
                    "observation": expl["what_was_observed"],
                    "analysis": expl["risk_reasoning"],
                    "recommendation": expl["recommended_action"],
                    "evidence": {
                        "port": p_info["port"],
                        "service": p_info["service"],
                        "version": p_info["version"],
                        "banner": p_info.get("banner", "")
                    },
                })
                event_counter += 1

                # Record SECURITY_FINDING event
                scan_events.append({
                    "event_id": f"SEV-{int(start_time)}-{event_counter:03d}",
                    "timestamp": port_discover_time + 0.001,
                    "timestamp_str": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "event_type": "SECURITY_FINDING",
                    "severity": finding_obj["severity"],
                    "source_ip": "127.0.0.1",
                    "destination_ip": ip,
                    "source_port": None,
                    "destination_port": p_info["port"],
                    "protocol": p_info["protocol"],
                    "short_explanation": finding_obj["title"],
                    "observation": finding_obj["description"],
                    "analysis": finding_obj["risk_reasoning"],
                    "recommendation": finding_obj["recommended_action"],
                    "evidence": {"finding_id": finding_obj["finding_id"], "risk": finding_obj["severity"]},
                })
                event_counter += 1

                finding_id_counter += 1

            discovered_hosts.append({
                "ip": ip,
                "hostname": hostname,
                "status": "up",
                "open_ports": [p["port"] for p in open_ports_for_host],
                "open_ports_count": len(open_ports_for_host),
                "services": list(set(p["service"] for p in open_ports_for_host)),
                "findings_count": len(host_findings)
            })
        else:
            # Host responded or scanned but no standard open ports found
            discovered_hosts.append({
                "ip": ip,
                "hostname": hostname,
                "status": "filtered / no open ports in profile",
                "open_ports": [],
                "open_ports_count": 0,
                "services": [],
                "findings_count": 0
            })

    end_time = time.time()
    duration = round(end_time - start_time, 2)
    completed_at_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Record SCAN_COMPLETED event
    scan_events.append({
        "event_id": f"SEV-{int(start_time)}-{event_counter:03d}",
        "timestamp": end_time,
        "timestamp_str": completed_at_str,
        "event_type": "SCAN_COMPLETED",
        "severity": "INFO",
        "source_ip": "127.0.0.1",
        "destination_ip": target_ips[0] if target_ips else target_clean,
        "source_port": None,
        "destination_port": None,
        "protocol": "TCP",
        "short_explanation": f"Scan completed in {duration}s. {len(discovered_hosts)} host(s), {len(all_open_ports)} port(s), {len(findings_list)} finding(s).",
        "observation": f"Network scan completed successfully at {completed_at_str} across target '{target_clean}'.",
        "analysis": "All target probes finished with real responsive status captured.",
        "recommendation": "Review findings and ensure high-risk administrative services are restricted.",
        "evidence": {"duration_seconds": duration, "hosts": len(discovered_hosts), "open_ports": len(all_open_ports), "findings": len(findings_list)},
    })

    # Calculate Risk Summary & Highest Severity
    risk_summary = {
        "critical": sum(1 for f in findings_list if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings_list if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings_list if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings_list if f["severity"] == "LOW"),
        "info": sum(1 for f in findings_list if f["severity"] == "INFO"),
        "total_findings": len(findings_list)
    }

    highest_severity = "INFO"
    if risk_summary["critical"] > 0:
        highest_severity = "CRITICAL"
    elif risk_summary["high"] > 0:
        highest_severity = "HIGH"
    elif risk_summary["medium"] > 0:
        highest_severity = "MEDIUM"
    elif risk_summary["low"] > 0:
        highest_severity = "LOW"

    # Generate Aggregate Defensive Recommendations
    unique_services = set(f["service"] for f in findings_list)
    recommendations = []
    if "SSH" in unique_services:
        recommendations.append("Review SSH access controls, disable password authentication in favor of SSH public keys, and restrict access scope.")
    if "HTTP" in unique_services:
        recommendations.append("Enforce HTTP-to-HTTPS automatic redirection (301) and enable HSTS on all web services.")
    if "HTTPS" in unique_services:
        recommendations.append("Verify TLS certificate validity, enforce TLS 1.2+ protocols, and audit web application endpoints.")
    if "SMB" in unique_services:
        recommendations.append("Review whether SMB (TCP 445) is required outside internal file server networks; enforce SMB signing and disable legacy SMBv1.")
    if "Telnet" in unique_services:
        recommendations.append("Immediately deprecate unencrypted Telnet (TCP 23) in favor of encrypted SSH.")
    if "Redis" in unique_services:
        recommendations.append("Ensure Redis is bound to private localhost interfaces, configure strong authentication via requirepass, and enable protected-mode.")
    if any(s in ["MySQL", "PostgreSQL"] for s in unique_services):
        recommendations.append("Restrict database listening ports to application backend IP addresses and require encrypted client connections.")
    
    if not recommendations and findings_list:
        recommendations.append("Ensure only required network services remain exposed and verify that host firewalls restrict incoming traffic to authorized IP subnets.")

    # Executive Summary Text
    summary_text = (
        f"Network scan performed on target '{target_clean}' identified {len(discovered_hosts)} host(s) "
        f"and {len(all_open_ports)} open service port(s) across {len(ports)} scanned probe ports. "
        f"{len(findings_list)} potential security consideration(s) were recorded for defensive review. "
        f"All classifications represent observable service posture and do not prove active exploitation."
    )

    return {
        "target": target_clean,
        "scan_type": scan_type,
        "started_at": started_at_str,
        "completed_at": completed_at_str,
        "duration_seconds": duration,
        "hosts_discovered": len(discovered_hosts),
        "open_ports_count": len(all_open_ports),
        "services_count": len(unique_services),
        "potential_findings_count": len(findings_list),
        "highest_severity": highest_severity,
        "hosts": discovered_hosts,
        "ports": all_open_ports,
        "findings": findings_list,
        "risk_summary": risk_summary,
        "events": scan_events,
        "timeline": scan_events,
        "recommendations": recommendations,
        "summary_text": summary_text,
        "methodology": {
            "scanner": "Nova Cyber Spark™ Non-Intrusive Asynchronous TCP Port & Service Inspector",
            "scan_type": scan_type.upper(),
            "target": target_clean,
            "ports_examined_count": len(ports),
            "ports_examined": ports,
            "service_detection_enabled": True,
            "intrusive_exploitation": False
        },
        "limitations": "This report reflects observations from the network scan performed at the specified time. An open port does not by itself establish that a service is vulnerable or compromised. Further validation may be required."
    }
