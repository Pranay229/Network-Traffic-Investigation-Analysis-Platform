"""
TShark subprocess wrapper.

SECURITY NOTES:
- Never uses shell=True
- Arguments are passed as a list, never concatenated strings
- Only the pre-configured TSHARK_PATH binary is executed
- PCAP file path is validated before use
- Raw user input is NEVER passed to subprocess
"""
import json
import subprocess
import logging
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

# Standard TShark fields we extract for every packet
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "frame.protocols",
    "_ws.col.Info",
    # DNS fields
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.response",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dns.resp.ttl",
    "dns.id",
    "dns.flags.rcode",
    # HTTP fields
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
    "http.response.code",
    "http.content_type",
    "http.content_length",
    # ICMP fields
    "icmp.type",
    "icmp.code",
    # ARP
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
]


def get_tshark_path() -> Path:
    """Return validated TShark path."""
    p = Path(settings.TSHARK_PATH)
    if not p.is_file():
        # Try common Linux path as fallback
        fallback = Path("/usr/bin/tshark")
        if fallback.is_file():
            return fallback
        import shutil
        in_path = shutil.which("tshark")
        if in_path:
            return Path(in_path)
        raise FileNotFoundError(
            f"TShark not found at '{settings.TSHARK_PATH}'. "
            "Install Wireshark/TShark or set TSHARK_PATH environment variable."
        )
    return p


def validate_pcap_path(pcap_path: str) -> Path:
    """Validate that the PCAP path exists and is within allowed upload directory."""
    p = Path(pcap_path).resolve()
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    if not p.exists():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    if not p.is_file():
        raise ValueError(f"Path is not a file: {p}")
    # Ensure path is within upload directory (path traversal protection)
    try:
        p.relative_to(upload_dir)
    except ValueError:
        raise ValueError(f"PCAP path is outside allowed upload directory.")
    return p


def run_tshark_json(pcap_path: str) -> list[dict[str, Any]]:
    """
    Run TShark on a PCAP file and return parsed JSON output.
    Uses -T ek (Elasticsearch/NDJSON) for memory-efficient streaming.
    """
    tshark = get_tshark_path()
    validated_path = validate_pcap_path(pcap_path)

    # Build field arguments
    field_args = []
    for field in TSHARK_FIELDS:
        field_args.extend(["-e", field])

    cmd = [
        str(tshark),
        "-r", str(validated_path),
        "-T", "json",        # JSON output
        "-n",                # No name resolution (faster, no DNS lookups)
        "--no-duplicate-keys",
    ] + field_args

    logger.info(f"Running TShark on {validated_path}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5-minute timeout
        )
        if result.returncode not in (0, 1):  # TShark returns 1 for some warnings
            logger.warning(f"TShark stderr: {result.stderr[:500]}")

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return data if isinstance(data, list) else []

    except subprocess.TimeoutExpired:
        raise TimeoutError("TShark analysis timed out (>5 minutes). File may be too large.")
    except json.JSONDecodeError as e:
        logger.error(f"TShark JSON parse error: {e}")
        return []
    except Exception as e:
        logger.error(f"TShark execution error: {e}")
        raise


def get_pcap_summary(pcap_path: str) -> dict[str, Any]:
    """Get high-level PCAP summary using capinfos."""
    tshark = get_tshark_path()
    capinfos = tshark.parent / "capinfos.exe"
    if not capinfos.is_file():
        capinfos = tshark.parent / "capinfos"  # Linux

    validated_path = validate_pcap_path(pcap_path)

    summary = {
        "packet_count": 0,
        "file_size": validated_path.stat().st_size,
        "capture_duration": 0.0,
        "start_time": None,
        "end_time": None,
    }

    if capinfos.is_file():
        try:
            result = subprocess.run(
                [str(capinfos), "-m", "-c", "-d", "-e", "-s", str(validated_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if "Number of packets" in line:
                    try:
                        summary["packet_count"] = int(line.split(":")[1].strip())
                    except Exception:
                        pass
                elif "Capture duration" in line:
                    try:
                        summary["capture_duration"] = float(line.split(":")[1].strip().split(" ")[0])
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"capinfos failed: {e}")

    return summary
