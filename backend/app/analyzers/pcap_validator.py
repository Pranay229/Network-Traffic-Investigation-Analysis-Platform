"""PCAP file validator — checks magic bytes, extension, and file size."""
import hashlib
import logging
from pathlib import Path
from app.config import settings

logger = logging.getLogger(__name__)

# Magic bytes for PCAP formats
PCAP_MAGIC = [
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng
    b"\x4d\x3c\xb2\xa1",  # modified pcap
    b"\xa1\xb2\xcd\x34",  # modified pcap (big-endian)
]

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


def validate_pcap_file(file_path: str, original_filename: str) -> dict:
    """
    Validate a PCAP file by checking extension, magic bytes, and file size.
    Returns a dict with 'valid', 'format', and 'error' keys.
    """
    result = {"valid": False, "format": None, "error": None, "file_hash": None}
    path = Path(file_path)

    # Check extension
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        result["error"] = f"Unsupported file type '{ext}'. Only .pcap and .pcapng files are accepted."
        return result

    # Check file exists and is not empty
    if not path.is_file():
        result["error"] = "File not found."
        return result

    file_size = path.stat().st_size
    if file_size == 0:
        result["error"] = "File is empty."
        return result

    if file_size > settings.max_upload_bytes:
        result["error"] = f"File too large ({file_size // (1024*1024)} MB). Maximum is {settings.MAX_UPLOAD_SIZE_MB} MB."
        return result

    # Check magic bytes
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except IOError as e:
        result["error"] = f"Cannot read file: {e}"
        return result

    detected_format = None
    for i, m in enumerate(PCAP_MAGIC):
        if magic == m:
            detected_format = "pcapng" if i == 2 else "pcap"
            break

    if not detected_format:
        # Also check if extension is pcapng (pcapng magic check above)
        if ext == ".pcapng" and magic == b"\x0a\x0d\x0d\x0a":
            detected_format = "pcapng"
        else:
            result["error"] = "File does not appear to be a valid PCAP or PCAPNG file (invalid magic bytes)."
            return result

    # Compute SHA-256 hash
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        result["file_hash"] = sha256.hexdigest()
    except Exception as e:
        logger.warning(f"Could not compute file hash: {e}")

    result["valid"] = True
    result["format"] = detected_format
    return result
