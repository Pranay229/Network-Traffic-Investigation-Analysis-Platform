import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import subprocess
from app.analyzers.tshark_runner import TSHARK_FIELDS, get_tshark_path

pcap = Path(__file__).resolve().parents[2] / "pcaps" / "demo_traffic.pcap"
tshark = get_tshark_path()

invalid_fields = []
valid_fields = []

for f in TSHARK_FIELDS:
    cmd = [str(tshark), "-r", str(pcap), "-T", "fields", "-e", f, "-c", "1"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if "Some fields aren't valid" in res.stderr or "isn't a valid field" in res.stderr:
        invalid_fields.append((f, res.stderr.strip()))
    else:
        valid_fields.append(f)

print("=== TShark Field Validation ===")
print(f"Valid fields ({len(valid_fields)}):", valid_fields)
print(f"Invalid fields ({len(invalid_fields)}):", invalid_fields)

# Test tcp.flags.reset instead
res = subprocess.run([str(tshark), "-r", str(pcap), "-T", "fields", "-e", "tcp.flags.reset", "-c", "1"], capture_output=True, text=True)
print("Is 'tcp.flags.reset' valid?", "Yes" if "isn't a valid field" not in res.stderr else "No")
