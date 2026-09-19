import subprocess
import json
from pathlib import Path
from app.analyzers.tshark_runner import TSHARK_FIELDS, get_tshark_path

pcap = Path(__file__).resolve().parents[2] / "pcaps" / "demo_traffic.pcap"
tshark = get_tshark_path()

field_args = []
for field in TSHARK_FIELDS:
    field_args.extend(["-e", field])

cmd = [
    str(tshark),
    "-r", str(pcap),
    "-T", "json",
    "-n",
    "--no-duplicate-keys",
] + field_args

res = subprocess.run(cmd, capture_output=True, text=True)
print("Returncode:", res.returncode)
print("Stdout length:", len(res.stdout))
print("Stderr:", res.stderr[:300])
if res.stdout.strip():
    data = json.loads(res.stdout)
    print("Parsed packets count:", len(data))
    if data:
        print("First packet layers keys:", list(data[0].get("_source", {}).get("layers", {}).keys()))
