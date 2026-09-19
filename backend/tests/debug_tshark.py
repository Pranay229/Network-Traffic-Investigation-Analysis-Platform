import subprocess
import json
from pathlib import Path

pcap = Path(__file__).resolve().parents[2] / "pcaps" / "demo_traffic.pcap"
tshark = r"C:\Program Files\Wireshark\tshark.exe"

cmd1 = [tshark, "-r", str(pcap), "-T", "json", "-n", "--no-duplicate-keys", "-e", "frame.number", "-e", "ip.src"]
r1 = subprocess.run(cmd1, capture_output=True, text=True)
d1 = json.loads(r1.stdout)
print("Test 1 layers in first packet:", d1[0].get("_source", {}).get("layers", {}))

cmd2 = [tshark, "-r", str(pcap), "-T", "json", "-n", "--no-duplicate-keys"]
r2 = subprocess.run(cmd2, capture_output=True, text=True)
d2 = json.loads(r2.stdout)
layers2 = d2[0].get("_source", {}).get("layers", {})
print("Test 2 layer names:", list(layers2.keys()))
if "ip" in layers2:
    print("Test 2 ip layer keys:", list(layers2["ip"].keys())[:10])
