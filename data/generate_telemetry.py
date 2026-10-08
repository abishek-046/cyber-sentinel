"""
Generates realistic validation telemetry data covering all threat scenarios.
Run: python data/generate_telemetry.py
"""
import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(BASE_DIR, "telemetry.csv")

FIELDS = [
    "timestamp", "source_ip", "dest_ip", "src_port", "dest_port",
    "protocol", "bytes", "packets", "auth_status", "event_type",
]

def ts(base, offset_seconds):
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%d %H:%M:%S")

def rand_ext_ip(seed=None):
    r = random.Random(seed) if seed else random
    return f"{r.randint(1,254)}.{r.randint(1,254)}.{r.randint(1,254)}.{r.randint(1,254)}"

base = datetime(2024, 6, 1, 8, 0, 0)
rows = []

# ── Normal office traffic (192.168.1.10–20) ──────────────────────────────────
for ip_last in range(10, 21):
    src = f"192.168.1.{ip_last}"
    for i in range(40):
        rows.append([
            ts(base, i * 30 + ip_last),
            src, "8.8.8.8", random.randint(49152, 65535), 443,
            "https", random.randint(1000, 80000), random.randint(5, 50),
            "none", "network_flow",
        ])
    # Some DNS
    for i in range(10):
        rows.append([
            ts(base, i * 60 + ip_last * 2),
            src, "8.8.4.4", random.randint(49152, 65535), 53,
            "dns", random.randint(60, 300), random.randint(1, 3),
            "none", "dns_query",
        ])
    # Successful logins
    for i in range(3):
        rows.append([
            ts(base, 1800 + i * 600 + ip_last),
            src, "192.168.1.100", random.randint(49152, 65535), 22,
            "ssh", 2000, 10, "success", "authentication",
        ])

# ── Port Scan (192.168.1.50) ─────────────────────────────────────────────────
scan_src = "192.168.1.50"
scan_target = "10.0.0.5"
for port in range(1, 501):
    rows.append([
        ts(base, port),
        scan_src, scan_target, random.randint(49152, 65535), port,
        "tcp", 60, 1, "none", "network_flow",
    ])
# additional sweep across multiple targets
for port in [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]:
    for target_last in range(1, 20):
        rows.append([
            ts(base, 600 + port + target_last),
            scan_src, f"10.0.0.{target_last}", random.randint(49152, 65535), port,
            "tcp", 60, 1, "none", "network_flow",
        ])

# ── Brute Force SSH (192.168.1.55) ───────────────────────────────────────────
brute_src = "192.168.1.55"
brute_target = "192.168.1.100"
for i in range(150):
    rows.append([
        ts(base, i * 4),
        brute_src, brute_target, random.randint(49152, 65535), 22,
        "ssh", 800, 5, "failure", "authentication",
    ])
# A couple successes near the end
for i in range(2):
    rows.append([
        ts(base, 600 + i * 30),
        brute_src, brute_target, random.randint(49152, 65535), 22,
        "ssh", 1200, 8, "success", "authentication",
    ])

# ── Brute Force RDP (192.168.1.56) ───────────────────────────────────────────
rdp_src = "192.168.1.56"
for i in range(80):
    rows.append([
        ts(base, i * 6),
        rdp_src, "192.168.1.101", random.randint(49152, 65535), 3389,
        "rdp", 900, 6, "failure", "authentication",
    ])

# ── Lateral Movement (10.0.1.5) ─────────────────────────────────────────────
lateral_src = "10.0.1.5"
internal_targets = [f"10.0.{s}.{h}" for s in range(1, 6) for h in [10, 20, 30, 40]]
for i, target in enumerate(internal_targets):
    for port in [445, 139, 3389, 1433]:
        rows.append([
            ts(base, i * 15 + port // 10),
            lateral_src, target, random.randint(49152, 65535), port,
            "smb" if port in (445, 139) else "tcp",
            random.randint(500, 5000), random.randint(3, 20),
            "success" if random.random() > 0.4 else "failure", "authentication",
        ])
    # Also file share access
    rows.append([
        ts(base, i * 15 + 5),
        lateral_src, target, random.randint(49152, 65535), 445,
        "smb", random.randint(10000, 200000), random.randint(10, 80),
        "success", "file_access",
    ])

# ── Data Exfiltration (192.168.2.10) ─────────────────────────────────────────
exfil_src = "192.168.2.10"
exfil_dests = [rand_ext_ip(seed=i) for i in range(12)]
for i, dest in enumerate(exfil_dests):
    # Large outbound transfers
    rows.append([
        ts(base, i * 45),
        exfil_src, dest, random.randint(49152, 65535), 443,
        "https", random.randint(500_000, 2_000_000), random.randint(300, 1200),
        "none", "network_flow",
    ])
    rows.append([
        ts(base, i * 45 + 10),
        exfil_src, dest, random.randint(49152, 65535), 80,
        "http", random.randint(200_000, 800_000), random.randint(100, 500),
        "none", "network_flow",
    ])
# Sustained upload to one C2 endpoint
c2 = "185.220.101.50"
for i in range(20):
    rows.append([
        ts(base, i * 30),
        exfil_src, c2, random.randint(49152, 65535), 8443,
        "https", random.randint(300_000, 1_000_000), random.randint(200, 800),
        "none", "network_flow",
    ])

# ── Background / Noise Traffic ───────────────────────────────────────────────
for i in range(30):
    rows.append([
        ts(base, i * 20), "192.168.1.1", "255.255.255.255",
        68, 67, "dhcp", 342, 1, "none", "dhcp",
    ])
for i in range(20):
    rows.append([
        ts(base, i * 30), "192.168.1.1", "224.0.0.1",
        0, 0, "igmp", 60, 1, "none", "multicast",
    ])

# ── Malformed / noisy records ─────────────────────────────────────────────────
malformed = [
    ["not-a-timestamp", "192.168.1.9", "10.0.0.1", "80", "443", "tcp", "1000", "5", "none", "network_flow"],
    ["2024-06-01 09:00:00", "999.999.999.999", "10.0.0.1", "80", "443", "tcp", "1000", "5", "none", "network_flow"],
    ["2024-06-01 09:00:01", "192.168.1.9", "10.0.0.1", "abc", "443", "tcp", "1000", "5", "none", "network_flow"],
    ["2024-06-01 09:00:02", "", "10.0.0.1", "80", "443", "tcp", "1000", "5", "none", "network_flow"],
    ["2024-06-01 09:00:03", "192.168.1.9", "10.0.0.1", "80", "443", "tcp", "-500", "5", "none", "network_flow"],
    ["2024-06-01 09:00:04", "192.168.1.9", "invalid_ip", "80", "443", "tcp", "1000", "5", "none", "network_flow"],
    # Incomplete row — only partial fields
    ["2024-06-01 09:00:05", "192.168.1.8"],
]

random.shuffle(rows)

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(FIELDS)
    for row in rows:
        if len(row) < len(FIELDS):
            row = row + [""] * (len(FIELDS) - len(row))
        writer.writerow(row[:len(FIELDS)])
    # Write malformed rows raw
    for m in malformed:
        if len(m) < len(FIELDS):
            m = m + [""] * (len(FIELDS) - len(m))
        writer.writerow(m[:len(FIELDS)])

print(f"Generated {len(rows) + len(malformed)} rows -> {OUTPUT}")
