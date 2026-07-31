"""
synthetic_generator.py

Generates synthetic packet-level network traffic with ground-truth labels.

WHY THIS EXISTS:
Real pcap datasets (CICIDS2017, UNSW-NB15) are hundreds of MB-GB and require
downloading from external sites. For development/testing, and to let anyone
running this repo reproduce results without a large download, this module
generates synthetic traffic with the same *statistical shape* as real attacks:

  - normal traffic: many src/dst pairs, moderate packet rates, varied ports
  - port scan: one attacker IP hits many ports on one target in a short window
  - SYN flood: one attacker IP sends many SYNs to one port, few completed ACKs
  - beaconing: one internal IP contacts one external IP at regular intervals
    (classic malware C2 pattern)

Each packet is labeled with its true category so evaluate.py can compute
precision/recall against ground truth.
"""

import pandas as pd
import numpy as np


def _random_ip(rng, prefix="10.0."):
    return f"{prefix}{rng.integers(0, 255)}.{rng.integers(1, 255)}"


def generate_normal_traffic(rng, n_flows=400, start_time=0.0):
    """Simulate ordinary background traffic: many different src/dst pairs,
    each with a handful of packets, random ports, mixed protocols."""
    rows = []
    t = start_time
    for _ in range(n_flows):
        src = _random_ip(rng)
        dst = _random_ip(rng, prefix="172.16.")
        dport = rng.choice([80, 443, 443, 443, 22, 53, 8080])  # weighted toward common ports
        n_packets = rng.integers(2, 15)
        for i in range(n_packets):
            t += rng.exponential(0.05)  # irregular timing = normal
            rows.append({
                "timestamp": t,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": rng.integers(1024, 65535),
                "dst_port": int(dport),
                "protocol": "TCP",
                "size": int(np.clip(rng.normal(500, 200), 40, 1500)),
                "syn": i == 0,
                "ack": i > 0,
                "label": "normal",
            })
    return rows, t


def generate_port_scan(rng, attacker_ip, target_ip, start_time, n_ports=150):
    """One source IP probes many ports on one target in quick succession —
    the classic Nmap-style reconnaissance signature."""
    rows = []
    t = start_time
    ports = rng.choice(range(1, 65535), size=n_ports, replace=False)
    for p in ports:
        t += rng.exponential(0.01)  # fast, regular probing
        rows.append({
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": rng.integers(1024, 65535),
            "dst_port": int(p),
            "protocol": "TCP",
            "size": 60,  # scan packets are small (just SYN, no payload)
            "syn": True,
            "ack": False,  # target mostly doesn't complete handshake
            "label": "port_scan",
        })
    return rows, t


def generate_syn_flood(rng, attacker_ip, target_ip, target_port, start_time, n_packets=800):
    """One source floods a single port with SYNs, few of which get ACKed —
    classic resource-exhaustion DoS pattern."""
    rows = []
    t = start_time
    for _ in range(n_packets):
        t += rng.exponential(0.002)  # very high rate
        rows.append({
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": rng.integers(1024, 65535),
            "dst_port": target_port,
            "protocol": "TCP",
            "size": 60,
            "syn": True,
            "ack": rng.random() < 0.02,  # almost none complete
            "label": "syn_flood",
        })
    return rows, t


def generate_beaconing(rng, internal_ip, c2_ip, dport, start_time, n_beacons=40, interval=30.0):
    """One internal host contacts one external IP at a suspiciously regular
    interval — a classic malware command-and-control (C2) beaconing pattern."""
    rows = []
    t = start_time
    for _ in range(n_beacons):
        t += interval + rng.normal(0, 0.5)  # tight jitter = regular = suspicious
        rows.append({
            "timestamp": t,
            "src_ip": internal_ip,
            "dst_ip": c2_ip,
            "src_port": rng.integers(1024, 65535),
            "dst_port": dport,
            "protocol": "TCP",
            "size": int(np.clip(rng.normal(300, 20), 100, 500)),  # consistent size too
            "syn": True,
            "ack": True,
            "label": "beaconing",
        })
    return rows, t


def build_synthetic_dataset(seed=42):
    """Assemble a full labeled dataset combining normal traffic with each
    attack type, then shuffle by timestamp so detectors see realistic
    interleaved traffic rather than neatly separated blocks."""
    rng = np.random.default_rng(seed)
    all_rows = []

    rows, t = generate_normal_traffic(rng, n_flows=400, start_time=0.0)
    all_rows += rows

    rows, t2 = generate_port_scan(rng, attacker_ip="203.0.113.50",
                                   target_ip="172.16.0.10", start_time=t + 5)
    all_rows += rows

    rows, t3 = generate_syn_flood(rng, attacker_ip="198.51.100.77",
                                   target_ip="172.16.0.20", target_port=443,
                                   start_time=t2 + 5)
    all_rows += rows

    rows, t4 = generate_beaconing(rng, internal_ip="10.0.5.13",
                                   c2_ip="198.51.100.200", dport=443,
                                   start_time=t3 + 5)
    all_rows += rows

    df = pd.DataFrame(all_rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_synthetic_dataset()
    df.to_csv("/home/linuxx/netanomaly/data/synthetic_traffic.csv", index=False)
    print(f"Generated {len(df)} packets")
    print(df["label"].value_counts())
