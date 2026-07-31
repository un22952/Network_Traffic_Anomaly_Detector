"""
rule_detectors.py

Rule-based (threshold) detection. We start here rather than jumping to ML
because:
  1. Rules are explainable — we can tell
     exactly *why* something was flagged.
  2. These specific attacks have well-known, stable signatures — we don't
     need a learned model to know that "one IP touching 100+ ports in 10
     seconds" is a port scan.
  3. It gives us a labeled baseline to compare the ML layer against.

Each detector takes the flow-features DataFrame from flow_builder.py and
returns the subset of rows it flags, tagged with which rule fired.
"""

import pandas as pd

PORT_SCAN_MIN_UNIQUE_PORTS = 20      # ports touched by one src_ip in one window
SYN_FLOOD_MIN_PPS = 50               # packets/sec from one src_ip
SYN_FLOOD_MIN_SYN_ACK_RATIO = 10.0   # SYNs per completed ACK
BEACON_MAX_INTERVAL_CV = 0.05        # coefficient of variation; lower = more regular
BEACON_MIN_PACKET_COUNT = 10         # need enough samples to trust the timing stat


def detect_port_scans(flows):
    hits = flows[flows["unique_dst_ports"] >= PORT_SCAN_MIN_UNIQUE_PORTS].copy()
    hits["rule"] = "port_scan"
    hits["reason"] = hits["unique_dst_ports"].apply(
        lambda n: f"contacted {n} distinct ports in one window"
    )
    return hits


def detect_syn_floods(flows):
    hits = flows[
        (flows["packets_per_second"] >= SYN_FLOOD_MIN_PPS)
        & (flows["syn_ack_ratio"] >= SYN_FLOOD_MIN_SYN_ACK_RATIO)
    ].copy()
    hits["rule"] = "syn_flood"
    hits["reason"] = hits.apply(
        lambda r: f"{r.packets_per_second:.0f} pkts/sec, SYN:ACK ratio {r.syn_ack_ratio:.1f}",
        axis=1,
    )
    return hits


def detect_beaconing(flows):
    # Beacons send one packet per window by design, so we check total packets
    # across the WHOLE capture (total_packet_count) rather than per-window
    # packet_count, then de-dupe to one row per src_ip since the same source
    # otherwise appears once per window it was active in.
    candidates = flows[flows["total_packet_count"] >= BEACON_MIN_PACKET_COUNT].copy()
    hits = candidates[candidates["interval_cv"] <= BEACON_MAX_INTERVAL_CV].copy()
    hits = hits.drop_duplicates(subset="src_ip").copy()
    hits["rule"] = "beaconing"
    hits["reason"] = hits["interval_cv"].apply(
        lambda cv: f"highly regular timing (CV={cv:.3f}), suggests automated C2 check-ins"
    )
    return hits


def run_all_rules(flows):
    """Run every detector and combine results into a single flagged-events table."""
    results = pd.concat([
        detect_port_scans(flows),
        detect_syn_floods(flows),
        detect_beaconing(flows),
    ], ignore_index=True)
    return results.sort_values("start_time")


if __name__ == "__main__":
    from flow_builder import build_flow_features

    df = pd.read_csv("/home/linuxx/netanomaly/data/synthetic_traffic.csv")
    flows = build_flow_features(df)
    flagged = run_all_rules(flows)

    print(f"Flagged {len(flagged)} events out of {len(flows)} flow-windows\n")
    print(flagged[["src_ip", "rule", "reason"]].to_string(index=False))
