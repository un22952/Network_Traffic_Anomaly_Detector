"""
flow_builder.py

Raw packets are too granular to reason about directly — a single SYN packet
tells you nothing. Anomalies show up in *aggregate behavior*: how many ports
did this source touch? How regular was its timing? What's its SYN/ACK ratio?

This module groups packets by (src_ip) within sliding time windows and
computes per-window features. We aggregate by src_ip rather than by full
5-tuple flow because port scans and SYN floods are defined by one source's
behavior *across many destinations/ports* — grouping too narrowly would hide
exactly the pattern we're trying to catch.

Output: one row per (src_ip, time_window) with engineered features.
"""

import pandas as pd
import numpy as np


def build_flow_features(df, window_seconds=10.0):
    """
    Args:
        df: packet-level DataFrame with columns
            [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, syn, ack]
        window_seconds: size of the sliding time bucket used to group packets
            from the same source IP. Smaller windows = more sensitive to
            fast attacks (scans, floods) but noisier. Larger windows = better
            for catching slow beaconing but blurs fast bursts.

    Returns:
        DataFrame with one row per (src_ip, window) containing behavioral
        features used by both the rule-based and ML detectors.
    """
    df = df.copy()
    df["window"] = (df["timestamp"] // window_seconds).astype(int)

    grouped = df.groupby(["src_ip", "window"])

    features = grouped.agg(
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
        packet_count=("timestamp", "count"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        avg_packet_size=("size", "mean"),
        std_packet_size=("size", "std"),
        syn_count=("syn", "sum"),
        ack_count=("ack", "sum"),
    ).reset_index()

    # Derived features that don't come directly from .agg()
    features["duration"] = (features["end_time"] - features["start_time"]).clip(lower=0.001)
    features["packets_per_second"] = features["packet_count"] / features["duration"]
    features["syn_ack_ratio"] = features["syn_count"] / features["ack_count"].replace(0, 1)
    features["std_packet_size"] = features["std_packet_size"].fillna(0)

    # Inter-packet timing regularity, per src_ip — used for beaconing detection.
    # Low variance in time-deltas = suspiciously regular = bot-like behavior.
    timing_features = []
    for src_ip, group in df.groupby("src_ip"):
        deltas = group.sort_values("timestamp")["timestamp"].diff().dropna()
        if len(deltas) >= 3:
            timing_features.append({
                "src_ip": src_ip,
                "mean_interval": deltas.mean(),
                "interval_std": deltas.std(),
                # Coefficient of variation: std/mean. Near 0 = very regular timing.
                "interval_cv": deltas.std() / deltas.mean() if deltas.mean() > 0 else np.nan,
                # Total packets from this src_ip across the WHOLE capture, not
                # just this window — beacons are infrequent by design (one
                # packet every 30s), so per-window packet_count undercounts
                # them. This total is what we check before trusting the CV.
                "total_packet_count": len(deltas) + 1,
            })
    timing_df = pd.DataFrame(timing_features)

    features = features.merge(timing_df, on="src_ip", how="left")

    return features


if __name__ == "__main__":
    df = pd.read_csv("/home/linuxx/netanomaly/data/synthetic_traffic.csv")
    flows = build_flow_features(df)
    print(f"Built {len(flows)} flow-window rows from {len(df)} packets")
    print(flows.sort_values("unique_dst_ports", ascending=False).head(8)[
        ["src_ip", "packet_count", "unique_dst_ports", "packets_per_second", "syn_ack_ratio"]
    ])
