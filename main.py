"""
main.py

End-to-end CLI: ingest packets -> build flow features -> run detectors ->
print flagged events. This is the "demo" entry point — run this to see the
whole pipeline work against either synthetic data or a real pcap file.

Usage:
    python main.py                          # runs against bundled synthetic data
    python main.py --pcap capture.pcap       # runs against a real capture file
    python main.py --window 5                # use a 5-second aggregation window
"""

import argparse
import pandas as pd

from detection.flow_builder import build_flow_features
from detection.rule_detectors import run_all_rules
from detection.ml_detector import detect_ml_anomalies


def load_traffic(pcap_path=None):
    if pcap_path:
        from ingestion.pcap_reader import read_pcap
        print(f"Reading packets from {pcap_path} ...")
        return read_pcap(pcap_path)
    else:
        print("No --pcap given, using bundled synthetic traffic dataset ...")
        from ingestion.synthetic_generator import build_synthetic_dataset
        return build_synthetic_dataset()


def main():
    parser = argparse.ArgumentParser(description="Network traffic anomaly detector")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze", default=None)
    parser.add_argument("--window", type=float, default=10.0,
                         help="Aggregation window size in seconds (default: 10)")
    parser.add_argument("--ml", action="store_true",
                         help="Also run the Isolation Forest ML layer")
    args = parser.parse_args()

    df = load_traffic(args.pcap)
    print(f"Loaded {len(df)} packets from {df['src_ip'].nunique()} unique source IPs\n")

    flows = build_flow_features(df, window_seconds=args.window)
    print(f"Built {len(flows)} flow-window rows using a {args.window}s window\n")

    print("=" * 60)
    print("RULE-BASED DETECTION RESULTS")
    print("=" * 60)
    flagged = run_all_rules(flows)
    if flagged.empty:
        print("No rule-based anomalies detected.")
    else:
        for _, row in flagged.iterrows():
            print(f"  [{row['rule'].upper():10s}] {row['src_ip']:16s} — {row['reason']}")

    if args.ml:
        print("\n" + "=" * 60)
        print("ML LAYER (ISOLATION FOREST) RESULTS")
        print("=" * 60)
        scored = detect_ml_anomalies(flows)
        ml_flagged = scored[scored["is_anomaly"]].sort_values("anomaly_score")
        if ml_flagged.empty:
            print("No ML anomalies detected.")
        else:
            for _, row in ml_flagged.iterrows():
                print(f"  [score={row['anomaly_score']:+.3f}] {row['src_ip']:16s} "
                      f"— {row['packet_count']} pkts, {row['unique_dst_ports']} ports, "
                      f"{row['packets_per_second']:.1f} pkt/s")


if __name__ == "__main__":
    main()
