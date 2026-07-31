"""
evaluate.py

Turns "it flagged some stuff" into actual numbers: precision, recall, and
false positive rate, measured against ground-truth labels.
Ground truth here is per src_ip (an IP is
"malicious" if any of its packets carry an attack label). We evaluate at the
src_ip level rather than per-packet or per-flow-window because that's the
actionable unit for a SOC analyst — you block/investigate an IP, not an
individual packet.
"""

import pandas as pd
from detection.flow_builder import build_flow_features
from detection.rule_detectors import run_all_rules
from detection.ml_detector import detect_ml_anomalies
from ingestion.synthetic_generator import build_synthetic_dataset




def get_ground_truth_malicious_ips(df):
    """An IP is malicious if ANY of its packets carry a non-'normal' label."""
    malicious = df[df["label"] != "normal"]["src_ip"].unique()
    return set(malicious)


def evaluate_detector(flagged_ips, all_ips, truth_ips, detector_name):
    flagged_ips = set(flagged_ips)
    all_ips = set(all_ips)

    true_positives = flagged_ips & truth_ips
    false_positives = flagged_ips - truth_ips
    false_negatives = truth_ips - flagged_ips
    true_negatives = (all_ips - truth_ips) - flagged_ips

    precision = len(true_positives) / len(flagged_ips) if flagged_ips else float("nan")
    recall = len(true_positives) / len(truth_ips) if truth_ips else float("nan")
    fpr = len(false_positives) / (len(false_positives) + len(true_negatives)) \
        if (false_positives or true_negatives) else float("nan")

    print(f"--- {detector_name} ---")
    print(f"  True positives:  {len(true_positives)}  {sorted(true_positives)}")
    print(f"  False positives: {len(false_positives)}  {sorted(false_positives)[:10]}"
          f"{' ...' if len(false_positives) > 10 else ''}")
    print(f"  False negatives: {len(false_negatives)}  {sorted(false_negatives)}")
    print(f"  Precision: {precision:.2%}" if precision == precision else "  Precision: n/a")
    print(f"  Recall:    {recall:.2%}" if recall == recall else "  Recall: n/a")
    print(f"  FPR:       {fpr:.2%}" if fpr == fpr else "  FPR: n/a")
    print()

    return {"precision": precision, "recall": recall, "fpr": fpr}


def main():

    df = build_synthetic_dataset()
    truth_ips = get_ground_truth_malicious_ips(df)
    all_ips = set(df["src_ip"].unique())

    print(f"Total unique source IPs: {len(all_ips)}")
    print(f"Ground-truth malicious IPs: {len(truth_ips)}  {sorted(truth_ips)}\n")

    flows = build_flow_features(df)

    # --- Rule-based ---
    rule_flags = run_all_rules(flows)
    rule_flagged_ips = rule_flags["src_ip"].unique()
    evaluate_detector(rule_flagged_ips, all_ips, truth_ips, "Rule-based detectors (combined)")

    # --- ML-based ---
    ml_scored = detect_ml_anomalies(flows)
    ml_flagged_ips = ml_scored[ml_scored["is_anomaly"]]["src_ip"].unique()
    evaluate_detector(ml_flagged_ips, all_ips, truth_ips, "Isolation Forest (ML layer)")

    # --- Combined (either layer flags it) ---
    combined_ips = set(rule_flagged_ips) | set(ml_flagged_ips)
    evaluate_detector(combined_ips, all_ips, truth_ips, "Combined (rules OR ML)")


if __name__ == "__main__":
    main()
