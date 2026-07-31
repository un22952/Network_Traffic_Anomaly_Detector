"""
ml_detector.py

Unsupervised anomaly detection using Isolation Forest, layered on top of the
rule-based detectors.

WHY ISOLATION FOREST SPECIFICALLY:
It doesn't need labeled attack examples to train (unlike a classifier) — it
works by randomly partitioning the feature space and observing that
anomalies (rare, different points) get isolated into their own partition in
fewer random splits than normal points do. This matches our problem well:
attacks are rare and different, but we don't want to hand-craft a rule for
every possible attack type in advance.

WHY THIS LAYER MATTERS (BEYOND THE RULES):
Rule-based detectors only catch what we explicitly coded for. This layer
can catch flow-feature combinations that are statistically weird WITHOUT
matching any of our hand-written thresholds — e.g. a slow, low-and-slow scan
that stays under the port-count threshold, or a beacon interval that's
irregular enough to dodge the CV threshold, but is still an outlier once we
look at all the features jointly.

We deliberately do NOT try to make this replace the rule-based layer —
in a real writeup we'd present them side by side and discuss the tradeoff:
rules are explainable and precise but rigid; the ML layer is more flexible
but its flags require more investigation to explain.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "packet_count",
    "unique_dst_ips",
    "unique_dst_ports",
    "avg_packet_size",
    "std_packet_size",
    "packets_per_second",
    "syn_ack_ratio",
]


def detect_ml_anomalies(flows, contamination=0.02, random_state=42):
    """
    Args:
        flows: flow-features DataFrame from flow_builder.build_flow_features
        contamination: expected proportion of anomalies in the data. This is
            the main knob to tune — too high and we get many false
            positives, too low and we miss real attacks. 0.02 (2%) is a
            reasonable starting point when we genuinely don't know the
            attack rate; in practice we'd tune this against a validation
            set the same way we'd tune the rule thresholds.
        random_state: for reproducibility.

    Returns:
        flows DataFrame with two new columns:
          - anomaly_score: raw Isolation Forest score (lower = more anomalous)
          - is_anomaly: boolean flag from the model's own threshold
    """
    data = flows.copy()

    # Missing values happen for e.g. std_packet_size when a window has just
    # one packet (std of one value is undefined) — fill with 0 rather than
    # dropping rows, since a single-packet window is itself informative.
    X = data[FEATURE_COLUMNS].fillna(0)

    # Isolation Forest splits on raw feature values, so features on very
    # different scales (e.g. packet_count ~10s vs packets_per_second ~100s)
    # can distort which splits look "informative." Standardizing puts every
    # feature on comparable footing.
    X_scaled = StandardScaler().fit_transform(X)

    model = IsolationForest(contamination=contamination, random_state=random_state)
    predictions = model.fit_predict(X_scaled)  # -1 = anomaly, 1 = normal
    scores = model.decision_function(X_scaled)  # lower = more anomalous

    data["anomaly_score"] = scores
    data["is_anomaly"] = predictions == -1

    return data


if __name__ == "__main__":
    from flow_builder import build_flow_features

    df = pd.read_csv("/home/linuxx/netanomaly/data/synthetic_traffic.csv")
    flows = build_flow_features(df)
    scored = detect_ml_anomalies(flows)

    flagged = scored[scored["is_anomaly"]].sort_values("anomaly_score")
    print(f"ML layer flagged {len(flagged)} of {len(flows)} flow-windows\n")
    print(flagged[["src_ip", "packet_count", "unique_dst_ports",
                    "packets_per_second", "syn_ack_ratio", "anomaly_score"]].to_string(index=False))
