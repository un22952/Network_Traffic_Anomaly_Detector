# Network Traffic Anomaly Detector

A network intrusion detection tool that identifies port scans, SYN floods,
and malware beaconing (C2 check-ins) from packet capture data, using both
rule-based detection and an unsupervised ML layer.

## Threat model

This project targets three well-known attack signatures:

| Attack | Signature | Detection approach |
|---|---|---|
| Port scan | One source IP contacts many distinct ports on a target in a short window | Threshold on unique destination ports per window |
| SYN flood | High packet rate with a very high SYN:ACK ratio (few completed handshakes) | Threshold on packets/sec and SYN:ACK ratio |
| Beaconing (C2) | One host contacts another at suspiciously regular intervals | Coefficient of variation on inter-packet timing |

## Architecture

```
ingestion/
  pcap_reader.py          # parses real .pcap files (Scapy)
  synthetic_generator.py  # generates labeled synthetic traffic for testing
detection/
  flow_builder.py         # aggregates packets into per-src-IP flow features
  rule_detectors.py       # threshold-based detectors (explainable, precise)
  ml_detector.py          # Isolation Forest anomaly detection (unsupervised)
evaluate.py                # precision/recall/FPR against ground truth
main.py                    # CLI entry point
```

**Pipeline:** raw packets → flow aggregation (10s windows) → rule-based
detectors → (optional) ML anomaly scoring → flagged IPs with reasons.

## Why rule-based AND ML?

Rules are explainable and precise for known attack signatures — you can
tell exactly why an IP was flagged. But they only catch what you explicitly
coded for. The Isolation Forest layer catches statistically unusual flow
behavior without needing a hand-written rule for it, at the cost of being
harder to explain and (in this implementation) noisier.

## Results (on bundled synthetic dataset)

Ground truth: 3 malicious IPs (1 port scanner, 1 SYN flooder, 1 beaconing
host) mixed into ~400 IPs of normal background traffic.

| Detector | Precision | Recall | False Positive Rate |
|---|---|---|---|
| Rule-based (combined) | 100% | 100% | 0% |
| Isolation Forest | 20% | 66.7% | 2% |
| Combined (OR) | 27.3% | 100% | 2% |

**Takeaway:** the rule-based layer nails all three known attack types with
zero false positives on this dataset. The ML layer catches the same two
high-volume attacks but misses the beaconing pattern (its features look
similar to normal periodic traffic in aggregate) and flags several
single-packet windows as false positives — an artifact of how
`packets_per_second` gets extreme for very short-lived flows. This is a
realistic illustration of the classic detection tradeoff: rules give you
precision on known patterns, ML gives you (noisier) coverage of the
unknown.

Run `python evaluate.py` to reproduce these numbers.

## Usage

```bash
pip install -r requirements.txt

# Run against bundled synthetic traffic
python main.py --ml

# Run against a real pcap file
python main.py --pcap capture.pcap --window 5 --ml

# Reproduce evaluation numbers
python evaluate.py
```

To test against real-world labeled traffic instead of the synthetic
generator, download a public IDS dataset such as
[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) or
[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) and
point `--pcap` at the capture files.

## Design decisions worth discussing

- **Aggregation window size (10s default):** shorter windows catch fast
  attacks (scans, floods) more sensitively but fragment slow beaconing;
  longer windows do the opposite. This is a real tunable tradeoff, not an
  arbitrary constant.
- **Grouping by src_ip rather than full 5-tuple flow:** port scans and
  floods are defined by one source's behavior *across* many
  destinations/ports, so grouping too narrowly (e.g., per 5-tuple) would
  hide the exact pattern being detected.
- **Isolation Forest over a supervised classifier:** no labeled attack
  data is required to train it, which matches real deployment conditions
  where you rarely have clean labeled attack examples in advance.

