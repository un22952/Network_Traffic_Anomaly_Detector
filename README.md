# Network Traffic Anomaly Detector

## Description
A Python network intrusion detection tool that analyzes PCAP files to detect port scans, SYN floods, and command-and-control (C2) beaconing. Combines explainable rule-based detection with an optional unsupervised Isolation Forest model to identify anomalous traffic.

## Run

```bash
pip install -r requirements.txt

# Analyze bundled synthetic traffic
python main.py --ml

# Analyze a PCAP file
python main.py --pcap capture.pcap --window 5 --ml

# Evaluate detection performance
python evaluate.py
```

## Features
- PCAP parsing with Scapy and synthetic traffic generation.
- Flow aggregation and feature extraction over configurable time windows.
- Rule-based detection for port scans, SYN floods, and beaconing.
- Optional Isolation Forest anomaly detection.
- Precision, recall, and false-positive-rate evaluation.

## Results

On the bundled synthetic dataset:

| Detector | Precision | Recall | False Positive Rate |
|---|---:|---:|---:|
| Rule-based | 100% | 100% | 0% |
| Isolation Forest | 20% | 66.7% | 2% |
| Combined | 27.3% | 100% | 2% |

The results illustrate the tradeoff between precise, explainable rules and broader but noisier ML-based anomaly detection.
