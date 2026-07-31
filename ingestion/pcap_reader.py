"""
pcap_reader.py

Reads a real .pcap/.pcapng capture file (e.g. from Wireshark, tcpdump, or a
public dataset like CICIDS2017/UNSW-NB15) and converts it into the same
packet-level DataFrame schema produced by synthetic_generator.py, so the rest
of the pipeline (flow_builder, detectors, evaluate) works unchanged regardless
of whether the data is real or synthetic.

Requires: scapy (pip install scapy)

Usage:
    from ingestion.pcap_reader import read_pcap
    df = read_pcap("capture.pcap")
"""

import pandas as pd
from scapy.all import rdpcap, TCP, IP


def read_pcap(path):
    """Parse a pcap file into a packet-level DataFrame.
    """
    packets = rdpcap(path)
    rows = []

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            flags = tcp_layer.flags  # a FlagValue object; supports 'S' in flags etc.

            rows.append({
                "timestamp": float(pkt.time),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": int(tcp_layer.sport),
                "dst_port": int(tcp_layer.dport),
                "protocol": "TCP",
                "size": len(pkt),
                "syn": "S" in flags,
                "ack": "A" in flags,
                # No ground-truth "label" column for real captures — that's
                # only available for datasets that ship labels (like
                # CICIDS2017's separate label CSVs, which you'd merge in
                # separately by matching on 5-tuple + timestamp).
            })

    df = pd.DataFrame(rows)
    return df.sort_values("timestamp").reset_index(drop=True)


def sniff_live(interface, duration_seconds=60):
    """Capture live traffic from a network interface for `duration_seconds`.
    """
    from scapy.all import sniff, wrpcap

    packets = sniff(iface=interface, timeout=duration_seconds)
    tmp_path = "/tmp/live_capture.pcap"
    wrpcap(tmp_path, packets)
    return read_pcap(tmp_path)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python pcap_reader.py <path_to_pcap>")
        sys.exit(1)
    df = read_pcap(sys.argv[1])
    print(f"Parsed {len(df)} TCP packets")
    print(df.head())
