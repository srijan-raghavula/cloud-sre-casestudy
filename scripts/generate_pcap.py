#!/usr/bin/env python3
"""
Synthetic PCAP Generator — Attack + Benign Traffic for Offline Pipeline.

Generates a deterministic PCAP with scapy (no root required) containing:
  - A1a: SYN port scan (many SYNs across ports)
  - A1:  SYN flood burst to port 80
  - A4c: HTTP GETs with SQLi / XSS / traversal payloads
  - Benign HTTP flows (handshake + GET + response)

The PCAP feeds both:
  - scripts/feature_extractor.py --pcap (flow features)
  - Suricata offline (-r pcap) for eve.json

Usage:
    python3 scripts/generate_pcap.py --output data/capture.pcap
    python3 scripts/generate_pcap.py --output data/capture.pcap --flows 50 --seed 42
"""

import argparse
import os
import random

from scapy.all import IP, TCP, Raw, wrpcap

ATTACKER = "10.0.1.100"
WEBSERVER = "10.0.2.10"

SQLI_PAYLOADS = [
    "/vulnerable?id=' UNION SELECT NULL,NULL,NULL--",
    "/vulnerable?id=' OR 1=1--",
    "/vulnerable?id='; DROP TABLE users--",
    "/vulnerable?x=' OR SLEEP(5)--&id=information_schema.tables",
    "/vuln?q=admin'--&u=mysql.user",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/search?q=<img src=x onerror=alert(1)>",
    "/search?q=javascript:alert(document.cookie)",
    "/search?q=<svg onload=alert(1)>",
]

TRAVERSAL_PAYLOADS = [
    "/files?f=../../etc/passwd",
    "/files?f=%2e%2e/%2e%2e/proc/self/environ",
]

BENIGN_PATHS = ["/", "/index.html", "/about", "/products?id=5", "/contact"]


def _tcp_flow(src, sport, dst, dport, payloads, seq0=1000, duration_ms=10):
    """Build a full TCP flow: SYN, SYN-ACK, ACK, PSH-ACKs, FINs."""
    pkts = []
    t = 1_700_000_000.0
    seq_c, seq_s = seq0, 5000

    syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c)
    syn.time = t
    pkts.append(syn)
    t += duration_ms / 1000.0 / 10

    synack = IP(src=dst, dst=src) / TCP(
        sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1
    )
    synack.time = t
    pkts.append(synack)
    t += duration_ms / 1000.0 / 10

    ack = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1
    )
    ack.time = t
    pkts.append(ack)
    t += duration_ms / 1000.0 / 10
    seq_c += 1
    seq_s += 1

    for pl in payloads:
        req = (
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s)
            / Raw(load=pl)
        )
        req.time = t
        pkts.append(req)
        t += duration_ms / 1000.0 / 10
        seq_c += len(pl)

        resp = (
            IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
            / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        )
        resp.time = t
        pkts.append(resp)
        t += duration_ms / 1000.0 / 10
        seq_s += 40

    fin = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s
    )
    fin.time = t
    pkts.append(fin)
    return pkts


def http_get(path, host=WEBSERVER):
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    ).encode()


def generate(output, n_scan_ports=120, n_flood=300, n_web_each=4, n_benign=20, seed=42):
    rng = random.Random(seed)
    pkts = []
    sport = 40000

    # ── A1a: SYN scan across ports ──
    for i in range(n_scan_ports):
        dport = 1 + (i * 7) % 1000
        p = IP(src=ATTACKER, dst=WEBSERVER) / TCP(
            sport=sport, dport=dport, flags="S", seq=100 + i
        )
        p.time = 1_700_000_000.0 + i * 0.005
        pkts.append(p)
        sport += 1

    # ── A1: SYN flood to port 80 ──
    base = 1_700_000_100.0
    for i in range(n_flood):
        p = IP(src=ATTACKER, dst=WEBSERVER) / TCP(
            sport=sport, dport=80, flags="S", seq=5000 + i
        )
        p.time = base + i * 0.001
        pkts.append(p)
        sport += 1

    # ── A4c: web attacks (full flows so Suricata reassembles HTTP) ──
    base = 1_700_000_200.0
    for pl in (
        SQLI_PAYLOADS[:n_web_each]
        + XSS_PAYLOADS[:n_web_each]
        + TRAVERSAL_PAYLOADS[:n_web_each]
    ):
        pkts.extend(
            _tcp_flow(
                ATTACKER,
                sport,
                WEBSERVER,
                80,
                [http_get(pl)],
                seq0=rng.randint(1000, 60000),
            )
        )
        sport += 1

    # ── Benign traffic ──
    for i in range(n_benign):
        path = rng.choice(BENIGN_PATHS)
        pkts.extend(
            _tcp_flow(
                f"10.0.1.{10 + (i % 40)}",
                sport,
                WEBSERVER,
                80,
                [http_get(path)],
                seq0=rng.randint(1000, 60000),
            )
        )
        sport += 1

    pkts.sort(key=lambda p: float(p.time))
    parent = os.path.dirname(output)
    if parent:
        os.makedirs(parent, exist_ok=True)
    wrpcap(output, pkts)
    print(f"[PCAP] Wrote {len(pkts)} packets to {output}")
    return output


def main():
    parser = argparse.ArgumentParser(description="Synthetic attack PCAP generator")
    parser.add_argument("--output", default="data/capture.pcap")
    parser.add_argument("--flows", type=int, default=20, help="Number of benign flows")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    generate(args.output, n_benign=args.flows, seed=args.seed)


if __name__ == "__main__":
    main()
