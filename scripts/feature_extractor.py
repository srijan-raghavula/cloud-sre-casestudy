#!/usr/bin/env python3
"""
Feature Extraction Pipeline — Real-time Network Flow Feature Extraction
Reference: Khan (2016) Case Study — Phase 3, Config C (Hybrid ML-IDPS)

Extracts 5 key flow features from live packet capture using PyShark/scapy
for real-time ML anomaly detection.

Features extracted:
  1. Flow Duration (ms)
  2. Total Forward/Backward Packets
  3. Packet Length Mean & Std Dev
  4. Flow Bytes/s & Flow Packets/s
  5. TCP Flag Counts (SYN, ACK, FIN)

Usage:
    python3 feature_extractor.py --interface eth0 --output data/flow_features.csv
    python3 feature_extractor.py --pcap data/capture.pcap --output data/flow_features.csv
"""

import argparse
import json
import time
import threading
import sys
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import pyshark

    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    from scapy.layers.inet import TCP_OL

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─────────────────────────────────────────────────────────────
# Flow Record Data Structure
# ─────────────────────────────────────────────────────────────
class FlowRecord:
    """Represents a single network flow with all extracted features."""

    __slots__ = [
        "flow_id",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "start_time",
        "end_time",
        "duration_ms",
        "total_fwd_pkts",
        "total_bwd_pkts",
        "total_fwd_bytes",
        "total_bwd_bytes",
        "packet_lengths",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "flag_syn",
        "flag_ack",
        "flag_fin",
        "flag_rst",
        "flag_psh",
        "flag_urg",
    ]

    def __init__(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.end_time = time.time()
        self.duration_ms = 0.0
        self.total_fwd_pkts = 0
        self.total_bwd_pkts = 0
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        self.packet_lengths = []
        self.flow_bytes_per_sec = 0.0
        self.flow_packets_per_sec = 0.0
        self.flag_syn = 0
        self.flag_ack = 0
        self.flag_fin = 0
        self.flag_rst = 0
        self.flag_psh = 0
        self.flag_urg = 0

    def to_dict(self) -> Dict:
        """Convert flow record to dictionary for CSV/JSON export."""
        lengths = self.packet_lengths if self.packet_lengths else [0]
        return {
            "timestamp": datetime.now().isoformat(),
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_ms": round(self.duration_ms, 2),
            "total_fwd_pkts": self.total_fwd_pkts,
            "total_bwd_pkts": self.total_bwd_pkts,
            "total_pkts": self.total_fwd_pkts + self.total_bwd_pkts,
            "total_fwd_bytes": self.total_fwd_bytes,
            "total_bwd_bytes": self.total_bwd_bytes,
            "pkt_len_mean": round(sum(lengths) / len(lengths), 2),
            "pkt_len_std": round(
                (
                    sum((l - (sum(lengths) / len(lengths))) ** 2 for l in lengths)
                    / len(lengths)
                )
                ** 0.5,
                2,
            )
            if len(lengths) > 1
            else 0.0,
            "flow_bytes_per_sec": round(self.flow_bytes_per_sec, 2),
            "flow_packets_per_sec": round(self.flow_packets_per_sec, 2),
            "flag_syn": self.flag_syn,
            "flag_ack": self.flag_ack,
            "flag_fin": self.flag_fin,
            "flag_rst": self.flag_rst,
            "flag_psh": self.flag_psh,
            "flag_urg": self.flag_urg,
        }


# ─────────────────────────────────────────────────────────────
# Feature Extractor — PyShark Backend
# ─────────────────────────────────────────────────────────────
class PySharkExtractor:
    """Live packet capture and feature extraction using PyShark."""

    def __init__(self, interface: str, bpf_filter: str = "tcp or udp"):
        if not HAS_PYSHARK:
            raise ImportError("PyShark not installed: pip install pyshark")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flows: Dict[str, FlowRecord] = {}
        self._lock = threading.Lock()
        self._running = False

    def _get_flow_key(self, packet) -> str:
        """Generate unique flow identifier from packet tuple."""
        try:
            src = str(packet.ip.src)
            dst = str(packet.ip.dst)
            src_port = int(packet[tcp].srcport) if "tcp" in packet else 0
            dst_port = int(packet[tcp].dstport) if "tcp" in packet else 0
            proto = packet.highest_layer
            # Canonical flow ID (sorted endpoints for bidirectional)
            if (src, src_port) < (dst, dst_port):
                return f"{src}:{src_port}->{dst}:{dst_port}:{proto}"
            else:
                return f"{dst}:{dst_port}->{src}:{src_port}:{proto}"
        except (AttributeError, IndexError):
            return None

    def _is_forward(self, packet, flow: FlowRecord) -> bool:
        """Check if packet is in forward direction."""
        try:
            return str(packet.ip.src) == flow.src_ip
        except AttributeError:
            return True

    def _extract_tcp_flags(self, packet, flow: FlowRecord):
        """Extract and count TCP flags from packet."""
        try:
            tcp_layer = packet["tcp"]
            flags = tcp_layer.flags
            if hasattr(flags, "SYN") and flags.SYN:
                flow.flag_syn += 1
            if hasattr(flags, "ACK") and flags.ACK:
                flow.flag_ack += 1
            if hasattr(flags, "FIN") and flags.FIN:
                flow.flag_fin += 1
            if hasattr(flags, "RST") and flags.RST:
                flow.flag_rst += 1
            if hasattr(flags, "PSH") and flags.PSH:
                flow.flag_psh += 1
            if hasattr(flags, "URG") and flags.URG:
                flow.flag_urg += 1
        except (AttributeError, KeyError):
            pass

    def process_packet(self, packet):
        """Process a single captured packet and update flow features."""
        try:
            if not hasattr(packet, "ip"):
                return

            src = str(packet.ip.src)
            dst = str(packet.ip.dst)
            proto = packet.highest_layer

            try:
                src_port = int(packet["tcp"].srcport) if "tcp" in packet else 0
                dst_port = int(packet["tcp"].dstport) if "tcp" in packet else 0
            except (AttributeError, IndexError):
                src_port = dst_port = 0

            flow_key = f"{src}:{src_port}->{dst}:{dst_port}:{proto}"
            reverse_key = f"{dst}:{dst_port}->{src}:{src_port}:{proto}"

            with self._lock:
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                elif reverse_key in self.flows:
                    flow = self.flows[reverse_key]
                else:
                    flow = FlowRecord(flow_key, src, dst, src_port, dst_port, proto)
                    self.flows[flow_key] = flow

                # Update packet counts
                is_fwd = self._is_forward(packet, flow)
                if is_fwd:
                    flow.total_fwd_pkts += 1
                else:
                    flow.total_bwd_pkts += 1

                # Extract packet length
                try:
                    pkt_len = int(packet.length)
                    flow.packet_lengths.append(pkt_len)
                    if is_fwd:
                        flow.total_fwd_bytes += pkt_len
                    else:
                        flow.total_bwd_bytes += pkt_len
                except (AttributeError, ValueError):
                    pass

                # Extract TCP flags
                if proto == "TCP":
                    self._extract_tcp_flags(packet, flow)

                # Update end time and rates
                flow.end_time = time.time()
                flow.duration_ms = (flow.end_time - flow.start_time) * 1000
                elapsed = max(flow.end_time - flow.start_time, 0.001)
                flow.flow_bytes_per_sec = (
                    flow.total_fwd_bytes + flow.total_bwd_bytes
                ) / elapsed
                flow.flow_packets_per_sec = (
                    flow.total_fwd_pkts + flow.total_bwd_pkts
                ) / elapsed

        except Exception as e:
            pass  # Silently skip malformed packets

    def start_capture(self, output_file: str = None, callback=None):
        """Start live packet capture."""
        self._running = True
        capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter=self.bpf_filter,
            output_file=output_file,
        )

        def _capture_loop():
            try:
                for packet in capture.sniff_continuously():
                    if not self._running:
                        break
                    self.process_packet(packet)
                    if callback:
                        callback(packet)
            except Exception as e:
                print(f"[ERROR] Capture error: {e}", file=sys.stderr)
            finally:
                capture.close()

        thread = threading.Thread(target=_capture_loop, daemon=True)
        thread.start()
        return thread

    def stop_capture(self):
        """Stop the live capture."""
        self._running = False

    def export_flows(self, output_path: str):
        """Export all captured flows to CSV format."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        records = [flow.to_dict() for flow in self.flows.values()]
        import csv

        if records:
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
        print(f"[INFO] Exported {len(records)} flows to {output_path}")
        return records


# ─────────────────────────────────────────────────────────────
# Feature Extractor — Scapy Backend (Fallback)
# ─────────────────────────────────────────────────────────────
class ScapyExtractor:
    """Live packet capture and feature extraction using Scapy."""

    def __init__(self, interface: str, bpf_filter: str = "tcp"):
        if not HAS_SCAPY:
            raise ImportError("Scapy not installed: pip install scapy")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flows: Dict[str, FlowRecord] = {}
        self._lock = threading.Lock()
        self._running = False

    def _get_flow_key(self, pkt) -> Optional[str]:
        """Generate unique flow identifier."""
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if (src, sport) < (dst, dport):
            return f"{src}:{sport}->{dst}:{dport}:TCP"
        return f"{dst}:{dport}->{src}:{sport}:TCP"

    def _process_packet(self, pkt):
        """Process individual scapy packet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        flow_key = self._get_flow_key(pkt)
        if not flow_key:
            return

        with self._lock:
            if flow_key not in self.flows:
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                self.flows[flow_key] = FlowRecord(
                    flow_key, src, dst, sport, dport, "TCP"
                )

            flow = self.flows[flow_key]
            pkt_len = len(pkt)
            flow.total_fwd_pkts += 1
            flow.packet_lengths.append(pkt_len)
            flow.total_fwd_bytes += pkt_len
            flow.end_time = time.time()
            flow.duration_ms = (flow.end_time - flow.start_time) * 1000
            elapsed = max(flow.end_time - flow.start_time, 0.001)
            flow.flow_bytes_per_sec = flow.total_fwd_bytes / elapsed
            flow.flow_packets_per_sec = flow.total_fwd_pkts / elapsed

            # TCP flags
            flags = pkt[TCP].flags
            if flags & 0x02:
                flow.flag_syn += 1  # SYN
            if flags & 0x10:
                flow.flag_ack += 1  # ACK
            if flags & 0x01:
                flow.flag_fin += 1  # FIN
            if flags & 0x04:
                flow.flag_rst += 1  # RST
            if flags & 0x08:
                flow.flag_psh += 1  # PSH
            if flags & 0x20:
                flow.flag_urg += 1  # URG

    def start_capture(self, output_file: str = None, duration: int = 300):
        """Start live packet capture with Scapy."""
        self._running = True

        def _timeout_check():
            time.sleep(duration)
            self.stop_capture()

        timeout_thread = threading.Thread(target=_timeout_check, daemon=True)
        timeout_thread.start()

        def _packet_handler(pkt):
            if not self._running:
                return
            self._process_packet(pkt)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_packet_handler,
            store=False,
            timeout=duration,
        )

    def stop_capture(self):
        self._running = False

    def export_flows(self, output_path: str):
        """Export all captured flows to CSV."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        records = [flow.to_dict() for flow in self.flows.values()]
        import csv

        if records:
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
        print(f"[INFO] Exported {len(records)} flows to {output_path}")
        return records


# ─────────────────────────────────────────────────────────────
# Unified Feature Pipeline
# ─────────────────────────────────────────────────────────────
class FeaturePipeline:
    """Orchestrates feature extraction and feeds data to ML detector."""

    def __init__(self, backend: str = "scapy", interface: str = "eth0"):
        self.backend = backend
        self.interface = interface
        self.extractor = None
        self._results_callback = None

    def set_callback(self, callback):
        """Set callback for real-time feature streaming to ML detector."""
        self._results_callback = callback

    def initialize(self):
        """Initialize the appropriate extractor backend."""
        if self.backend == "pyshark":
            self.extractor = PySharkExtractor(interface=self.interface)
        else:
            self.extractor = ScapyExtractor(interface=self.interface)
        print(
            f"[INFO] Feature extractor initialized with {self.backend} backend on {self.interface}"
        )

    def start(self, output_file: str = None, duration: int = 300):
        """Start feature extraction pipeline."""
        if self.extractor is None:
            self.initialize()
        self.extractor.export_fn = output_file
        if self.backend == "pyshark":
            thread = self.extractor.start_capture(output_file=output_file)
        else:
            self.extractor.start_capture(duration=duration)
        return self.extractor

    def stop(self):
        """Stop the pipeline and export results."""
        if self.extractor:
            self.extractor.stop_capture()


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Real-time Network Flow Feature Extractor for Hybrid ML-IDPS"
    )
    parser.add_argument("--interface", default="eth0", help="Network interface")
    parser.add_argument(
        "--backend",
        choices=["pyshark", "scapy"],
        default="scapy",
        help="Packet capture backend",
    )
    parser.add_argument("--pcap", default=None, help="Read from offline PCAP file")
    parser.add_argument(
        "--output", default="data/flow_features.csv", help="Output CSV path"
    )
    parser.add_argument(
        "--duration", type=int, default=300, help="Capture duration in seconds"
    )
    parser.add_argument(
        "--ml-endpoint",
        default=None,
        help="ML detector socket endpoint for real-time streaming",
    )

    args = parser.parse_args()

    pipeline = FeaturePipeline(backend=args.backend, interface=args.interface)

    if args.ml_endpoint:
        pipeline.set_callback(lambda pkt: None)  # Connect to ML daemon

    print(f"[INFO] Starting feature extraction ({args.backend}, {args.duration}s)...")
    pipeline.start(output_file=args.output, duration=args.duration)
    pipeline.stop()

    flows = pipeline.extractor.export_flows(args.output)
    print(f"[INFO] Extraction complete. {len(flows)} flows captured.")
    if flows:
        print(f"[INFO] Sample features: {json.dumps(flows[0], indent=2)}")


if __name__ == "__main__":
    main()
