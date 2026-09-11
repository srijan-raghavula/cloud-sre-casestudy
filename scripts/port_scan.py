#!/usr/bin/env python3
"""Port Scan Attack Automation (A1a — Network: Port Scanning)."""
import argparse, subprocess, sys, time, json, os, xml.etree.ElementTree as ET
from datetime import datetime

def run_nmap_scan(target, ports="1-1000", duration=60, output_dir="data/results"):
    os.makedirs(output_dir, exist_ok=True)
    ts = int(time.time())
    xml_file = f"{output_dir}/nmap_{target.replace('.', '_')}_{ts}.xml"
    cmd = ['nmap', '-sS', '-T4', '--min-rate', '1000', '-p', ports, '-oX', xml_file, target]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+30)
        elapsed = time.time() - start
        results = {'target': target, 'elapsed': round(elapsed, 2), 'return_code': proc.returncode}
        if os.path.exists(xml_file):
            results.update(parse_nmap_xml(xml_file))
        results['timestamp'] = datetime.now().isoformat()
        return results
    except subprocess.TimeoutExpired:
        return {'target': target, 'error': 'timeout', 'elapsed': duration, 'timestamp': datetime.now().isoformat()}

def parse_nmap_xml(xml_file):
    metrics = {'open_ports': 0, 'closed_ports': 0, 'filtered_ports': 0, 'open_port_list': []}
    try:
        tree = ET.parse(xml_file); root = tree.getroot()
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None:
                    name = state.get('name', 'unknown')
                    if name == 'open': metrics['open_ports'] += 1; metrics['open_port_list'].append(int(port.get('portid')))
                    elif name == 'closed': metrics['closed_ports'] += 1
                    elif name == 'filtered': metrics['filtered_ports'] += 1
    except: pass
    return metrics

def main():
    p = argparse.ArgumentParser(description="Port Scan Attack (A1a)")
    p.add_argument("--target", required=True); p.add_argument("--ports", default="1-1000")
    p.add_argument("--duration", type=int, default=60); p.add_argument("--output-dir", default="data/results")
    args = p.parse_args()
    results = run_nmap_scan(args.target, args.ports, args.duration, args.output_dir)
    with open(f"{args.output_dir}/port_scan_{int(time.time())}.json", 'w') as f: json.dump(results, f, indent=2)
    print(f"[PORT SCAN] Completed. Open ports: {results.get('open_ports', 0)}")

if __name__ == "__main__": main()
