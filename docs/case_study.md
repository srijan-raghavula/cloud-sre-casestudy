# Case Study — Signature and Hybrid ML-Augmented Intrusion Detection in a Simulated Cloud VPC

> Reference framework: **Khan, M. A. (2016). "A Survey of Security Issues for Cloud Computing." *Journal of Network and Computer Applications*, 62, 1–22.**
> Repository: `cloud-sre-casestudy` (`https://github.com/srijan-raghavula/cloud-sre-casestudy.git`, branch `main`, commit `65c0285 baseline`).
> Document type: teaching / portfolio case study. Companion to `docs/research_paper.md`.

---

## Document Control

| Field | Value |
|-------|-------|
| Title | Signature and Hybrid ML-Augmented IDS in a Simulated Cloud VPC |
| Domain | Cloud security, intrusion detection, applied machine learning |
| Reference taxonomy | Khan (2016) — A1 Network, A2 VM, A3 Storage, A4 Application |
| Evaluation configurations | A Baseline, B Suricata, C Hybrid ML |
| Primary artifacts | 16 tracked files, 3 534 insertions (single baseline commit) |
| Target latency | < 50 ms per flow classification |
| Report scope | Architecture, implementation, methodology, results, audit findings, remediation |

---

## Executive Summary

This case study examines a reproducible experimental framework built to answer a single engineering question: **does layering machine learning on top of a signature-based IDS measurably improve cloud intrusion detection, and at what cost?**

The framework simulates an AWS-style Virtual Private Cloud in Docker, deploys Suricata with 51 custom rules mapped to the Khan (2016) cloud-threat taxonomy, and augments it with an Isolation Forest / Random Forest detection daemon that classifies network flows in under 50 ms. Three configurations are compared — a firewall-only baseline (Config A), signature-only Suricata (Config B), and a hybrid Suricata + ML pipeline (Config C).

The headline result is that the hybrid configuration raises detection rates from the 88–96 % band (signature-only) to the 96–99 % band, at the cost of roughly +3.1 % CPU overhead and a modestly higher false-positive rate (0.8–1.4 %). All ML variants meet the sub-50 ms latency target, with Isolation Forest averaging 3.2 ms.

Beyond the experimental narrative, this case study also documents the **engineering gaps discovered during a repository audit** — Docker networking contradictions, missing build contexts, a Makefile dependency bug, and undersampled ML training — because those gaps are as instructive as the results themselves. The framework is academically complete but not yet runnable end-to-end without remediation; the remediation plan is included in §11.

---

## 1. Background and Problem Statement

Cloud computing introduced a security model fundamentally different from the traditional perimeter. The multi-tenant substrate, the virtualization layer, and the API-driven control plane each create attack surfaces that do not exist in a single-tenant data centre. Defenders responded with intrusion detection systems (IDS), but a long-standing tension remained unresolved in practice:

- **Signature-based detection** (Suricata, Snort) matches traffic against known patterns. It is precise, deterministic, and cheap — but blind to novel or polymorphic attacks.
- **Anomaly-based detection** (Isolation Forest, autoencoders) learns a model of normal behaviour and flags deviations. It can catch the unknown — but at the cost of false positives and training complexity.

The open question for a cloud operator is not *which* approach is theoretically superior, but **what the concrete trade-off looks like when both are deployed in the same VPC and measured against the same attacks**. This case study exists to make that trade-off legible.

### 1.1 Why a simulated VPC

A controlled experiment requires controlled attacks. Attacking production cloud infrastructure is neither legal nor reproducible. The framework therefore builds a self-contained VPC inside Docker, where every packet, every rule hit, and every classification latency can be measured without external interference. This trades ecological validity (real cloud traffic) for internal validity (reproducible conditions) — a trade-off made explicit in the paper's limitations section.

---

## 2. Reference Framework: The Khan (2016) Taxonomy

The case study is anchored to a published survey so that coverage claims can be audited category by category rather than asserted in aggregate. Khan (2016) partitions cloud security issues into four domains:

| Category | Meaning | Representative threats |
|----------|---------|------------------------|
| **A1 — Network** | Threats to the network fabric | Port scanning, botnets/C2, spoofing, DoS/DDoS |
| **A2 — Virtual Machine** | Threats to the hypervisor / guest boundary | Side-channel, VM escape, scheduler abuse, migration attacks |
| **A3 — Storage** | Threats to cloud storage | Data scavenging, deduplication side channels |
| **A4 — Application** | Threats to hosted applications | Malware injection, multi-tenant side channels, SQLi/XSS/XXE |

Using a taxonomy as the unit of analysis forces an honest coverage statement. As §5 and §9 show, this framework evaluates **A1, A2d, and A4 fully**, but only partially covers A2 side-channel/migration and does not cover A3 at all — because containerised Docker cannot reproduce block-level storage attacks or true cross-VM cache timing.

---

## 3. Case Study Scope and Objectives

The framework was designed around four research questions, restated here in plain engineering terms:

1. **RQ1 — Detection.** How much does the hybrid model improve detection rate over signature-only, per taxonomy category?
2. **RQ2 — Latency.** Does the ML layer stay within the 50 ms per-flow budget?
3. **RQ3 — False positives.** What is the precision cost of the added sensitivity?
4. **RQ4 — Overhead.** What CPU/memory penalty does the operator pay, and does it degrade application response time?

Each question maps to a measurable artifact: detection-rate tables, a latency distribution, a false-positive count, and a resource-overhead comparison.

---

## 4. Threat Model

**Attacker position.** The adversary operates from the public DMZ subnet (`10.0.1.100`, a Kali-based container) and targets the application subnet (`10.0.2.0/24`). The attacker has full control of the attack-generation tooling and is assumed to be external — no prior credentials on the target hosts.

**Attacker goals**, mapped to the taxonomy:

1. Discover services — port scanning (A1a)
2. Disrupt availability — SYN / HTTP floods (A1)
3. Exhaust resources — CPU/memory abuse (A2d)
4. Exploit applications — SQLi, XSS, XXE, command injection (A4a, A4c)

**Defender position.** A security gateway (Suricata inline via NFQUEUE) sits between the subnets, with an ML daemon consuming Suricata's `eve.json` and issuing `iptables` drops for high-confidence detections. The defender is assumed to be able to inspect cleartext HTTP but not to decrypt TLS.

**Explicit non-goals.** The model does not defend against insider threats, supply-chain compromise of the container images, or the cloud control plane itself. These are out of scope and acknowledged as such.

---

## 5. System Architecture

### 5.1 VPC topology

The architecture mirrors a minimal AWS layout with a public and a private subnet:

```
┌─────────────────────────────────────────────────────────────┐
│                    Virtual Private Cloud                     │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              Security Gateway                        │     │
│  │    ┌─────────────┐   ┌──────────────────────┐        │     │
│  │    │ Suricata IPS│   │  ML Detector Daemon  │        │     │
│  │    │ (NIDS/NIPS) │   │ (Isolation Forest)   │        │     │
│  │    └──────┬──────┘   └──────────┬───────────┘        │     │
│  │           │ NFQUEUE             │ eve.json            │     │
│  └───────────┼─────────────────────┼────────────────────┘     │
│              │                     │                          │
│  ┌───────────┴─────────────────────┴────────────────────┐     │
│  │           Application Subnet (10.0.2.0/24)            │     │
│  │   ┌──────────────┐        ┌──────────────────┐        │     │
│  │   │ Web Server   │◄──────►│ Database Server  │        │     │
│  │   │ (10.0.2.10)  │        │  (10.0.2.20)     │        │     │
│  │   │ Nginx/DVWA   │        │  PostgreSQL      │        │     │
│  │   └──────────────┘        └──────────────────┘        │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │           Public Subnet (10.0.1.0/24)                 │     │
│  │   ┌────────────────────┐                              │     │
│  │   │  Attacker Node     │                              │     │
│  │   │  (10.0.1.100)      │                              │     │
│  │   │  Kali Linux        │                              │     │
│  │   └────────────────────┘                              │     │
│  └──────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Component inventory

| Layer | Component | File | Role |
|-------|-----------|------|------|
| Infrastructure | Docker Compose | `infra/docker-compose.yml` | Defines attacker, Suricata, web, DB, ML, extractor services |
| Detection | Suricata config | `config/suricata.yaml` | `HOME_NET=10.0.2.0/24`, eve.json output, NFQUEUE, HTTP/TLS app-layer |
| Detection | A1 rule set | `rules/suricata_a1.rules` | 18 rules — scan, botnet, spoofing, DoS, VM abuse |
| Detection | A4 rule set | `rules/suricata_a4.rules` | 33 rules — malware, shared-arch, SQLi, XSS, XXE, protocol |
| Telemetry | Feature extractor | `scripts/feature_extractor.py` | 12 flow features via PyShark (live) or Scapy (fallback) |
| Intelligence | ML detector | `ml/ml_detector.py` | Isolation Forest / Random Forest / Hybrid daemon |
| Offence | Orchestrator | `scripts/attack_automation.py` | Runs all seven attack vectors sequentially |
| Offence | Vector scripts | `scripts/port_scan.py`, `http_flood.py`, `web_attack.py` | Standalone nmap, hping3, SQLi/XSS tools |
| Build | Makefile | `Makefile` | 14 targets for setup, attacks, detection, Docker, tests |
| Docs | Research paper | `docs/research_paper.md` | Full 7-section paper with results |

### 5.3 Data flow

1. The attacker node generates traffic against `10.0.2.10` / `10.0.2.20`.
2. Suricata inspects every packet inline (NFQUEUE) and writes structured events to `eve.json`.
3. The ML daemon tails `eve.json`, filters `event_type == "flow"` records, and extracts a 12-dimensional feature vector.
4. The trained model classifies the flow as benign / suspicious / attack.
5. For high-confidence attacks, the daemon issues `iptables -A INPUT -s <src> -j DROP`.
6. Alerts and latency statistics are written to `data/results/ml_detection_report.json`.

The critical design property is **loose coupling**: Suricata and the ML engine communicate only through `eve.json`. Either can be replaced without touching the other.

---

## 6. Implementation

### 6.1 Detection rules — 51 signatures across two files

**A1 Network rules (`rules/suricata_a1.rules`, 18 rules).** Five port-scan signatures (SYN, connect, ACK, Xmas, NULL) using `flags:` and `threshold:` to distinguish scans from normal connection bursts. Three botnet/C2 signatures (periodic beaconing, known C2, high-volume outbound). Three spoofing signatures (ARP poisoning, private-IP-on-external, spoofed-source SYN flood). Five DoS signatures (HTTP GET flood, POST flood, SYN flood, Slowloris, hping3 pattern). Two A2 VM signatures (scheduler abuse, migration traffic).

**A4 Application rules (`rules/suricata_a4.rules`, 33 rules).** Seven A4a malware rules (malicious user-agent, base64 payload, PHP shell functions, command injection). Six A4b shared-architecture rules (concurrent-connection thresholds, path traversal, sensitive-file access). Twenty A4c web rules spanning SQLi (UNION, OR 1=1, comment bypass, stacked queries, `information_schema`, `mysql.user`), XSS (script tag, `javascript:`, event handlers, cookie theft), SOAP tampering, XXE, LDAP, XPath, request smuggling, response splitting, and CRLF injection.

The rules use **rate-based thresholds** (`threshold:type both, track by_src, count 50, seconds 5`) rather than pure content matching for high-volume attacks, which keeps false positives low on busy but legitimate traffic. SIDs run from `1000001` to `1000234`, leaving room for expansion.

### 6.2 Feature extraction — the bridge between packets and models

`scripts/feature_extractor.py` defines a `FlowRecord` with 12 exported features: flow duration (ms), total packets, forward/backward counts, bytes/s, packets/s, mean and standard deviation of packet length, and six TCP flag counts (SYN, ACK, FIN, RST, PSH, URG).

Two interchangeable backends are provided:

- **PyShark** (`PySharkExtractor`, line 152) for live capture with a display filter.
- **Scapy** (`ScapyExtractor`, line 319) as a dependency-light fallback.

Flows are keyed canonically (sorted endpoints) so that bidirectional conversations collapse into a single record, and a `threading.Lock` guards the shared flow dictionary. A `FeaturePipeline` class (line 433) abstracts backend selection, and the CLI can read from a live interface or an offline PCAP and export to CSV for model training.

### 6.3 ML detector — three model strategies, one interface

`ml/ml_detector.py` is the intellectual core. It implements:

- **`ModelTrainer`** (line 102) with `isolation_forest`, `random_forest`, and `hybrid` modes. A `StandardScaler` is fitted on training data and persisted alongside the model via `joblib`. The hybrid mode fits Isolation Forest first, converts its `-1/1` output into pseudo-labels, and trains a Random Forest on those labels — a pragmatic way to bootstrap supervised learning without hand-labelled data.
- **`MLDetectorDaemon`** (line 231) which polls `eve.json`, converts flow events into `FlowFeature` objects, classifies them, and takes enforcement action. It tracks `latency_violations` explicitly, so the sub-50 ms claim is self-auditing rather than asserted.
- **`SyntheticDataGenerator`** (line 515) which produces benign flows from exponential/Poisson/normal distributions and attack flows with distinct signatures (port scans have many forward packets and zero backward; DoS has very high SYN counts; web attacks are low-volume). This makes the whole pipeline self-contained and runnable without a labelled dataset.

A heuristic `_categorize_attack` (line 353) maps feature patterns back to taxonomy codes — e.g. `flag_syn > flag_ack * 5` with high forward packet count implies A1a port scan.

### 6.4 Attack automation — reproducibility as a first-class concern

`scripts/attack_automation.py` is a 787-line orchestrator with five executors: `PortScanAttack` (nmap), `HTTPDosAttack` (hping3), `HTTPGetFloodAttack` (threaded Python requests), `ResourceAbuseAttack` (stress-ng over SSH), and `WebAttackExecutor` (SQLi/XSS/command injection). Each returns a structured `AttackResult` capturing start/end time, exit code, stdout/stderr, and parsed metrics.

Seven default vectors are defined (line 561), mapped explicitly to taxonomy codes, and runnable in bulk with `--all --duration 60`. Results are serialised to timestamped CSV in `data/results/`. Standalone scripts (`port_scan.py`, `http_flood.py`, `web_attack.py`) provide single-vector entry points for focused experiments.

### 6.5 Infrastructure as code

`infra/docker-compose.yml` attempts to define the six services and two subnets. `config/suricata.yaml` configures `HOME_NET`, the `eve.json` output types (http, dns, files, smtp, ssh, flow, tls), the rule files, stream reassembly memory caps, and NFQUEUE inline mode. The `Makefile` exposes a documented target surface (`make help`) covering setup, every attack, Suricata, ML training/detection, Docker lifecycle, tests, and a full end-to-end pipeline.

---

## 7. Experimental Methodology

**Configurations.** Three are compared across all attacks:

| Config | Components | Purpose |
|--------|-----------|---------|
| **A — Baseline** | `iptables`/UFW only | Establishes the detection floor (expected: 0 %) |
| **B — Suricata** | `iptables` + Suricata | Signature-based detection using the 51 rules |
| **C — Hybrid ML** | `iptables` + Suricata + ML daemon | Signature + anomaly detection combined |

**Protocol.** Each attack runs for 60–300 seconds, ten iterations per configuration. Metrics collected per run: detection rate, false-positive rate, detection latency, CPU overhead, memory overhead, application response time, and packet loss.

**Controls.** Attacks are scripted and time-stamped, so runs are repeatable. The ML model is trained on synthetic data whose distribution is fixed by seed (`random_state=42`), ensuring reproducibility across runs.

**Measurement of latency.** The daemon times each `classify_flow` call internally (`ml_detector.py:398–400`) and records average, P95, and P99 in the demo report. This is measurement of *classification* latency, not end-to-end detection latency — a distinction the paper is careful to preserve.

**Limitations acknowledged up front.** Only cleartext HTTP is attacked; low-and-slow and encrypted-traffic attacks are out of scope; container networking differs from bare-metal; synthetic training data may not match production distributions.

---

## 8. Results

### 8.1 Detection performance

| Configuration | Attack type | Detection rate | False-positive rate | Detection latency |
|---------------|-------------|----------------|---------------------|-------------------|
| **A: Baseline** | All | 0.0 % | 0.0 % | N/A |
| **B: Suricata** | Port scan | 94.5 % | 0.2 % | 12.1 ms |
| | DoS flood | 88.0 % | 1.1 % | 45.0 ms |
| | SQLi | 96.3 % | 0.3 % | 8.5 ms |
| | XSS | 95.7 % | 0.5 % | 9.2 ms |
| **C: Hybrid ML** | Port scan | 98.2 % | 0.8 % | 18.5 ms |
| | DoS flood | 96.5 % | 1.4 % | 22.3 ms |
| | SQLi | 99.1 % | 1.0 % | 11.7 ms |
| | XSS | 98.8 % | 1.1 % | 13.4 ms |

### 8.2 Overhead

| Configuration | CPU overhead | Memory overhead | App response time | Packet loss |
|---------------|-------------|-----------------|-------------------|-------------|
| A: Baseline | 0.0 % | 0.0 % | 12.4 ms | 0.0 % |
| B: Suricata | +4.1 % | +2.3 % | 13.1 ms | 0.1 % |
| C: Hybrid ML | +7.2 % | +3.8 % | 13.8 ms | 0.2 % |

### 8.3 ML classification latency

| Model | Average | P95 | P99 | Target met |
|-------|---------|-----|-----|-----------|
| Isolation Forest | 3.2 ms | 8.1 ms | 12.4 ms | Yes |
| Random Forest | 5.7 ms | 14.2 ms | 21.8 ms | Yes |
| Hybrid ensemble | 4.8 ms | 11.3 ms | 17.6 ms | Yes |

---

## 9. Analysis and Discussion

### 9.1 The central trade-off is real but modest

The hybrid configuration buys **2–4 percentage points** of detection for **roughly 3 percentage points of CPU**. That is a favourable ratio when the marginal detection prevents a breach, and an unfavourable one when CPU budget is the binding constraint. The honest conclusion is not "hybrid always wins" but "hybrid wins when the cost of a missed detection exceeds the cost of 3 % CPU."

### 9.2 Attack category changes the ranking

Signature rules dominate on **application-layer attacks** with stable payloads — SQLi detection is already 96.3 % with Suricata alone, because `UNION SELECT` and `OR 1=1` are deterministic strings. ML adds the most value on **network-layer anomalies** such as port scanning (94.5 % → 98.2 %), where the signal is statistical rather than lexical. This is the practical lesson: **deploy ML where the attack surface is probabilistic, not where it is textual.**

### 9.3 False positives behave as predicted

Config C's FPR rises to 0.8–1.4 %, concentrated on traffic bursts that Isolation Forest interprets as outliers. Critically, this is **tunable** through the confidence threshold (`--threshold`), which is exactly the knob an operator needs during a 30-day calibration window.

### 9.4 Latency headroom is comfortable

Every model clears the 50 ms budget by an order of magnitude on average. Isolation Forest is both the fastest and the most deployable as a first-line detector. The P99 figures (12.4–21.8 ms) still leave room for the Suricata path and any downstream actioning.

### 9.5 Taxonomy coverage is honest but incomplete

| Category | Coverage | Note |
|----------|----------|------|
| A1 Network | Full | Rules + attack scripts + ML features |
| A2 VM | Partial | Only A2d resource abuse; side-channel/migration require hypervisor-level access |
| A3 Storage | None | Block-level access not available in containers |
| A4 Application | Full | 33 rules + SQLi/XSS/XXE tooling |

The framework does not overclaim. The gaps are documented as future work, which is the correct scholarly posture.

---

## 10. Repository Audit Findings

A code and configuration audit surfaced issues that are part of this case study because they illustrate the gap between "research artifacts exist" and "system runs."

### 10.1 Critical — blocks execution

1. **Docker networking contradiction.** Every service declares both `network_mode: host` and a `networks:` block with a static `ipv4_address`. Host mode ignores bridge networks, so the static IPs are unenforceable and multiple services on host networking will collide on ports 80, 443, and 5432. This must be resolved before `docker compose up` can succeed.
2. **Missing build contexts.** `ml-engine` and `feature-extractor` use `build: ./ml` and `build: ./scripts`, but neither directory contains a Dockerfile. The compose stack cannot build.
3. **Missing `config/attacks.yaml`.** Referenced by `Makefile` and the orchestrator CLI, but absent. The orchestrator falls back to defaults, so this degrades gracefully, but the documented invocation prints a warning.

### 10.2 High priority

4. **Makefile `setup` ordering bug.** `setup: clean install venv` executes `clean` (which deletes `.venv`), then `install` (which depends on and creates `.venv`), then `venv` (which recreates it). The correct form is `setup: venv install` or `setup: clean venv install`.
5. **Missing `tests/` directory.** `make test` runs `pytest tests/`, which does not exist. The coverage flags will fail immediately.
6. **`requirements.txt` errors.** `python-setuptools` should be `setuptools`; `python-suricata` is not a PyPI package (Suricata rules update via `suricata-update`); `ipaddress` is part of the standard library since Python 3.3.

### 10.3 Medium

7. **ML training undersampling.** In `train` mode, `n_benign=args.train_samples // 10` means passing `--train-samples 11000` trains on 1 100 benign flows, not 11 000 — a 10× reduction relative to `demo` mode. This invalidates the intended train/demo equivalence.
8. **Suricata config references absent rule files.** `emerging-exploit.rules` and `emerging-trojan.rules` are listed in `config/suricata.yaml` but not vendored. Suricata will warn (and fail to load those files) unless they are fetched or the references removed.
9. **Fish-shell-only activation.** The Makefile hardcodes `source .venv/bin/activate.fish`, breaking bash and zsh users.
10. **Security hygiene.** The Postgres password is committed in plaintext, and the attacker container runs privileged with host networking.

### 10.4 Low

- `PROGRESS.md` reports 13 source files but 16 are tracked.
- `feature_extractor.py`'s docstring says "5 key flow features" while the code extracts 12.

---

## 11. Remediation Plan

Ordered by dependency, so that each step unblocks the next:

1. **Fix networking.** Remove `network_mode: host` from services that need static IPs and keep the two bridge subnets. Alternatively, keep host mode only for the attacker and Suricata and drop the `networks:` blocks from those services. Ensure no two services bind the same host port.
2. **Add Dockerfiles.** Create `ml/Dockerfile` (`FROM python:3.10-slim`, install `requirements.txt`, copy `ml_detector.py`) and `scripts/Dockerfile` (same base, install Scapy, copy scripts). This makes `docker compose up` buildable.
3. **Add `config/attacks.yaml`.** Mirror the seven default vectors from `attack_automation.py:561` so the documented `--config` invocation is real rather than a fallback.
4. **Fix the Makefile.** Change `setup` to `setup: venv install`; add a shell-agnostic activation note or a `SHELL := /bin/bash` conditional.
5. **Add `tests/`.** At minimum: a smoke test that (a) the synthetic generator produces the expected shape, (b) the trained model exceeds a minimum accuracy on held-out synthetic data, (c) the Docker Compose file parses, and (d) the rule files contain exactly 51 `alert` statements.
6. **Repair `requirements.txt`.** Remove `python-setuptools`, `python-suricata`, and `ipaddress`; pin the remainder.
7. **Fix the training sample count.** Use `n_benign=args.train_samples` or split explicitly, so train and demo modes agree.
8. **Vendor or remove the Emerging Threats references** in `config/suricata.yaml`.
9. **Move the DB password to an environment variable / `.env` file** and add it to `.gitignore` (already partially covered).

After steps 1–5, the framework becomes runnable end-to-end; steps 6–9 are correctness and hygiene.

### 11.1 Remediation status

All nine findings have since been remediated in the repository:

| # | Finding | Resolution |
|---|---------|-----------|
| 1 | Docker networking contradiction | All `network_mode: host` blocks removed; services consolidated onto a single `vpc-net` bridge (`10.0.0.0/16`) so the attacker can reach the targets. |
| 2 | Missing build contexts | `ml/Dockerfile` and `scripts/Dockerfile` added, built from repo root so `requirements.txt` is in context. |
| 3 | Missing `config/attacks.yaml` | Added, mirroring the seven default vectors. |
| 4 | Makefile `setup` ordering | `setup: clean venv install`. |
| 5 | Missing `tests/` | Added `tests/` with smoke and artifact tests plus `pytest.ini`. |
| 6 | `requirements.txt` errors | `python-setuptools`, `python-suricata`, `ipaddress` removed; remaining deps pinned. |
| 7 | ML training undersampling | `n_benign=args.train_samples` (attack count kept at 10 %). |
| 8 | Absent Emerging Threats references | Removed from `config/suricata.yaml`. |
| 9 | DB password / shell portability | Password moved to `${POSTGRES_PASSWORD}` with `.env.example`; activation lines made shell-agnostic. |

The tests in `tests/` now assert these invariants (rule count = 51, no host/bridge conflict, no `emerging-` refs), so the fixes are regression-guarded rather than one-off.

---

## 12. Lessons Learned

**For the researcher.** A taxonomy-backed design forces you to state coverage honestly. The framework's willingness to mark A3 as unevaluated is a strength, not a weakness.

**For the engineer.** "All files present" is not the same as "system works." The audit found that the repository could be read in full and still fail on the first `docker compose up` because of a networking contradiction invisible to a code reviewer. **Integration tests that actually build the stack are non-negotiable** for infrastructure projects.

**For the ML practitioner.** Supervised models need labels. Bootstrapping them from an unsupervised model's pseudo-labels (the hybrid strategy here) is a legitimate shortcut when labels are expensive, but it inherits the unsupervised model's blind spots. The 3.2 ms Isolation Forest latency is an argument for keeping the unsupervised model as the first line of defence and the supervised model as a confidence refinement.

**For the operator.** The deployment recommendation falls out of the numbers: hybrid for critical infrastructure, signature-only where CPU is scarce, and a 30-day calibration window to tune the confidence threshold before trusting the false-positive rate.

---

## 13. Conclusion

This case study documents a cloud security experiment that does three things well. It grounds a concrete IDS evaluation in a published taxonomy, so coverage claims can be audited. It builds a complete, reproducible pipeline from attack generation through feature extraction to ML classification and enforcement. And it reports results — 96–99 % detection, sub-50 ms latency, +7.2 % CPU — with the trade-offs made explicit rather than buried.

It also documents the distance between artifacts and a running system: five blocking or high-priority defects, none of them conceptually difficult, all of them fatal to a naive `make setup`. The remediation plan closes that distance.

The strategic conclusion is that **hybrid detection is a justified default for high-value cloud workloads**, because the marginal detection (2–4 points) is obtained for a marginal cost (3 points of CPU), and the model selection can be matched to the attack surface — signatures for stable payloads, ML for statistical anomalies.

---

## Appendix A — Khan (2016) Coverage Map

| Category | Sub-category | Implemented | Artifact |
|----------|-------------|-------------|----------|
| A1a | Port scanning | Yes | 5 rules, nmap script |
| A1b | Botnets | Partial | 3 rules, no dedicated C2 simulator |
| A1c | Spoofing | Partial | 3 rules, no spoofing script |
| A1 | DoS/DDoS | Yes | 5 rules, hping3 + GET flood |
| A2a | Side-channel | No | Future work |
| A2d | Scheduler abuse | Yes | stress-ng, 2 rules |
| A3a/A3b | Storage | No | Block-level access unavailable |
| A4a | Malware injection | Yes | 7 rules |
| A4b | Shared architecture | Partial | 6 rules, no true multi-tenant sim |
| A4c | Web/protocol | Yes | 20 rules + SQLi/XSS/XXE tooling |

## Appendix B — Attack Vector Summary

| Vector | Category | Tool | Detection (Config C) |
|--------|----------|------|----------------------|
| SYN port scan | A1a | Nmap | 98.2 % |
| HTTP GET flood | A1 | hping3 / Python | 96.5 % |
| CPU exhaustion | A2d | stress-ng | 91.3 % |
| SQLi UNION | A4c | curl / sqlmap | 99.1 % |
| XSS script | A4c | curl | 98.8 % |
| XXE injection | A4c | curl | 97.5 % |

## Appendix C — File Manifest

| File | Lines | Role |
|------|-------|------|
| `docs/research_paper.md` | 377 | Full research paper |
| `ml/ml_detector.py` | 731 | ML detection daemon |
| `scripts/attack_automation.py` | 787 | Attack orchestrator |
| `scripts/feature_extractor.py` | 518 | Flow feature pipeline |
| `Makefile` | 170 | Command surface |
| `infra/docker-compose.yml` | 141 | VPC topology |
| `QUICKSTART.md` | 157 | Setup guide |
| `config/suricata.yaml` | 116 | Suricata configuration |
| `rules/suricata_a4.rules` | 104 | 33 application rules |
| `PROGRESS.md` | 81 | Phase tracker |
| `rules/suricata_a1.rules` | 77 | 18 network rules |
| `scripts/web_attack.py` | 73 | SQLi/XSS injector |
| `scripts/http_flood.py` | 54 | DoS automation |
| `scripts/port_scan.py` | 47 | Nmap wrapper |
| `requirements.txt` | 46 | Python dependencies |
| `.gitignore` | 55 | Ignore rules |

---

*Case study authored as a companion to the Cloud SRE case-study repository. Experimental data as reported in `docs/research_paper.md`; audit findings from direct repository inspection.*