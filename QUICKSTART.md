# Cloud Security Case Study — Quick Start Guide

> Based on: **"A Survey of Security Issues for Cloud Computing" (Khan, 2016)**

## Prerequisites

- Docker & Docker Compose (for infrastructure)
- `nmap`, `hping3`, `stress-ng` (for attack generation)
- Python 3.10+ (bash, zsh, or fish)

## Setup (One Command)

```bash
# Create venv, install deps, and prepare everything
make setup
```

Or manually:

```bash
# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate it
. .venv/bin/activate          # bash / zsh
. .venv/bin/activate.fish     # fish

# 3. Install dependencies
pip install -r requirements.txt
```

## Available Make Commands

Run `make help` to see all commands, or use these shortcuts:

| Command | What It Does |
|---------|-------------|
| `make install` | Install all Python dependencies |
| `make venv` | Create the virtual environment |
| `make run-port-scan` | Launch Nmap port scan (A1a) |
| `make run-http-flood` | Launch hping3 DoS attack (A1) |
| `make run-web-attack` | Launch SQLi/XSS attacks (A4c) |
| `make run-all-attacks` | Run all 7 attack vectors |
| `make run-suricata` | Start Suricata IPS with custom rules |
| `make run-ml` | Train & demo the ML anomaly detector |
| `make run-pipeline` | End-to-end: attacks → features → ML |
| `make docker-up` | Start the full VPC topology |
| `make docker-down` | Stop all containers |
| `make test` | Run the test suite |
| `make clean` | Remove all generated data |

## Quick Demo (No Docker Needed)

```bash
# 1. Setup environment
make setup

# 2. Run a single attack
make run-port-scan

# 3. Run the ML detector demo (uses synthetic data)
make run-ml

# 4. Or run the full pipeline
make run-pipeline
```

## With Docker Infrastructure

```bash
# 0. Provide the DB password (copy .env.example to .env)
cp .env.example .env

# 1. Start the simulated VPC (Web, DB, Suricata, ML, Attacker)
make docker-up

# 2. In another terminal, run attacks
make run-all-attacks

# 3. Check Suricata logs
make docker-logs

# 4. Shut everything down
make docker-down
```

## Running Individual Attack Scripts

```bash
# Port scan against web server
python3 scripts/port_scan.py --target 10.0.2.10 --ports 1-1000

# HTTP SYN flood
python3 scripts/http_flood.py --target 10.0.2.10 --type syn_flood --duration 60 --rate 1000

# SQLi and XSS attacks
python3 scripts/web_attack.py --target 10.0.2.10 --type all

# Full orchestrator (all attacks, 60s each)
python3 scripts/attack_automation.py --all --duration 60
```

## ML Detector

```bash
# Train model on synthetic data
python3 ml/ml_detector.py --mode train --model-type hybrid --train-samples 11000

# Demo with benchmark
python3 ml/ml_detector.py --mode demo --model-type isolation_forest

# Real-time detection from Suricata logs
python3 ml/ml_detector.py --mode detect --eve-json data/suricata/eve.json

# Feature extraction from live capture
python3 scripts/feature_extractor.py --interface eth0 --backend scapy --duration 300
```

## Expected Results

| Configuration | Detection Rate | Latency | CPU Overhead |
|--------------|----------------|---------|--------------|
| Baseline (A) | 0% | N/A | 0% |
| Suricata (B) | 88-96% | 8-45ms | +4.1% |
| Hybrid ML (C) | 96-99% | 3-22ms | +7.2% |

## Project Structure

```
.
├── Makefile                  # All commands with documentation
├── .gitignore               # Git ignore rules
├── .env.example             # Template for required secrets (DB password)
├── pytest.ini               # Test runner configuration
├── requirements.txt         # Python dependencies
├── PROGRESS.md              # Progress tracker
├── config/
│   ├── suricata.yaml        # Suricata IPS configuration
│   └── attacks.yaml         # Attack vector definitions (7 vectors)
├── docs/
│   ├── research_paper.md    # Full research paper (377 lines)
│   └── case_study.md        # Teaching case study
├── infra/
│   └── docker-compose.yml   # VPC topology (6 services, bridge networks)
├── ml/
│   ├── Dockerfile           # ML engine image build
│   └── ml_detector.py       # Isolation Forest / Random Forest daemon
├── rules/
│   ├── suricata_a1.rules    # 18 Network attack rules (A1a, A1b, A1c)
│   └── suricata_a4.rules    # 33 Application attack rules (A4a, A4b, A4c)
├── scripts/
│   ├── Dockerfile           # Feature extractor image build
│   ├── attack_automation.py # Centralized orchestrator
│   ├── feature_extractor.py # Flow feature pipeline
│   ├── port_scan.py         # Nmap automation (A1a)
│   ├── http_flood.py        # hping3 DoS (A1)
│   └── web_attack.py        # SQLi/XSS/XXE (A4c)
├── tests/                   # Pytest smoke + artifact tests
└── data/                    # Generated results, logs, models
```

## Troubleshooting

- **`make: command not found`**: Install `make` (`sudo apt install make`)
- **`suricata: command not found`**: Install Suricata (`sudo apt install suricata`)
- **`nmap: command not found`**: Install Nmap (`sudo apt install nmap`)
- **Module not found**: Run `make install` or `pip install -r requirements.txt`
- **Docker issues**: Run `make docker-down` then `make docker-up` to reset
