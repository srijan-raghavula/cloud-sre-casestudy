.PHONY: help venv install run-attack run-suricata run-ml run-feature run-all clean test

# ──────────────────────────────────────────────────────────
# Default target — shows available commands
# ──────────────────────────────────────────────────────────
help: ## Show this help message with all available commands
	@echo "============================================"
	@echo "  Cloud Security Case Study — Make Commands"
	@echo "  (Based on Khan, 2016 Taxonomy)"
	@echo "============================================"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ──────────────────────────────────────────────────────────
# Virtual Environment Setup
# ──────────────────────────────────────────────────────────
venv: ## Create Python virtual environment (.venv)
	@echo "[SETUP] Creating virtual environment..."
	python3 -m venv .venv
	@echo "[SETUP] Virtual environment created at .venv/"
	@echo "[SETUP] Activate with: . .venv/bin/activate (bash/zsh) or . .venv/bin/activate.fish (fish)"

# ──────────────────────────────────────────────────────────
# Install Dependencies
# ──────────────────────────────────────────────────────────
install: venv ## Install all Python dependencies into the virtual environment
	@echo "[INSTALL] Installing requirements..."
	.venv/bin/pip install -r requirements.txt
	@echo "[INSTALL] Dependencies installed successfully."

# ──────────────────────────────────────────────────────────
# Feature Extraction Pipeline
# ──────────────────────────────────────────────────────────
run-feature: install ## Extract network flow features using PyShark/Scapy
	@echo "[FEATURE] Starting real-time feature extraction..."
	.venv/bin/python scripts/feature_extractor.py --interface eth0 --backend scapy --duration 300 --output data/flow_features.csv
	@echo "[FEATURE] Feature extraction complete. Output: data/flow_features.csv"

# ──────────────────────────────────────────────────────────
# Port Scanning Attack (A1a)
# ──────────────────────────────────────────────────────────
run-port-scan: install ## Execute Nmap SYN port scan against target 10.0.2.10
	@echo "[ATTACK] Running port scan (A1a) against Web Server..."
	.venv/bin/python scripts/port_scan.py --target 10.0.2.10 --ports 1-1000 --duration 60 --output-dir data/results
	@echo "[ATTACK] Port scan complete. Results in data/results/"

# ──────────────────────────────────────────────────────────
# HTTP DoS Attack (A1)
# ──────────────────────────────────────────────────────────
run-http-flood: install ## Execute SYN flood or HTTP GET flood against target 10.0.2.10
	@echo "[ATTACK] Running HTTP DoS attack (A1)..."
	.venv/bin/python scripts/http_flood.py --target 10.0.2.10 --type syn_flood --duration 60 --rate 1000 --output-dir data/results
	@echo "[ATTACK] HTTP flood complete. Results in data/results/"

# ──────────────────────────────────────────────────────────
# Web Application Attack (A4c — SQLi/XSS)
# ──────────────────────────────────────────────────────────
run-web-attack: install ## Execute SQLi and XSS attacks against target 10.0.2.10
	@echo "[ATTACK] Running web application attacks (A4c)..."
	.venv/bin/python scripts/web_attack.py --target 10.0.2.10 --type all --endpoint / --duration 60 --output-dir data/results
	@echo "[ATTACK] Web attacks complete. Results in data/results/"

# ──────────────────────────────────────────────────────────
# Suricata IPS Detection (Config B)
# ──────────────────────────────────────────────────────────
run-suricata: install ## Start Suricata IDS/IPS with A1+A4 rule sets
	@echo "[SURICATA] Starting Suricata IPS with custom rules..."
	cat rules/suricata_a1.rules rules/suricata_a4.rules > data/suricata/combined.rules
	suricata -c config/suricata.yaml \
		-S data/suricata/combined.rules \
		-l data/suricata \
		--set app-layer.protocols.http.enabled=true
	@echo "[SURICATA] Suricata IDS/IPS running. Logs in data/suricata/"

# ──────────────────────────────────────────────────────────
# Synthetic PCAP + Suricata Offline (no root needed)
# ──────────────────────────────────────────────────────────
gen-pcap: install ## Generate synthetic attack PCAP (A1, A4c + benign)
	@echo "[PCAP] Generating synthetic attack traffic..."
	.venv/bin/python scripts/generate_pcap.py --output data/capture.pcap --flows 20
	@echo "[PCAP] PCAP ready: data/capture.pcap"

run-suricata-offline: gen-pcap ## Run Suricata offline via Docker on synthetic PCAP
	@echo "[SURICATA] Running offline detection on data/capture.pcap..."
	mkdir -p data/suricata
	cat rules/suricata_a1.rules rules/suricata_a4.rules > data/suricata/combined.rules
	rm -f data/suricata/eve.json
	docker run --rm \
		-v "$(CURDIR)/data:/data:rw" \
		-v "$(CURDIR)/data/suricata/combined.rules:/rules/combined.rules:ro" \
		-v "$(CURDIR)/config/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
		jasonish/suricata:latest suricata -c /etc/suricata/suricata.yaml \
		-S /rules/combined.rules -r /data/capture.pcap -l /data/suricata \
		--set stream.checksum-validation=no
	@echo "[SURICATA] Offline detection complete. Logs in data/suricata/"

# ──────────────────────────────────────────────────────────
# ML Anomaly Detection (Config C)
# ──────────────────────────────────────────────────────────
run-ml: install ## Train and run ML anomaly detector (Isolation Forest / Random Forest)
	@echo "[ML] Training and running ML anomaly detector..."
	.venv/bin/python ml/ml_detector.py --mode demo --model-type isolation_forest --threshold 0.7
	@echo "[ML] ML detection complete. Check data/results/ml_detection_report.json"

# ──────────────────────────────────────────────────────────
# Train ML Models
# ──────────────────────────────────────────────────────────
train-ml: install ## Train ML models on synthetic dataset and save to disk
	@echo "[ML] Training models on synthetic dataset..."
	.venv/bin/python ml/ml_detector.py --mode train --model-type hybrid --train-samples 11000 --model-path ml/models/idps_model.joblib
	@echo "[ML] Model training complete. Saved to ml/models/idps_model.joblib"

# ──────────────────────────────────────────────────────────
# Full Attack Automation Orchestrator
# ──────────────────────────────────────────────────────────
run-all-attacks: install ## Execute all 7 attack vectors sequentially via orchestrator
	@echo "[ORCHESTRATOR] Running all attack vectors (A1, A2d, A4c)..."
	.venv/bin/python scripts/attack_automation.py --all --duration 60 --config config/attacks.yaml
	@echo "[ORCHESTRATOR] All attacks complete. Results in data/results/"

# ──────────────────────────────────────────────────────────
# Run ML Detection Daemon (Real-time)
# ──────────────────────────────────────────────────────────
run-ml-daemon: install ## Start the ML detector daemon listening to Suricata eve.json
	@echo "[ML DAEMON] Starting real-time anomaly detection..."
	.venv/bin/python ml/ml_detector.py --mode detect --model-path ml/models/idps_model.joblib --eve-json data/suricata/eve.json --threshold 0.7
	@echo "[ML DAEMON] Daemon stopped."

# ──────────────────────────────────────────────────────────
# Docker Infrastructure
# ──────────────────────────────────────────────────────────
docker-up: ## Start the full VPC topology using Docker Compose
	@echo "[DOCKER] Bringing up VPC infrastructure..."
	docker compose --project-name cloud-sre -f infra/docker-compose.yml --env-file .env up -d --build
	@echo "[DOCKER] VPC infrastructure running. Access DVWA at http://localhost"

docker-down: ## Stop and remove all Docker containers
	@echo "[DOCKER] Shutting down VPC infrastructure..."
	docker compose --project-name cloud-sre -f infra/docker-compose.yml --env-file .env down
	@echo "[DOCKER] All containers stopped."

docker-logs: ## Show logs from all running containers
	@echo "[DOCKER] Streaming container logs..."
	docker compose --project-name cloud-sre -f infra/docker-compose.yml --env-file .env logs -f

# ──────────────────────────────────────────────────────────
# Full Live Demo — VPC + Attacks + Suricata + ML
# ──────────────────────────────────────────────────────────
run-everything: install ## Full live demo: VPC up → live attacks → Suricata → ML → down
	@echo "[EVERYTHING] Starting full live demo (VPC + attacks + detection)..."
	@echo "[EVERYTHING] Tip: KEEP_UP=1 make run-everything (leave VPC up)"
	chmod +x scripts/run_everything.sh scripts/wait_for_infra.sh
	KEEP_UP=$(KEEP_UP) CAPTURE_SECS=$(CAPTURE_SECS) ATTACK_SECS=$(ATTACK_SECS) bash scripts/run_everything.sh

# ──────────────────────────────────────────────────────────
# Test Suite
# ──────────────────────────────────────────────────────────
test: install ## Run the test suite to verify all modules
	@echo "[TEST] Running pytest test suite..."
	.venv/bin/python -m pytest tests/ -v --cov=scripts --cov=ml --cov-report=term-missing
	@echo "[TEST] Test suite complete."

# ──────────────────────────────────────────────────────────
# Data Pipeline — End-to-End
# ──────────────────────────────────────────────────────────
run-pipeline: install ## Run full pipeline: attack → pcap → features → Suricata → ML
	@echo "[PIPELINE] Starting end-to-end detection pipeline..."
	@echo "[PIPELINE] Step 1/6: Running attacks..."
	.venv/bin/python scripts/attack_automation.py --all --duration 5 --output data/results
	@echo "[PIPELINE] Step 2/6: Generating synthetic PCAP..."
	.venv/bin/python scripts/generate_pcap.py --output data/capture.pcap --flows 20
	@echo "[PIPELINE] Step 3/6: Extracting features from PCAP..."
	.venv/bin/python scripts/feature_extractor.py --pcap data/capture.pcap --output data/flow_features.csv
	@echo "[PIPELINE] Step 4/6: Running Suricata offline (Docker)..."
	mkdir -p data/suricata
	cat rules/suricata_a1.rules rules/suricata_a4.rules > data/suricata/combined.rules
	rm -f data/suricata/eve.json
	docker run --rm \
		-v "$(CURDIR)/data:/data:rw" \
		-v "$(CURDIR)/data/suricata/combined.rules:/rules/combined.rules:ro" \
		-v "$(CURDIR)/config/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
		jasonish/suricata:latest suricata -c /etc/suricata/suricata.yaml \
		-S /rules/combined.rules -r /data/capture.pcap -l /data/suricata \
		--set stream.checksum-validation=no
	@echo "[PIPELINE] Step 5/6: Training ML models..."
	.venv/bin/python ml/ml_detector.py --mode train --model-type hybrid --train-samples 11000 --model-path ml/models/idps_model.joblib
	@echo "[PIPELINE] Step 6/6: Running batch ML detection on eve.json..."
	.venv/bin/python ml/ml_detector.py --mode detect --model-path ml/models/idps_model.joblib --eve-json data/suricata/eve.json --threshold 0.7 --once --output data/results/ml_detection_report.json
	@echo "[PIPELINE] End-to-end pipeline complete!"

# ──────────────────────────────────────────────────────────
# Clean Up
# ──────────────────────────────────────────────────────────
clean: ## Remove all generated data, results, and cached files
	@echo "[CLEAN] Removing generated files..."
	rm -rf data/results/ data/suricata/ data/flow_features.csv data/live_flows.csv
	rm -rf data/capture.pcap data/capture-live.pcap data/nmap_*.xml
	rm -rf ml/models/ .ruff_cache/ __pycache__/ .venv/
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "[CLEAN] Workspace cleaned."

# ──────────────────────────────────────────────────────────
# Quick Setup (One Command)
# ──────────────────────────────────────────────────────────
setup: clean venv install ## Full fresh setup: clean workspace, create venv, install deps
	@echo "[SETUP] Complete! Ready to run experiments."
	@echo "  Activate: . .venv/bin/activate (bash/zsh) or . .venv/bin/activate.fish (fish)"
	@echo "  Start infra: make docker-up"
	@echo "  Run attacks: make run-all-attacks"
