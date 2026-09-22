#!/usr/bin/env bash
# Full live demo: VPC up → live in-VPC attacks + capture → Suricata → ML → down.
#
# Usage:
#   scripts/run_everything.sh
#   KEEP_UP=1 scripts/run_everything.sh        # leave the VPC running for inspection
#   CAPTURE_SECS=120 ATTACK_SECS=30 scripts/run_everything.sh
#
# Requires: docker, .venv with project deps (run `make install` first).
set -u

KEEP_UP="${KEEP_UP:-0}"
CAPTURE_SECS="${CAPTURE_SECS:-240}"
ATTACK_SECS="${ATTACK_SECS:-30}"
COMPOSE="docker compose --project-name cloud-sre -f infra/docker-compose.yml --env-file .env"
PY=".venv/bin/python"

if [ ! -x "$PY" ]; then
  echo "[EVERYTHING] Missing $PY — run 'make install' first." >&2
  exit 1
fi
if [ ! -f .env ]; then
  echo "[EVERYTHING] Missing .env — copying from .env.example."
  cp .env.example .env
fi

teardown() {
  if [ "$KEEP_UP" = "1" ]; then
    echo "[EVERYTHING] KEEP_UP=1 — VPC left running. Tear down with 'make docker-down'."
  else
    echo "[EVERYTHING] Tearing down VPC..."
    $COMPOSE down >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

echo "[EVERYTHING] Step 1/7: Bringing up VPC..."
$COMPOSE up -d --build || exit 1

echo "[EVERYTHING] Step 2/7: Waiting for services..."
bash scripts/wait_for_infra.sh 300 || exit 1

echo "[EVERYTHING] Step 3/7: Initializing DVWA database (best effort)..."
$COMPOSE exec -T feature-extractor python3 -c \
  "import urllib.request; urllib.request.urlopen('http://10.0.2.10/setup.php', timeout=10)" \
  >/dev/null 2>&1 && echo "[EVERYTHING] DVWA setup page reachable." \
  || echo "[EVERYTHING] DVWA setup skipped (non-fatal)."

echo "[EVERYTHING] Step 4/7: Starting live capture (${CAPTURE_SECS}s) + live attacks..."
rm -f data/capture-live.pcap data/live_flows.csv
$COMPOSE exec -d feature-extractor python3 /app/feature_extractor.py \
  --interface eth0 --backend scapy --duration "$CAPTURE_SECS" \
  --output /data/live_flows.csv --pcap-out /data/capture-live.pcap
sleep 5
$COMPOSE exec -T feature-extractor python3 /app/attack_automation.py \
  --all --duration "$ATTACK_SECS" --config /config/attacks.yaml --output /data/results

echo "[EVERYTHING] Step 5/7: Waiting for capture to finish..."
deadline=$((SECONDS + CAPTURE_SECS + 60))
while [ ! -f data/capture-live.pcap ] && [ $SECONDS -lt $deadline ]; do sleep 10; done
sleep 5

PCAP=data/capture-live.pcap
if [ ! -s "$PCAP" ]; then
  echo "[EVERYTHING] Live capture empty — falling back to synthetic PCAP."
  $PY scripts/generate_pcap.py --output data/capture.pcap --flows 20
  PCAP=data/capture.pcap
fi
echo "[EVERYTHING] Using PCAP: $PCAP"

echo "[EVERYTHING] Step 6/7: Suricata (Docker) + ML detection..."
mkdir -p data/suricata
cat rules/suricata_a1.rules rules/suricata_a4.rules > data/suricata/combined.rules
rm -f data/suricata/eve.json
docker run --rm \
  -v "$(pwd)/data:/data:rw" \
  -v "$(pwd)/data/suricata/combined.rules:/rules/combined.rules:ro" \
  -v "$(pwd)/config/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
  jasonish/suricata:latest suricata -c /etc/suricata/suricata.yaml \
  -S /rules/combined.rules -r "/data/$(basename "$PCAP")" -l /data/suricata \
  --set stream.checksum-validation=no || exit 1
$PY ml/ml_detector.py --mode train --model-type hybrid \
  --train-samples 11000 --model-path ml/models/idps_model.joblib || exit 1
$PY ml/ml_detector.py --mode detect --model-path ml/models/idps_model.joblib \
  --eve-json data/suricata/eve.json --threshold 0.7 --once \
  --output data/results/ml_detection_report.json || exit 1

echo "[EVERYTHING] Step 7/7: Summary..."
$PY -c "
import json, csv, glob, os
from collections import Counter

def category(sid):
    if 1000001 <= sid <= 1000005: return 'A1a port-scan'
    if 1000010 <= sid <= 1000012: return 'A1b botnet/C2'
    if 1000020 <= sid <= 1000022: return 'A1c spoofing'
    if 1000030 <= sid <= 1000034: return 'A1 DoS'
    if 1000040 <= sid <= 1000041: return 'A2 VM abuse'
    if 1000100 <= sid <= 1000106: return 'A4a malware-injection'
    if 1000110 <= sid <= 1000115: return 'A4b side-channel'
    if 1000200 <= sid <= 1000234: return 'A4c web/protocol'
    return 'other'

alerts = Counter(); nevents = 0; nflows = 0
with open('data/suricata/eve.json') as f:
    for line in f:
        try: e = json.loads(line)
        except Exception: continue
        nevents += 1
        if e.get('event_type') == 'alert':
            alerts[e['alert']['signature_id']] += 1
        elif e.get('event_type') == 'flow':
            nflows += 1
print(f'  Suricata: {sum(alerts.values())} alerts / {nevents} events / {nflows} flows')
bycat = Counter()
for sid, n in alerts.items():
    bycat[category(sid)] += n
for cat, n in sorted(bycat.items(), key=lambda x: -x[1]):
    print(f'    {cat}: {n}')
print('  All firing SIDs:')
for sid, n in sorted(alerts.items(), key=lambda x: -x[1]):
    print(f'    sid {sid}: {n}')
rep = json.load(open('data/results/ml_detection_report.json'))
st = rep['statistics']
print(f\"  ML batch: {st['confirmed_attacks']} attacks, \"
      f\"{st['suspicious_alerts']} suspicious, {st['benign_classified']} benign, \"
      f\"{st.get('suricata_correlated', 0)} corroborated by both engines\")
print(f\"  Hybrid coverage: {rep.get('suricata_flagged_flows', 0)} flows flagged by Suricata, \"
      f\"{rep.get('ml_flagged_flows', 0)} by ML\")
flows = list(csv.DictReader(open('data/live_flows.csv'))) if os.path.exists('data/live_flows.csv') else []
print(f'  Live flows captured: {len(flows)}')
print(f\"  Attack CSVs: {sorted(glob.glob('data/results/attack_results_*.csv'))[-1:]}\")
"
echo "[EVERYTHING] Complete!"
