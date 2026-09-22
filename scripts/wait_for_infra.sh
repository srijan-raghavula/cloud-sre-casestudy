#!/usr/bin/env bash
# Wait for VPC services to become healthy. Exit 0 when ready, 1 on timeout.
# Probes run from INSIDE the VPC (host published ports may be filtered).
# Usage: scripts/wait_for_infra.sh [timeout_seconds]
set -u
TIMEOUT="${1:-300}"
COMPOSE="docker compose --project-name cloud-sre -f infra/docker-compose.yml --env-file .env"

echo "[WAIT] Waiting for VPC services (timeout ${TIMEOUT}s)..."
deadline=$((SECONDS + TIMEOUT))

web_ok=0; db_ok=0; suri_ok=0
while [ $SECONDS -lt $deadline ]; do
  if [ $web_ok -eq 0 ] && $COMPOSE exec -T feature-extractor python3 -c \
    "import urllib.request; urllib.request.urlopen('http://10.0.2.10/', timeout=5)" \
    >/dev/null 2>&1; then
    echo "[WAIT] web-server (DVWA) is up."
    web_ok=1
  fi
  if [ $db_ok -eq 0 ] && $COMPOSE exec -T db-server pg_isready -U admin -d cloudapp \
    >/dev/null 2>&1; then
    echo "[WAIT] db-server (Postgres) is up."
    db_ok=1
  fi
  if [ $suri_ok -eq 0 ] && [ "$($COMPOSE ps --status running --format '{{.Name}}' 2>/dev/null | grep -c '^suricata-ips$' || true)" -ge 1 ]; then
    echo "[WAIT] security-gateway (Suricata) is running."
    suri_ok=1
  fi
  if [ $web_ok -eq 1 ] && [ $db_ok -eq 1 ] && [ $suri_ok -eq 1 ]; then
    echo "[WAIT] All core services healthy."
    exit 0
  fi
  sleep 5
done

echo "[WAIT] TIMEOUT after ${TIMEOUT}s (web=$web_ok db=$db_ok suricata=$suri_ok)."
$COMPOSE ps 2>/dev/null || true
exit 1
