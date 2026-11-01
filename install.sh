#!/usr/bin/env bash
set -e

echo "====================================================================="
echo "   G1 Docket - Automated Docker Stack Installer"
echo "====================================================================="
echo ""

# 1. Check Docker CLI
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH!"
    echo "Please install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

# 2. Check Docker Daemon Status
if ! docker info &> /dev/null; then
    echo "[ERROR] Docker daemon is not running!"
    echo "Please ensure the Docker service is started."
    exit 1
fi
echo "[OK] Docker engine is running."

# 3. Prepare Environment
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        echo "[*] Creating .env from .env.example..."
        cp .env.example .env
    fi
fi

# 4. Build and Start Demo Stack
echo "[*] Building and starting all G1 Docket services (demo profile)..."
echo "    - PostgreSQL 15 (Port 15432)"
echo "    - Registry API & Store (Port 18080)"
echo "    - Signed Snapshot Publisher (Port 18081)"
echo "    - AI Gateway Prevalidator (Port 18082)"
echo "    - Attestation Engine & Discovery (Port 18083)"
echo "    - Local AI Gateway Mock (Port 14000)"
echo ""

docker compose --profile demo up -d --build

# 5. Wait for Services
echo ""
echo "[*] Waiting for services to initialize and pass health checks..."
URLS=(
    "http://localhost:18080/docs"
    "http://localhost:18081/docs"
    "http://localhost:18082/healthz"
    "http://localhost:18083/healthz"
    "http://localhost:14000/healthz"
)

all_ok=false
for i in {1..40}; do
    pending=0
    for u in "${URLS[@]}"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$u" || echo "000")
        if [ "$status" != "200" ]; then
            pending=$((pending + 1))
        fi
    done
    if [ "$pending" -eq 0 ]; then
        all_ok=true
        break
    fi
    echo -n "."
    sleep 2
done

echo ""
if [ "$all_ok" = true ]; then
    echo -e "\033[0;32m[+] All G1 Docket services are HEALTHY and ACTIVE!\033[0m"
else
    echo -e "\033[0;33m[!] Services started; some endpoints are still stabilizing.\033[0m"
fi

echo ""
echo "====================================================================="
echo "   G1 Docket Platform is live!"
echo "====================================================================="
echo " - Prevalidator Proxy:    http://localhost:18082"
echo " - Registry API Docs:     http://localhost:18080/docs"
echo " - Snapshot Publisher:    http://localhost:18081/docs"
echo " - Attestation Engine:    http://localhost:18083/docs"
echo " - Local Mock Gateway:    http://localhost:14000"
echo " - PostgreSQL DB:        localhost:15432 (user: pod, db: pod_registry)"
echo "====================================================================="
