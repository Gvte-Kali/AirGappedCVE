#!/bin/bash
# Exécuté à CHAQUE démarrage du Codespace
set -e

echo "=== Démarrage de FastAPI ==="
cd /workspace

# Tuer une éventuelle instance déjà lancée
pkill -f "uvicorn main:app" 2>/dev/null || true
sleep 1

# Lancer FastAPI en arrière-plan
nohup venv/bin/uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  >> logs/FastAPI.log 2>&1 &

echo "✅ FastAPI démarré (logs : logs/FastAPI.log)"
