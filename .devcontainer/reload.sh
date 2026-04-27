#!/bin/bash
cd /workspace

echo "=== Redémarrage de FastAPI ==="

# Arrêt propre
if pkill -f "uvicorn main:app" 2>/dev/null; then
  echo "  → Ancien processus arrêté"
fi
sleep 1

# Démarrage
mkdir -p logs
nohup venv/bin/uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  >> logs/FastAPI.log 2>&1 &

echo "✅ FastAPI redémarré (PID: $!)"
echo "   Logs : tail -f logs/FastAPI.log"