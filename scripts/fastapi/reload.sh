#!/bin/bash
cd /workspace

echo "=== Arrêt de FastAPI ==="
if pkill -f "uvicorn main:app" 2>/dev/null; then
  echo "✅ FastAPI arrêté"
else
  echo "⚠️  Aucun processus FastAPI trouvé"
fi

set -e

cd /workspace

# Créer le venv si absent (au cas où setup.sh n'a pas tourné)
if [ ! -f venv/bin/uvicorn ]; then
  echo "=== Venv absent, lancement du setup... ==="
  bash .devcontainer/setup.sh
fi

echo "=== Démarrage de FastAPI ==="
pkill -f "uvicorn main:app" 2>/dev/null || true
sleep 1

mkdir -p logs
nohup venv/bin/uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  >> logs/FastAPI.log 2>&1 &

echo "✅ FastAPI démarré sur le port 8000"
echo "   Logs : tail -f logs/FastAPI.log"