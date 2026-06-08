#!/bin/bash
cd /workspace

echo "=== Arrêt de FastAPI ==="

# Tuer tout ce qui écoute sur le port 8000 (parent + workers reload)
PIDS=$(lsof -ti :8000 2>/dev/null)
if [ -n "$PIDS" ]; then
  echo "$PIDS" | xargs kill -TERM 2>/dev/null || true
  sleep 1
  # Force si encore vivants
  PIDS=$(lsof -ti :8000 2>/dev/null)
  [ -n "$PIDS" ] && echo "$PIDS" | xargs kill -9 2>/dev/null || true
  echo "✅ FastAPI arrêté"
else
  echo "⚠️  Aucun processus sur le port 8000"
fi

# Nettoyer aussi les workers uvicorn orphelins par nom
pkill -9 -f "uvicorn main:app" 2>/dev/null || true

# Attendre que le port soit vraiment libéré
for i in {1..10}; do
  ss -tlnp | grep -q ':8000' || break
  sleep 0.5
done

set -e

# Créer le venv si absent
if [ ! -f venv/bin/uvicorn ]; then
  echo "=== Venv absent, lancement du setup... ==="
  bash .devcontainer/setup.sh
fi

echo "=== Démarrage de FastAPI ==="
mkdir -p logs

nohup venv/bin/uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  >> logs/FastAPI.log 2>&1 &

echo $! > logs/FastAPI.pid
echo "✅ FastAPI démarré (PID $!)"
echo "   Logs : tail -f logs/FastAPI.log"