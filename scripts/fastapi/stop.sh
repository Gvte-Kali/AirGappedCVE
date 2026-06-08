#!/bin/bash
echo "=== Arrêt de FastAPI ==="

PIDS=$(lsof -ti :8000 2>/dev/null)
if [ -n "$PIDS" ]; then
  echo "$PIDS" | xargs kill -TERM 2>/dev/null || true
  sleep 1
  PIDS=$(lsof -ti :8000 2>/dev/null)
  [ -n "$PIDS" ] && echo "$PIDS" | xargs kill -9 2>/dev/null || true
  echo "✅ FastAPI arrêté"
else
  echo "⚠️  Aucun processus sur le port 8000"
fi

pkill -9 -f "uvicorn main:app" 2>/dev/null || true
rm -f /workspace/logs/FastAPI.pid