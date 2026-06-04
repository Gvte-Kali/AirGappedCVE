#!/bin/bash
cd "$(dirname "$(dirname "$(dirname "$0")")")" || exit 1

echo "📊 Statut de FastAPI (mode dev) :"
if pgrep -f "uvicorn.*main:app" >/dev/null; then
    PID=$(pgrep -f "uvicorn.*main:app")
    PORT=$(grep -oP 'port=\K[0-9]+' "main.py" || echo "8000")
    echo "✅ FastAPI est en cours d'exécution (PID: $PID, Port: $PORT)"
    echo "   Logs : tail -f logs/FastAPI.log"
else
    echo "❌ FastAPI n'est pas en cours d'exécution."
fi