#!/bin/bash
echo "=== Arrêt de FastAPI ==="
if pkill -f "uvicorn main:app" 2>/dev/null; then
  echo "✅ FastAPI arrêté"
else
  echo "⚠️  Aucun processus FastAPI trouvé"
fi