#!/bin/bash

PROJECT_DIR="/opt/asset-manager"
VENV_PATH="$PROJECT_DIR/venv"

# Activer le venv
if [ -d "$VENV_PATH" ]; then
    source "$VENV_PATH/bin/activate"
fi

cd "$PROJECT_DIR"

# exec remplace bash par uvicorn — systemd suit le bon PID
exec uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level info