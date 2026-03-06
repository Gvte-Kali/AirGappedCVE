#!/usr/bin/env bash
set -euo pipefail

# Point d'entrée de démarrage (wrapper).
# Le script réel est conservé dans logs/start.sh.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/logs/start.sh"

