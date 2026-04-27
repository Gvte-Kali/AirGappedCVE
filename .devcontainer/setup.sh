#!/bin/bash
# Exécuté UNE SEULE FOIS à la création du Codespace
set -e

echo "=== Installation des dépendances Python ==="
cd /workspace
python3 -m venv venv
venv/bin/pip install --upgrade pip -q
venv/bin/pip install -r requirements.txt -q

echo "=== Création du .env de développement ==="
cat > /workspace/.env << ENVEOF
# DEV - Codespaces
SERVER_IP=localhost

# API Keys (injectées depuis les Codespaces Secrets)
NVD_API_KEY=${NVD_API_KEY:-your_nvd_api_key_here}
MISTRAL_API_KEY=${MISTRAL_API_KEY:-your_mistral_api_key_here}
MISTRAL_MODEL=mistral-large-latest

# Database
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=avea
DB_PASSWORD=devpassword
DB_NAME=asset_vuln_manager
ENVEOF

echo "=== Attente de MariaDB ==="
until mariadb -h 127.0.0.1 -u avea -pdevpassword asset_vuln_manager -e "SELECT 1" &>/dev/null; do
  echo "MariaDB pas encore prêt, attente..."
  sleep 2
done

echo ""
echo "✅ Setup terminé !"
echo "   FastAPI : http://localhost:8000"
echo "   Docs    : http://localhost:8000/docs"
echo "   MariaDB : localhost:3306"
