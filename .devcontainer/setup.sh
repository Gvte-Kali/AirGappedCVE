#!/bin/bash
# Exécuté UNE SEULE FOIS à la création du Codespace
set -e

echo "=== Installation des dépendances Python ==="
cd /workspace
sudo apt-get update -q
sudo apt-get install -y default-mysql-client wget -q
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

echo "=== Installation de Grafana ==="
sudo wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update -q && sudo apt-get install -y grafana -q
mkdir -p /workspace/logs
sudo grafana-server --config=/etc/grafana/grafana.ini --homepath=/usr/share/grafana >> /workspace/logs/grafana.log 2>&1 &
echo "✅ Grafana démarré (logs : logs/grafana.log)"

echo "=== Attente de MariaDB ==="
until mariadb -h 127.0.0.1 -u avea -pdevpassword asset_vuln_manager --skip-ssl -e "SELECT 1" &>/dev/null; do
  echo "MariaDB pas encore prêt, attente..."
  sleep 2
done

echo ""
echo "✅ Setup terminé !"
echo "   FastAPI : http://localhost:8000"
echo "   Docs    : http://localhost:8000/docs"
echo "   Grafana : http://localhost:3000"
echo "   MariaDB : localhost:3306"