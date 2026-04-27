#!/bin/bash
# =============================================================================
# install.sh — Installation complète Asset & Vulnerability Manager
# Usage : curl -sSL https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/main/install.sh | sudo bash
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()    { echo -e "${GREEN}[OK]${NC}  $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()  { echo -e "${RED}[ERR]${NC}  $1"; exit 1; }
header() { echo -e "\n${BLUE}==== $1 ====${NC}"; }
ask()    { echo -e "${YELLOW}  → $1${NC}"; }

if [ "$EUID" -ne 0 ]; then
  error "Lance ce script avec sudo : sudo bash install.sh"
fi

echo ""
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}   Asset & Vulnerability Manager — Installer    ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# =============================================================================
header "1/6 — Mise à jour système et dépendances"
# =============================================================================
apt update && apt upgrade -y
apt install -y curl wget git nano unzip python3 python3-pip python3-venv mariadb-server
log "Paquets système installés"

# =============================================================================
header "2/6 — Clone du repo"
# =============================================================================
if [ -d /opt/asset-manager/.git ]; then
  warn "Dossier déjà existant, mise à jour depuis GitHub"
  cd /opt/asset-manager && git pull
else
  git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
  log "Repo cloné dans /opt/asset-manager"
fi

groupadd -f asset-manager
SUDO_USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || echo 'pwner')}"
usermod -aG asset-manager "$SUDO_USER_NAME" 2>/dev/null || true
chown -R :asset-manager /opt/asset-manager
chmod -R 775 /opt/asset-manager
log "Groupe et permissions configurés"

# =============================================================================
header "3/6 — Configuration du .env"
# =============================================================================
echo ""
echo "  Remplis les informations suivantes pour configurer le système."
echo "  Appuie sur Entrée pour garder la valeur par défaut indiquée entre []."
echo ""

ask "Adresse IP du serveur [10.100.0.20] :"
read -rp "  > " SERVER_IP; SERVER_IP="${SERVER_IP:-10.100.0.20}"

ask "Clé API NVD (https://nvd.nist.gov/developers/request-an-api-key) :"
read -rp "  > " NVD_API_KEY

ask "Clé API Mistral (https://console.mistral.ai/api-keys) :"
read -rp "  > " MISTRAL_API_KEY

ask "Modèle Mistral [mistral-large-latest] :"
read -rp "  > " MISTRAL_MODEL; MISTRAL_MODEL="${MISTRAL_MODEL:-mistral-large-latest}"

ask "Nom d'utilisateur MariaDB de gestion [avea] :"
read -rp "  > " DB_USER; DB_USER="${DB_USER:-avea}"

ask "Mot de passe pour l'utilisateur '${DB_USER}' :"
read -rsp "  > " DB_PASSWORD; echo ""

ask "Nom de la base de données [asset_vuln_manager] :"
read -rp "  > " DB_NAME; DB_NAME="${DB_NAME:-asset_vuln_manager}"

# Écrire le .env
cat > /opt/asset-manager/.env << EOF
# SERVER INFOS
SERVER_IP=${SERVER_IP}

# API Keys
NVD_API_KEY=${NVD_API_KEY}
MISTRAL_API_KEY=${MISTRAL_API_KEY}
MISTRAL_MODEL=${MISTRAL_MODEL}

# Database Infos
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DB_NAME=${DB_NAME}
EOF

# Écrire config/secrets.json
mkdir -p /opt/asset-manager/config
cat > /opt/asset-manager/config/secrets.json << EOF
{
  "mariadb": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "${DB_USER}",
    "password": "${DB_PASSWORD}",
    "database": "${DB_NAME}"
  },
  "mistral": {
    "api_key": "${MISTRAL_API_KEY}"
  },
  "nvd": {
    "api_key": "${NVD_API_KEY}"
  }
}
EOF

chown :asset-manager /opt/asset-manager/.env /opt/asset-manager/config/secrets.json
chmod 660 /opt/asset-manager/.env /opt/asset-manager/config/secrets.json
log ".env et secrets.json configurés"

# =============================================================================
header "4/6 — Virtualenv Python et dépendances"
# =============================================================================
python3 -m venv /opt/asset-manager/venv
/opt/asset-manager/venv/bin/pip install --upgrade pip -q

if [ -f /opt/asset-manager/requirements.txt ]; then
  /opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt -q
  log "Dépendances Python installées"
else
  warn "Pas de requirements.txt, installation des paquets de base"
  /opt/asset-manager/venv/bin/pip install fastapi uvicorn python-dotenv sqlalchemy pymysql typer mistralai -q
fi

# =============================================================================
header "5/6 — MariaDB from scratch"
# =============================================================================
systemctl start mariadb
systemctl enable mariadb

until mariadb -u root -e "SELECT 1" &>/dev/null; do
  warn "Attente de MariaDB..."; sleep 2
done

# Sécurisation de base (suppression anonymes + base test)
mariadb -u root << EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
log "MariaDB sécurisé (users anonymes supprimés, base test supprimée)"

# Création de la base et de l'utilisateur
mariadb -u root << EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME}
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'%'         IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%'         WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
log "Base '${DB_NAME}' et utilisateur '${DB_USER}' créés"

# Import du schéma
if [ -f /opt/asset-manager/sql/schema.sql ]; then
  mariadb -u root "${DB_NAME}" < /opt/asset-manager/sql/schema.sql
  log "Schéma SQL importé"
else
  error "sql/schema.sql introuvable — le repo est-il bien cloné ?"
fi

# Création de la vue Grafana
mariadb -u root "${DB_NAME}" << 'EOF'
CREATE OR REPLACE VIEW v_vulnerabilites_tableau AS
SELECT
    co.id                                                       AS correlation_id,
    cl.nom                                                      AS client,
    s.nom                                                       AS site,
    a.nom_interne                                               AS asset,
    a.type_equipement,
    a.niveau_criticite,
    co.cve_id,
    cv.cvss_v3_score,
    cv.cvss_v3_severity,
    co.score_contextuel,
    co.priorite,
    co.statut,
    co.type_correlation,
    co.override_utilisateur,
    COALESCE(co.override_utilisateur, co.type_correlation)      AS decision_patch,
    co.exploitable_air_gap,
    co.analyse_mistral,
    co.risque_reel,
    co.date_detection,
    co.date_analyse,
    cv.description                                              AS cve_description,
    cv.cvss_v3_vector
FROM correlations co
JOIN assets a          ON a.id      = co.asset_id
JOIN cve cv            ON cv.cve_id = co.cve_id
JOIN sites s           ON s.id      = a.site_id
JOIN clients cl        ON cl.id     = s.client_id
JOIN product_vendors pv ON pv.id   = a.vendor_id
WHERE co.statut NOT IN ('faux_positif')
ORDER BY
    FIELD(co.priorite, 'critique', 'haute', 'moyenne', 'basse'),
    cv.cvss_v3_score DESC;
EOF
log "Vue v_vulnerabilites_tableau créée"

# =============================================================================
header "6/6 — Service systemd"
# =============================================================================
cat > /etc/systemd/system/asset-manager.service << EOF
[Unit]
Description=Asset & Vulnerability Manager - FastAPI
After=network.target mariadb.service

[Service]
Type=simple
User=${SUDO_USER_NAME}
WorkingDirectory=/opt/asset-manager
EnvironmentFile=/opt/asset-manager/.env
ExecStart=/opt/asset-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable asset-manager
systemctl start asset-manager
sleep 3

if systemctl is-active --quiet asset-manager; then
  log "Service asset-manager démarré"
else
  warn "Service pas encore actif — vérifie : journalctl -u asset-manager -n 30"
fi

# =============================================================================
# Configuration réseau optionnelle
# =============================================================================
echo ""
echo -e "${YELLOW}Veux-tu configurer une IP statique ? (o/N)${NC}"
read -rp "  > " CONFIGURE_IP

if [[ "$CONFIGURE_IP" =~ ^[oO]$ ]]; then
  header "Configuration réseau (IP statique)"
  ask "Adresse IP       (ex: 192.168.1.100) :"; read -rp "  > " NET_IP
  ask "Masque CIDR      (ex: 24) :";            read -rp "  > " NET_MASK
  ask "Passerelle       (ex: 192.168.1.1) :";   read -rp "  > " NET_GW
  ask "DNS primaire     (ex: 192.168.1.1) :";   read -rp "  > " NET_DNS1
  ask "DNS secondaire   (ex: 8.8.8.8) :";       read -rp "  > " NET_DNS2

  NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
  NET_IFACE="${NET_IFACE:-eth0}"
  NETPLAN_FILE=$(ls /etc/netplan/*.yaml 2>/dev/null | head -1)
  NETPLAN_FILE="${NETPLAN_FILE:-/etc/netplan/50-cloud-init.yaml}"

  cat > "$NETPLAN_FILE" << EOF
network:
  version: 2
  ethernets:
    ${NET_IFACE}:
      dhcp4: false
      addresses:
        - ${NET_IP}/${NET_MASK}
      routes:
        - to: default
          via: ${NET_GW}
      nameservers:
        addresses:
          - ${NET_DNS1}
$([ -n "$NET_DNS2" ] && echo "          - ${NET_DNS2}")
EOF

  netplan apply
  log "IP statique configurée : ${NET_IP}/${NET_MASK}"
  SERVER_IP="${NET_IP}"
fi

# =============================================================================
echo ""
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}   Installation terminée avec succès !          ${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""
echo "  FastAPI  : http://${SERVER_IP}:8000"
echo "  Docs API : http://${SERVER_IP}:8000/docs"
echo "  MariaDB  : localhost:3306 / base : ${DB_NAME}"
echo "  Auth BDD : sudo mariadb  (root sans mot de passe)"
echo ""
echo -e "${YELLOW}Actions manuelles restantes :${NC}"
echo "  1. Vérifier le service : systemctl status asset-manager"
echo "  2. Vérifier les logs   : journalctl -u asset-manager -n 50"
echo "  3. Se reconnecter SSH  : pour activer le groupe asset-manager"
echo ""
