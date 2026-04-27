#!/bin/bash
# =============================================================================
# install.sh — Installation complète Asset & Vulnerability Manager
# Usage : curl -sSL https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/main/install.sh | sudo bash
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[OK]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[!]${NC}   $1"; }
info()    { echo -e "${CYAN}[~]${NC}   $1"; }
ask()     { echo -e "${YELLOW}  → $1${NC}"; }

# Erreur avec conseil de correction
error() {
  echo ""
  echo -e "${RED}${BOLD}[ERREUR]${NC} $1"
  [ -n "${2:-}" ] && echo -e "         ${YELLOW}→ $2${NC}"
  echo ""
  exit 1
}

# Avertissement non fatal avec conseil
warn_tip() {
  echo -e "${YELLOW}[!]${NC}   $1"
  [ -n "${2:-}" ] && echo -e "         ${CYAN}→ $2${NC}"
}

# Séparateur visuel
header() {
  echo ""
  echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}${BOLD}║${NC}  $1"
  echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════╝${NC}"
}

# Suivi des étapes réussies pour le résumé final
STEPS_OK=()
STEPS_WARN=()
step_ok()   { STEPS_OK+=("$1"); }
step_warn() { STEPS_WARN+=("$1"); }

# Résumé final appelé à la sortie (succès ou erreur)
summary() {
  echo ""
  echo -e "${BLUE}${BOLD}════════════════════════════════════════════${NC}"
  echo -e "${BLUE}${BOLD}   Résumé de l'installation${NC}"
  echo -e "${BLUE}${BOLD}════════════════════════════════════════════${NC}"
  for s in "${STEPS_OK[@]:-}"; do
    echo -e "  ${GREEN}✔${NC}  $s"
  done
  for s in "${STEPS_WARN[@]:-}"; do
    echo -e "  ${YELLOW}⚠${NC}  $s"
  done
  echo ""
}
trap summary EXIT

# =============================================================================
# VÉRIFICATION ROOT
# =============================================================================
if [ "$EUID" -ne 0 ]; then
  error "Ce script doit être lancé en root." "Relance avec : sudo bash install.sh"
fi

SUDO_USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || echo 'pwner')}"

echo ""
echo -e "${BLUE}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║    Asset & Vulnerability Manager — Installer      ║${NC}"
echo -e "${BLUE}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# VÉRIFICATION DES PRÉREQUIS
# =============================================================================
header "0/6 — Vérification des prérequis"

# Connexion internet
info "Vérification de la connexion internet..."
if ! curl -sf --max-time 5 https://github.com > /dev/null; then
  error "Pas de connexion internet détectée." "Vérifie ta connexion et réessaie."
fi
log "Connexion internet OK"

# Espace disque (minimum 2 Go)
FREE_KB=$(df / | awk 'NR==2 {print $4}')
FREE_GB=$(echo "scale=1; $FREE_KB / 1048576" | bc)
if [ "$FREE_KB" -lt 2097152 ]; then
  error "Espace disque insuffisant (${FREE_GB} Go disponibles, 2 Go requis)." \
        "Libère de l'espace avant de relancer."
fi
log "Espace disque OK (${FREE_GB} Go disponibles)"

# Ubuntu / Debian uniquement
if ! command -v apt &>/dev/null; then
  error "Ce script nécessite un système basé sur Debian/Ubuntu." \
        "Utilise Ubuntu Server 22.04 ou 24.04 LTS."
fi
log "Système compatible détecté"

step_ok "Prérequis validés"

# =============================================================================
header "1/6 — Mise à jour système et dépendances"
# =============================================================================
info "Mise à jour des paquets (peut prendre quelques minutes)..."
apt update -q && apt upgrade -y -q || \
  error "Échec de la mise à jour des paquets." \
        "Vérifie ta connexion ou les sources APT (/etc/apt/sources.list)."

apt install -y -q curl wget git nano unzip python3 python3-pip python3-venv mariadb-server bc || \
  error "Échec de l'installation des paquets." \
        "Relance le script ou installe manuellement : apt install python3 python3-venv mariadb-server"

log "Paquets système installés"
step_ok "Dépendances système installées"

# =============================================================================
header "2/6 — Clone du repo"
# =============================================================================
if [ -d /opt/asset-manager/.git ]; then
  warn "Dossier /opt/asset-manager déjà existant — mise à jour depuis GitHub"
  cd /opt/asset-manager
  git pull || warn_tip "git pull échoué, on continue avec la version locale." \
                       "Tu peux relancer 'git pull' manuellement plus tard."
else
  info "Clonage du repo..."
  git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager || \
    error "Échec du clonage du repo GitHub." \
          "Vérifie que https://github.com/Gvte-Kali/AirGappedCVE est accessible."
  log "Repo cloné dans /opt/asset-manager"
fi

groupadd -f asset-manager
usermod -aG asset-manager "$SUDO_USER_NAME" 2>/dev/null || \
  warn_tip "Impossible d'ajouter $SUDO_USER_NAME au groupe asset-manager." \
           "Fais-le manuellement : sudo usermod -aG asset-manager $SUDO_USER_NAME"
chown -R :asset-manager /opt/asset-manager
chmod -R 775 /opt/asset-manager

# Créer les dossiers nécessaires
mkdir -p /opt/asset-manager/logs /opt/asset-manager/data \
         /opt/asset-manager/documents

log "Groupe et permissions configurés"
step_ok "Repo cloné et permissions configurées"

# =============================================================================
header "3/6 — Configuration du .env"
# =============================================================================
echo ""
echo "  Remplis les informations suivantes pour configurer le système."
echo "  Appuie sur Entrée pour garder la valeur par défaut indiquée entre []."
echo ""

# --- Validation IP ---
validate_ip() {
  local ip=$1
  if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -r -a parts <<< "$ip"
    for part in "${parts[@]}"; do
      [ "$part" -gt 255 ] && return 1
    done
    return 0
  fi
  return 1
}

while true; do
  ask "Adresse IP du serveur [10.100.0.20] :"
  read -rp "  > " SERVER_IP; SERVER_IP="${SERVER_IP:-10.100.0.20}"
  validate_ip "$SERVER_IP" && break
  echo -e "  ${RED}IP invalide : '$SERVER_IP'. Exemple valide : 192.168.1.100${NC}"
done

# --- Clé NVD ---
while true; do
  ask "Clé API NVD (https://nvd.nist.gov/developers/request-an-api-key) :"
  read -rp "  > " NVD_API_KEY
  [ -n "$NVD_API_KEY" ] && break
  echo -e "  ${RED}La clé NVD ne peut pas être vide.${NC}"
done

# --- Clé Mistral ---
while true; do
  ask "Clé API Mistral (https://console.mistral.ai/api-keys) :"
  read -rp "  > " MISTRAL_API_KEY
  [ -n "$MISTRAL_API_KEY" ] && break
  echo -e "  ${RED}La clé Mistral ne peut pas être vide.${NC}"
done

ask "Modèle Mistral [mistral-large-latest] :"
read -rp "  > " MISTRAL_MODEL; MISTRAL_MODEL="${MISTRAL_MODEL:-mistral-large-latest}"

# --- Nom utilisateur MariaDB ---
while true; do
  ask "Nom d'utilisateur MariaDB de gestion [avea] :"
  read -rp "  > " DB_USER; DB_USER="${DB_USER:-avea}"
  [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]] && break
  echo -e "  ${RED}Nom invalide. Utilise uniquement lettres, chiffres et underscores.${NC}"
done

# --- Mot de passe avec confirmation ---
while true; do
  ask "Mot de passe pour l'utilisateur '${DB_USER}' :"
  read -rsp "  > " DB_PASSWORD; echo ""
  if [ -z "$DB_PASSWORD" ]; then
    echo -e "  ${RED}Le mot de passe ne peut pas être vide.${NC}"
    continue
  fi
  ask "Confirme le mot de passe :"
  read -rsp "  > " DB_PASSWORD_CONFIRM; echo ""
  [ "$DB_PASSWORD" = "$DB_PASSWORD_CONFIRM" ] && break
  echo -e "  ${RED}Les mots de passe ne correspondent pas. Réessaie.${NC}"
done

# --- Nom de la base ---
ask "Nom de la base de données [asset_vuln_manager] :"
read -rp "  > " DB_NAME; DB_NAME="${DB_NAME:-asset_vuln_manager}"

# Écriture du .env
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

chown :asset-manager /opt/asset-manager/.env
chmod 660 /opt/asset-manager/.env
log ".env configuré"
step_ok ".env généré"

# =============================================================================
header "4/6 — Virtualenv Python et dépendances"
# =============================================================================
info "Création du virtualenv Python..."
python3 -m venv /opt/asset-manager/venv || \
  error "Échec de la création du virtualenv." \
        "Vérifie que python3-venv est bien installé : apt install python3-venv"

info "Mise à jour de pip..."
/opt/asset-manager/venv/bin/pip install --upgrade pip -q

if [ -f /opt/asset-manager/requirements.txt ]; then
  info "Installation des dépendances depuis requirements.txt..."
  /opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt -q || \
    error "Échec de l'installation des dépendances Python." \
          "Vérifie le fichier requirements.txt ou ta connexion internet."
  log "Dépendances Python installées"
else
  warn_tip "Pas de requirements.txt trouvé — installation des paquets de base." \
           "Ajoute un requirements.txt au repo pour un install reproductible."
  /opt/asset-manager/venv/bin/pip install fastapi uvicorn python-dotenv sqlalchemy pymysql typer mistralai -q
fi

step_ok "Virtualenv Python et dépendances installés"

# =============================================================================
header "5/6 — MariaDB from scratch"
# =============================================================================
info "Démarrage de MariaDB..."
systemctl start mariadb || \
  error "Impossible de démarrer MariaDB." \
        "Vérifie les logs : journalctl -u mariadb -n 30"
systemctl enable mariadb -q

info "Attente que MariaDB soit prêt..."
RETRIES=0
until mariadb -u root -e "SELECT 1" &>/dev/null; do
  RETRIES=$((RETRIES+1))
  [ "$RETRIES" -ge 15 ] && \
    error "MariaDB ne répond pas après 30 secondes." \
          "Vérifie les logs : journalctl -u mariadb -n 30"
  sleep 2
done
log "MariaDB opérationnel"

# Sécurisation
info "Sécurisation de MariaDB..."
mariadb -u root << 'EOF'
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
log "MariaDB sécurisé (users anonymes et base test supprimés)"

# Création base et utilisateur
info "Création de la base et de l'utilisateur..."
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

# Import schéma
if [ -f /opt/asset-manager/sql/schema.sql ]; then
  info "Import du schéma SQL..."
  mariadb -u root "${DB_NAME}" < /opt/asset-manager/sql/schema.sql || \
    error "Échec de l'import du schéma SQL." \
          "Vérifie le fichier sql/schema.sql et relance."
  log "Schéma SQL importé"
else
  error "sql/schema.sql introuvable." \
        "Assure-toi que le repo est bien cloné et contient sql/schema.sql."
fi

# Création vue
info "Création de la vue v_vulnerabilites_tableau..."
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
JOIN assets a           ON a.id      = co.asset_id
JOIN cve cv             ON cv.cve_id = co.cve_id
JOIN sites s            ON s.id      = a.site_id
JOIN clients cl         ON cl.id     = s.client_id
JOIN product_vendors pv ON pv.id     = a.vendor_id
WHERE co.statut NOT IN ('faux_positif')
ORDER BY
    FIELD(co.priorite, 'critique', 'haute', 'moyenne', 'basse'),
    cv.cvss_v3_score DESC;
EOF
log "Vue v_vulnerabilites_tableau créée"
step_ok "MariaDB configuré (base, utilisateur, schéma, vue)"

# =============================================================================
header "6/6 — Service systemd"
# =============================================================================
info "Création du service systemd..."
cat > /etc/systemd/system/asset-manager.service << EOF
[Unit]
Description=Asset & Vulnerability Manager — FastAPI
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=${SUDO_USER_NAME}
WorkingDirectory=/opt/asset-manager
EnvironmentFile=/opt/asset-manager/.env
ExecStart=/opt/asset-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=append:/opt/asset-manager/logs/FastAPI.log
StandardError=append:/opt/asset-manager/logs/FastAPI.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable asset-manager -q
info "Démarrage du service..."
systemctl start asset-manager

# Vérification avec retry
RETRIES=0
until systemctl is-active --quiet asset-manager; do
  RETRIES=$((RETRIES+1))
  [ "$RETRIES" -ge 6 ] && {
    step_warn "Service asset-manager démarré mais statut incertain"
    warn_tip "Le service n'est pas encore actif." \
             "Vérifie : journalctl -u asset-manager -n 30"
    break
  }
  sleep 2
done
systemctl is-active --quiet asset-manager && {
  log "Service asset-manager démarré avec succès"
  step_ok "Service systemd actif sur le port 8000"
}

# =============================================================================
# CONFIGURATION RÉSEAU OPTIONNELLE
# =============================================================================
echo ""
echo -e "${YELLOW}Veux-tu configurer une IP statique ? (o/N)${NC}"
read -rp "  > " CONFIGURE_IP

if [[ "${CONFIGURE_IP}" =~ ^[oO]$ ]]; then
  header "Bonus — Configuration réseau (IP statique)"

  while true; do
    ask "Adresse IP (ex: 192.168.1.100) :"
    read -rp "  > " NET_IP
    validate_ip "$NET_IP" && break
    echo -e "  ${RED}IP invalide. Exemple : 192.168.1.100${NC}"
  done

  while true; do
    ask "Masque CIDR (ex: 24) :"
    read -rp "  > " NET_MASK
    [[ "$NET_MASK" =~ ^([0-9]|[1-2][0-9]|3[0-2])$ ]] && break
    echo -e "  ${RED}Masque invalide. Entrer un nombre entre 0 et 32.${NC}"
  done

  while true; do
    ask "Passerelle (ex: 192.168.1.1) :"
    read -rp "  > " NET_GW
    validate_ip "$NET_GW" && break
    echo -e "  ${RED}IP passerelle invalide.${NC}"
  done

  while true; do
    ask "DNS primaire (ex: 192.168.1.1) :"
    read -rp "  > " NET_DNS1
    validate_ip "$NET_DNS1" && break
    echo -e "  ${RED}IP DNS invalide.${NC}"
  done

  ask "DNS secondaire (optionnel, Entrée pour ignorer) :"
  read -rp "  > " NET_DNS2

  NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
  NET_IFACE="${NET_IFACE:-eth0}"
  info "Interface réseau détectée : $NET_IFACE"

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

  netplan apply 2>/dev/null || \
    warn_tip "netplan apply a échoué." \
             "Vérifie la config : cat $NETPLAN_FILE"

  log "IP statique configurée : ${NET_IP}/${NET_MASK} via ${NET_GW}"
  step_ok "IP statique configurée : ${NET_IP}/${NET_MASK}"
  SERVER_IP="${NET_IP}"
fi

# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║        Installation terminée avec succès !        ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}FastAPI${NC}  : http://${SERVER_IP}:8000"
echo -e "  ${BOLD}Docs API${NC} : http://${SERVER_IP}:8000/docs"
echo -e "  ${BOLD}MariaDB${NC}  : localhost:3306 — base : ${DB_NAME}"
echo -e "  ${BOLD}Logs${NC}     : /opt/asset-manager/logs/FastAPI.log"
echo ""
echo -e "${YELLOW}${BOLD}Actions manuelles restantes :${NC}"
echo "  1. Vérifier le service : systemctl status asset-manager"
echo "  2. Suivre les logs     : tail -f /opt/asset-manager/logs/FastAPI.log"
echo "  3. Se reconnecter SSH  : pour activer le groupe asset-manager"
echo "  4. Connexion MariaDB   : sudo mariadb"
echo ""
