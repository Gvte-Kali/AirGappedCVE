#!/bin/bash
# =============================================================================
# install_user_friendly.sh — Script d'installation utilisateur pour AirGappedCVE
# Ce script guide l'utilisateur étape par étape
# Usage: sudo bash install_user_friendly.sh
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
LOG_FILE="$INSTALL_DIR/installation.log"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_NAME="asset-manager"
SCRIPTS_DIR="$INSTALL_DIR/scripts"
PATH_FILE="/etc/profile.d/asset-manager.sh"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Compteur d'erreurs
ERRORS=0

# =============================================================================
# FONCTIONS DE LOG
# =============================================================================
log()     {
  echo -e "${GREEN}[✓]${NC}  $1" | tee -a "$LOG_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE"
}

error()   {
  ERRORS=$((ERRORS+1))
  echo -e "${RED}${BOLD}[ERREUR $ERRORS]${NC} $1" | tee -a "$LOG_FILE"
  [ -n "${2:-}" ] && echo -e "         ${YELLOW}→ $2${NC}" | tee -a "$LOG_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR $ERRORS] $1" >> "$LOG_FILE"
  [ -n "${2:-}" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR $ERRORS] Solution: $2" >> "$LOG_FILE"
}

info()    {
  echo -e "${CYAN}[~]${NC}   $1" | tee -a "$LOG_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$LOG_FILE"
}

header()  {
  echo "" | tee -a "$LOG_FILE"
  echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
  echo -e "${BLUE}${BOLD}  $1${NC}" | tee -a "$LOG_FILE"
  echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$LOG_FILE"
}

# Fonction pour demander si on continue après une erreur
ask_continue() {
  if [ $ERRORS -gt 0 ]; then
    echo ""
    echo -e "${RED}${BOLD}⚠️  $ERRORS erreur(s) détectée(s)${NC}"
    echo ""
    read -rp "Voulez-vous continuer l'installation ? (o/N) : " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[oOyY]$ ]]; then
      echo ""
      error "Installation annulée par l'utilisateur" "Corrigez les erreurs et relancez le script"
      exit 1
    fi
    echo ""
    info "Reprise de l'installation..."
  fi
}

# Fonction pour générer un mot de passe aléatoire de 32 caractères
generate_password() {
  tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
  echo
}

# =============================================================================
# VÉRIFICATION ROOT
# =============================================================================
if [ "$EUID" -ne 0 ]; then
  echo "Ce script doit être lancé en root." >&2
  echo "Relance avec : sudo bash $0" >&2
  exit 1
fi

# Créer le fichier de log
mkdir -p "$INSTALL_DIR"
touch "$LOG_FILE"

header "Début de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
echo "Script: $0"
echo "Utilisateur: $(whoami)"
echo "Système: $(lsb_release -d 2>/dev/null | cut -f2-)"

# =============================================================================
# ÉTAPE 1: MISE À JOUR SYSTÈME ET INSTALLATION DES DÉPENDANCES
# =============================================================================
header "Étape 1/5 — Mise à jour système et installation des dépendances"

info "Mise à jour des paquets..."
if ! apt-get update -qq > /dev/null 2>&1; then
  error "Échec de la mise à jour des paquets" "Vérifie ta connexion ou les sources APT (/etc/apt/sources.list)"
  ask_continue
fi

if ! apt-get upgrade -y -qq > /dev/null 2>&1; then
  error "Échec de la mise à niveau des paquets" "Vérifie ta connexion"
  ask_continue
fi
log "Système à jour"

info "Installation des dépendances..."
if ! apt-get install -y -qq \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-venv \
    mariadb-server \
    mariadb-client \
    bc \
    net-tools \
    netcat \
    > /dev/null 2>&1; then
  error "Échec de l'installation des dépendances" "Relance le script ou installe manuellement"
  ask_continue
fi
log "Dépendances installées"

ask_continue

# =============================================================================
# ÉTAPE 2: CRÉATION DU DOSSIER ET CLONE DU PROJET
# =============================================================================
header "Étape 2/5 — Clone du projet AirGappedCVE"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Dépôt existant détecté — mise à jour..."
    cd "$INSTALL_DIR"
    if ! git pull origin main > /dev/null 2>&1; then
      error "Échec de la mise à jour du dépôt" "Vérifie ta connexion ou les permissions"
      ask_continue
    fi
    log "Dépôt mis à jour"
else
    info "Clonage du dépôt dans $INSTALL_DIR..."
    if ! git clone "$REPO_URL" "$INSTALL_DIR" > /dev/null 2>&1; then
      error "Échec du clonage du dépôt GitHub" "Vérifie que $REPO_URL est accessible"
      ask_continue
    fi
    log "Dépôt cloné dans $INSTALL_DIR"
fi

# Supprimer les fichiers inutiles en production
rm -rf "$INSTALL_DIR/.devcontainer"
log ".devcontainer supprimé"

# Créer les dossiers nécessaires
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/documents"
log "Dossiers créés"

ask_continue

# =============================================================================
# ÉTAPE 3: CONFIGURATION DES VARIABLES D'ENVIRONNEMENT
# =============================================================================
header "Étape 3/5 — Configuration des variables d'environnement"

echo ""
echo "Nous allons maintenant configurer les variables nécessaires."
echo ""

# Demander NVD_API_KEY (optionnel)
while true; do
  read -rp "Entrez votre clé API NVD (laisser vide si vous n'en avez pas) : " NVD_API_KEY
  if [ -z "$NVD_API_KEY" ]; then
    echo "  → Aucune clé NVD fournie (optionnel)"
    break
  fi
  break
done

# Demander MISTRAL_API_KEY (optionnel)
while true; do
  read -rp "Entrez votre clé API Mistral (laisser vide si vous n'en avez pas) : " MISTRAL_API_KEY
  if [ -z "$MISTRAL_API_KEY" ]; then
    echo "  → Aucune clé Mistral fournie (optionnel)"
    break
  fi
  break
done

# Demander DB_USER (obligatoire)
while true; do
  read -rp "Entrez le nom d'utilisateur pour la base de données (obligatoire) : " DB_USER
  if [ -n "$DB_USER" ]; then
    break
  fi
  echo "  → Le nom d'utilisateur est obligatoire !"
done

# Générer DB_PASSWORD automatiquement
DB_PASSWORD=$(generate_password)
echo "  → Mot de passe généré automatiquement pour $DB_USER"

# Définir les valeurs par défaut
SERVER_IP=$(hostname -I | awk '{print $1}')
MISTRAL_MODEL="mistral-large-latest"
DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_NAME="asset_vuln_manager"

echo ""
echo "Configuration enregistrée :"
echo "  DB_USER     : $DB_USER"
echo "  DB_PASSWORD : $DB_PASSWORD (généré automatiquement)"
echo "  DB_NAME     : $DB_NAME"
echo "  DB_HOST     : $DB_HOST"
echo "  DB_PORT     : $DB_PORT"
echo "  SERVER_IP   : $SERVER_IP"
echo ""

# Créer le fichier .env
info "Création du fichier .env..."
cat > "$ENV_FILE" << EOF
# =============================================================================
# Configuration Asset & Vulnerability Manager
# Généré automatiquement par install_user_friendly.sh
# =============================================================================

# --- SERVER ---
SERVER_IP=$SERVER_IP
SERVER_PORT=8000

# --- DATABASE ---
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

# --- API KEYS ---
NVD_API_KEY=${NVD_API_KEY:-}
MISTRAL_API_KEY=${MISTRAL_API_KEY:-}
MISTRAL_MODEL=$MISTRAL_MODEL

# --- LOGGING ---
LOG_LEVEL=info
EOF

chmod 600 "$ENV_FILE"
log "Fichier .env créé avec les variables configurées"

ask_continue

# =============================================================================
# ÉTAPE 4: INSTALLATION DE LA BASE DE DONNÉES, FASTAPI ET SERVICES
# =============================================================================
header "Étape 4/5 — Installation de la base de données et de l'application"

# Configuration de MariaDB
info "Démarrage de MariaDB..."
if ! systemctl start mariadb > /dev/null 2>&1; then
  error "Impossible de démarrer MariaDB" "Vérifie les logs : journalctl -u mariadb -n 30"
  ask_continue
fi

if ! systemctl enable mariadb > /dev/null 2>&1; then
  error "Impossible d'activer MariaDB au démarrage" "Vérifie systemctl"
  ask_continue
fi

# Attendre que MariaDB soit prêt
info "Attente que MariaDB soit opérationnel..."
RETRIES=0
until mariadb -u root -e "SELECT 1" > /dev/null 2>&1; do
  RETRIES=$((RETRIES+1))
  if [ "$RETRIES" -ge 15 ]; then
    error "MariaDB ne répond pas après 30 secondes" "Vérifie les logs : journalctl -u mariadb -n 30"
    ask_continue
    break
  fi
  sleep 2
  echo -n "."
done
if [ "$RETRIES" -lt 15 ]; then
  echo ""
  log "MariaDB opérationnel"
fi

# Sécurisation de base
info "Sécurisation de MariaDB..."
if ! mariadb -u root << 'EOF' > /dev/null 2>&1
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
then
  error "Échec de la sécurisation de MariaDB" "Vérifie les permissions root"
  ask_continue
else
  log "MariaDB sécurisé"
fi

# Création de la base et import du schéma
info "Création de la base de données '$DB_NAME'..."
if ! mariadb -u root << EOF > /dev/null 2>&1
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
then
  error "Échec de la création de la base ou de l'utilisateur" "Vérifie les permissions MariaDB"
  ask_continue
else
  log "Base et utilisateur créés"
fi

# Import du schéma
SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
info "Import du schéma SQL..."
if ! mariadb -u root "$DB_NAME" < "$SCHEMA_FILE" 2>/dev/null; then
  error "Échec de l'import du schéma SQL" "Vérifie le fichier sql/schema.sql"
  ask_continue
else
  log "Schéma importé"
fi

# Création du virtualenv Python
info "Création de l'environnement virtuel Python..."
if ! python3 -m venv "$INSTALL_DIR/venv" > /dev/null 2>&1; then
  error "Échec de la création du virtualenv" "Vérifie que python3-venv est bien installé"
  ask_continue
else
  log "Virtualenv créé"
fi

# Installation des dépendances Python
info "Installation des dépendances Python..."
if ! "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q > /dev/null 2>&1; then
  error "Échec de la mise à jour de pip" "Vérifie l'environnement virtuel"
  ask_continue
fi

if ! "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q > /dev/null 2>&1; then
  error "Échec de l'installation des dépendances Python" "Vérifie le fichier requirements.txt ou ta connexion internet"
  ask_continue
else
  log "Dépendances installées"
fi

# Configuration du service systemd
info "Configuration du service systemd..."
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Asset & Vulnerability Manager — FastAPI
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/FastAPI.log
StandardError=append:$INSTALL_DIR/logs/FastAPI.log

[Install]
WantedBy=multi-user.target
EOF

if ! systemctl daemon-reload > /dev/null 2>&1; then
  error "Échec du rechargement de systemd" "Vérifie les permissions"
  ask_continue
else
  log "systemd rechargé"
fi

if ! systemctl enable "$SERVICE_NAME" > /dev/null 2>&1; then
  error "Échec de l'activation du service" "Vérifie le fichier de service"
  ask_continue
else
  log "Service activé"
fi

info "Démarrage du service..."
if ! systemctl start "$SERVICE_NAME" > /dev/null 2>&1; then
  error "Échec du démarrage du service" "Vérifie : journalctl -u $SERVICE_NAME -n 30"
  ask_continue
else
  log "Service démarré"
fi

# Attendre que le service soit prêt
RETRIES=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  RETRIES=$((RETRIES+1))
  if [ "$RETRIES" -ge 15 ]; then
    error "Service FastAPI ne répond pas après 30 secondes" "Vérifie les logs : journalctl -u $SERVICE_NAME -n 30"
    ask_continue
    break
  fi
  sleep 2
  echo -n "."
done
if [ "$RETRIES" -lt 15 ]; then
  echo ""
  log "Service FastAPI opérationnel"
fi

# Ajout au PATH
info "Ajout de asset-manager au PATH..."
cat > "$PATH_FILE" << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF

chmod +x "$PATH_FILE"
chmod +x "$SCRIPTS_DIR/asset-manager.sh"
export PATH="$PATH:$SCRIPTS_DIR"
log "asset-manager ajouté au PATH"

ask_continue

# =============================================================================
# ÉTAPE 5: VÉRIFICATIONS FINALES
# =============================================================================
header "Étape 5/5 — Vérifications finales"

info "Exécution des commandes de vérification..."
echo "" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo "VÉRIFICATIONS FINALES" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

# Créer un tableau pour stocker les résultats
VERIFICATION_RESULTS=()

# Fonction pour exécuter une commande de vérification et stocker le résultat
run_verification() {
  local cmd_name="$1"
  local cmd="$2"
  
  info "Exécution: $cmd_name"
  if eval "$cmd" >> "$LOG_FILE" 2>&1; then
    log "$cmd_name ✓"
    VERIFICATION_RESULTS+=("✓ $cmd_name")
    return 0
  else
    error "Échec de $cmd_name" "Vérifie les services"
    VERIFICATION_RESULTS+=("✗ $cmd_name")
    return 1
  fi
}

# Exécuter toutes les commandes de vérification
run_verification "asset-manager status" "bash \"$SCRIPTS_DIR/asset-manager.sh\" status"
run_verification "asset-manager sys ports" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys ports"
run_verification "asset-manager sys check-db" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-db"
run_verification "asset-manager sys check-env" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-env"
run_verification "asset-manager db check" "bash \"$SCRIPTS_DIR/asset-manager.sh\" db check"

ask_continue

# =============================================================================
# RÉCAPITULATIF FINAL
# =============================================================================
header "Récapitulatif de l'installation"

echo ""
echo "📊 État de l'installation :"

# Compter les succès et échecs
SUCCESS_COUNT=0
FAIL_COUNT=0
for result in "${VERIFICATION_RESULTS[@]}"; do
  if [[ "$result" == ✓* ]]; then
    SUCCESS_COUNT=$((SUCCESS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
done

if [ $ERRORS -eq 0 ] && [ $FAIL_COUNT -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✅ Installation réussie !${NC}"
  echo ""
  echo "Toutes les étapes et vérifications se sont déroulées avec succès."
elif [ $ERRORS -gt 0 ] || [ $FAIL_COUNT -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}⚠️  Installation terminée avec des problèmes${NC}"
  echo ""
  if [ $ERRORS -gt 0 ]; then
    echo "  - $ERRORS erreur(s) pendant l'installation"
  fi
  if [ $FAIL_COUNT -gt 0 ]; then
    echo "  - $FAIL_COUNT vérification(s) échouée(s)"
  fi
else
  echo -e "${RED}${BOLD}❌ Installation incomplète${NC}"
  echo ""
fi

echo ""
echo "📋 Résultats des vérifications :"
for result in "${VERIFICATION_RESULTS[@]}"; do
  echo "  $result"
done

echo ""
echo "📁 Configuration :"
echo "  FastAPI      : http://$SERVER_IP:8000"
echo "  API Docs     : http://$SERVER_IP:8000/docs"
echo "  MariaDB      : localhost:3306 (base: $DB_NAME)"
echo ""
echo "🔑 Identifiants MariaDB :"
echo "  Utilisateur : $DB_USER"
echo "  Mot de passe : $DB_PASSWORD"
echo ""
echo "📁 Dossiers :"
echo "  Application : $INSTALL_DIR"
echo "  Logs        : $INSTALL_DIR/logs/"
echo "  installation.log : $LOG_FILE"
echo "  .env        : $ENV_FILE"
echo ""
echo "📝 Commandes de vérification exécutées et loggées dans $LOG_FILE"
echo ""
echo "⚠️  Actions manuelles requises :"
echo "  1. Se déconnecter et se reconnecter pour activer le PATH"
echo "     (ou exécuter : source $PATH_FILE)"
if [ -z "$NVD_API_KEY" ]; then
  echo "  2. Ajouter NVD_API_KEY dans $ENV_FILE pour activer les fonctionnalités NVD"
fi
if [ -z "$MISTRAL_API_KEY" ]; then
  echo "  3. Ajouter MISTRAL_API_KEY dans $ENV_FILE pour activer l'IA Mistral"
fi
echo ""
echo "🎯 Commandes utiles :"
echo "  systemctl status $SERVICE_NAME"
echo "  journalctl -u $SERVICE_NAME -f"
echo "  mariadb -u root"
echo "  tail -f $LOG_FILE"
echo "  asset-manager help"
echo ""
echo "📄 Fichier de log complet : $LOG_FILE"

header "Fin de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
