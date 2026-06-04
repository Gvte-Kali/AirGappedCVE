#!/bin/bash
# =============================================================================
# install_ubuntu_complete.sh — Installation complète pour Ubuntu Server
# Spécialement conçu pour AirGappedCVE
# Prérequis: Le dépôt doit être cloné et .env doit être rempli manuellement
# Usage: sudo bash install_ubuntu_complete.sh
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

warn()    {
  echo -e "${YELLOW}[!]${NC}   $1" | tee -a "$LOG_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$LOG_FILE"
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
# VÉRIFICATION PRÉREQUIS
# =============================================================================
header "Vérification des prérequis"

# Vérifier que le dépôt est déjà cloné
if [ ! -d "$INSTALL_DIR/.git" ]; then
  echo ""
  echo -e "${RED}${BOLD}❌ ERREUR: Le dépôt n'est pas cloné dans $INSTALL_DIR${NC}"
  echo ""
  echo "Ce script suppose que le dépôt AirGappedCVE est déjà cloné."
  echo "Clonez d'abord le dépôt avec :"
  echo "  git clone https://github.com/Gvte-Kali/AirGappedCVE.git $INSTALL_DIR"
  echo ""
  exit 1
fi
log "Dépôt détecté dans $INSTALL_DIR"

# Vérifier que le fichier .env existe
if [ ! -f "$ENV_FILE" ]; then
  echo ""
  echo -e "${RED}${BOLD}❌ ERREUR: Le fichier .env n'existe pas dans $INSTALL_DIR${NC}"
  echo ""
  echo "Vous devez créer et remplir manuellement le fichier .env avant de lancer ce script."
  echo "Copiez le modèle : cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
  echo "Puis éditez-le avec vos valeurs : nano $INSTALL_DIR/.env"
  echo ""
  exit 1
fi
log "Fichier .env détecté"

# Vérifier que le fichier .env contient les variables nécessaires
MISSING_VARS=()
for var in SERVER_IP SERVER_PORT DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD; do
  if ! grep -q "^$var=" "$ENV_FILE" 2>/dev/null; then
    MISSING_VARS+=("$var")
  fi
done

if [ ${#MISSING_VARS[@]} -gt 0 ]; then
  echo ""
  echo -e "${RED}${BOLD}❌ ERREUR: Variables manquantes dans .env${NC}"
  echo ""
  echo "Les variables suivantes sont manquantes dans $ENV_FILE :"
  for var in "${MISSING_VARS[@]}"; do
    echo "  - $var"
  done
  echo ""
  echo "Remplissez toutes les variables nécessaires avant de relancer le script."
  echo ""
  exit 1
fi
log "Toutes les variables requises sont présentes dans .env"

# Vérifier que le script asset-manager.sh existe
if [ ! -f "$SCRIPTS_DIR/asset-manager.sh" ]; then
  echo ""
  echo -e "${RED}${BOLD}❌ ERREUR: Le script asset-manager.sh est introuvable${NC}"
  echo ""
  echo "Le fichier $SCRIPTS_DIR/asset-manager.sh n'existe pas."
  echo "Assurez-vous que le dépôt est bien cloné et complet."
  echo ""
  exit 1
fi
log "Script asset-manager.sh détecté"

# Vérifier que le schéma SQL existe
if [ ! -f "$INSTALL_DIR/sql/schema.sql" ]; then
  echo ""
  echo -e "${RED}${BOLD}❌ ERREUR: Le fichier schema.sql est introuvable${NC}"
  echo ""
  echo "Le fichier $INSTALL_DIR/sql/schema.sql n'existe pas."
  echo ""
  exit 1
fi
log "Schéma SQL détecté"

echo ""
read -rp "Appuyer sur Entrée pour continuer ou Ctrl+C pour annuler... "

# =============================================================================
# ÉTAPE 1: MISE À JOUR SYSTÈME ET INSTALLATION DES DÉPENDANCES
# =============================================================================
header "Étape 1/7 — Mise à jour système et installation des dépendances"

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
# ÉTAPE 2: CONFIGURATION DE LA BASE DE DONNÉES
# =============================================================================
header "Étape 2/7 — Configuration de MariaDB"

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

ask_continue

# =============================================================================
# ÉTAPE 3: CRÉATION DE LA BASE ET IMPORT DU SCHÉMA
# =============================================================================
header "Étape 3/7 — Création de la base et import du schéma"

# Lire les variables depuis .env
DB_NAME=$(grep "^DB_NAME=" "$ENV_FILE" | cut -d'=' -f2-)
DB_USER=$(grep "^DB_USER=" "$ENV_FILE" | cut -d'=' -f2-)
DB_PASSWORD=$(grep "^DB_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2-)

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

ask_continue

# =============================================================================
# ÉTAPE 4: CONFIGURATION DE L'APPLICATION
# =============================================================================
header "Étape 4/7 — Configuration de l'application"

# Créer le virtualenv Python
info "Création de l'environnement virtuel Python..."
if ! python3 -m venv "$INSTALL_DIR/venv" > /dev/null 2>&1; then
  error "Échec de la création du virtualenv" "Vérifie que python3-venv est bien installé"
  ask_continue
else
  log "Virtualenv créé"
fi

# Installer les dépendances
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

ask_continue

# =============================================================================
# ÉTAPE 5: CONFIGURATION DU SERVICE SYSTEMD
# =============================================================================
header "Étape 5/7 — Configuration du service systemd"

# Créer le service
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

ask_continue

# =============================================================================
# ÉTAPE 6: AJOUT AU PATH
# =============================================================================
header "Étape 6/7 — Ajout de asset-manager au PATH"

# Créer le fichier pour le PATH
cat > "$PATH_FILE" << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF

chmod +x "$PATH_FILE"

# Rendre le script asset-manager.sh exécutable
if [ -f "$SCRIPTS_DIR/asset-manager.sh" ]; then
  chmod +x "$SCRIPTS_DIR/asset-manager.sh"
  log "asset-manager.sh rendu exécutable"
else
  error "Fichier asset-manager.sh introuvable" "Le fichier $SCRIPTS_DIR/asset-manager.sh n'existe pas"
  ask_continue
fi

# Source le fichier pour la session actuelle
export PATH="$PATH:$SCRIPTS_DIR"

log "asset-manager ajouté au PATH"
log "La commande 'asset-manager' sera disponible après reconnexion"

ask_continue

# =============================================================================
# ÉTAPE 7: VÉRIFICATIONS FINALES
# =============================================================================
header "Étape 7/7 — Vérifications finales"

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
SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" | cut -d'=' -f2-)
SERVER_PORT=$(grep "^SERVER_PORT=" "$ENV_FILE" | cut -d'=' -f2-)
echo "  FastAPI      : http://$SERVER_IP:$SERVER_PORT"
echo "  API Docs     : http://$SERVER_IP:$SERVER_PORT/docs"
echo "  MariaDB      : localhost:3306 (base: $DB_NAME)"
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
echo "  2. Vérifier manuellement si des erreurs sont présentes"
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
