#!/bin/bash
# =============================================================================
# install.sh — Script d'installation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 5.0.0
# Description : Installe et configure automatiquement AirGappedCVE sur Ubuntu Server
# Usage: sudo bash install.sh
# =============================================================================

set +euo pipefail

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================

# Chemins et fichiers
INSTALL_DIR="/opt/asset-manager"
LOG_FILE="$INSTALL_DIR/installation.log"
VERBOSE_LOG="/tmp/asset-manager-installation.log"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_NAME="asset-manager"
SCRIPTS_DIR="$INSTALL_DIR/scripts"
PATH_FILE="/etc/profile.d/asset-manager.sh"
USER_BASHRC="$HOME/.bashrc"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'; PURPLE='\033[0;35m'

# Variables par défaut
DB_HOST="127.0.0.1"
DB_PORT=3306
DB_NAME="asset_vuln_manager"
SERVER_PORT=8000
MISTRAL_MODEL="mistral-large-latest"

# Compteurs
ERRORS=0
declare -a ERROR_MESSAGES=()
START_TIME=$(date +%s)

# Initialiser les logs
mkdir -p "$INSTALL_DIR" "/tmp" 2>/dev/null
> "$VERBOSE_LOG"
> "$LOG_FILE"

# =============================================================================
# FONCTIONS DE SPINNER
# =============================================================================

spinner_pid=""
spinner_chars="|/-\\"
spinner_delay=0.1

spinner_start() {
    local msg="$1"
    printf "[%s] %s" "${spinner_chars:0:1}" "$msg" >&2
    (
        while true; do
            for i in {0..3}; do
                printf "\r[%s] %s" "${spinner_chars:$i:1}" "$msg" >&2
                sleep $spinner_delay
            done
        done
    ) &
    spinner_pid=$!
    disown
}

spinner_stop() {
    local msg="$1"
    local exit_code="$2"
    if [ -n "$spinner_pid" ] && kill -0 "$spinner_pid" 2>/dev/null; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null
    fi
    printf "\r" >&2
    if [ "$exit_code" -eq 0 ]; then
        printf "[${GREEN}✅${NC}] %s\n" "$msg" >&2
    else
        printf "[${RED}❌${NC}] %s\n" "$msg" >&2
    fi
    spinner_pid=""
}

run_with_spinner() {
    local msg="$1"
    shift
    local cmd="$*"
    local exit_code=0

    spinner_start "$msg"
    eval "$cmd" >> "$VERBOSE_LOG" 2>&1 || exit_code=$?
    spinner_stop "$msg" $exit_code

    return $exit_code
}

# =============================================================================
# FONCTIONS DE LOG
# =============================================================================

log() {
    echo -e "${GREEN}[✅]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$VERBOSE_LOG"
}

error() {
    local msg="$1"
    local solution="${2:-}"
    ERRORS=$((ERRORS+1))
    ERROR_MESSAGES+=("$msg → $solution")

    echo -e "${RED}[❌ ERREUR $ERRORS]${NC} $msg"
    [ -n "$solution" ] && echo -e "         ${YELLOW}→ $solution${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] $msg" >> "$LOG_FILE"
    [ -n "$solution" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] Solution: $solution" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[⚠️ AVERTISSEMENT]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$LOG_FILE"
}

info() {
    echo -e "${CYAN}[ℹ️ INFO]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$LOG_FILE"
}

header() {
    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$LOG_FILE"
}

ask_continue() {
    if [ $ERRORS -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}${BOLD}⚠️ $ERRORS erreur(s) détectée(s)${NC}"
        echo "Détails dans $VERBOSE_LOG"
        echo ""
        read -t 30 -rp "Voulez-vous continuer ? (o/N) : " choice
        if [[ ! "$choice" =~ ^[oOyY]$ ]]; then
            echo ""
            echo -e "${RED}${BOLD}❌ Installation annulée par l'utilisateur${NC}"
            exit 0
        fi
        echo ""
        info "Reprise de l'installation..."
    fi
}

ask_continue_if_error() {
    local exit_code=$1
    if [ $exit_code -ne 0 ]; then
        ask_continue
    fi
}

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================

header "🔍 Vérifications préliminaires"

# 1. Root (SEULE ERREUR CRITIQUE)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}${BOLD}❌ ERREUR CRITIQUE: Ce script doit être lancé en root.${NC}"
    echo -e "${YELLOW}→ Relancez avec: sudo bash $0${NC}"
    exit 1
fi

# 2. Vérifications non bloquantes
check_disk_space() {
    MIN_SPACE_GB=5
    AVAILABLE_SPACE_KB=$(df /opt --output=avail | tail -1 2>/dev/null || echo "0")
    AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
    if [ "$AVAILABLE_SPACE_GB" -lt "$MIN_SPACE_GB" ]; then
        error "💾 Espace disque insuffisant" "$AVAILABLE_SPACE_GB GB disponibles, $MIN_SPACE_GB GB requis"
    else
        info "💾 Espace disque suffisant ($AVAILABLE_SPACE_GB GB)"
    fi
}

check_memory() {
    MIN_RAM_MB=2048
    TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")
    if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ]; then
        error "🧠 Mémoire insuffisante" "$TOTAL_RAM_MB MB détectés, $MIN_RAM_MB MB requis"
    else
        info "🧠 Mémoire suffisante ($TOTAL_RAM_MB MB)"
    fi
}

check_internet() {
    if command -v ping >/dev/null 2>&1 && ping -c 1 -W 2 github.com >/dev/null 2>&1; then
        info "🌐 Connexion internet active"
    else
        error "🌐 Pas de connexion internet" "Certaines étapes peuvent échouer"
    fi
}

check_ports() {
    if ss -tunlp | grep -q ":8000 " 2>/dev/null; then
        error "🚪 Port 8000 occupé" "Libérez le port ou changez SERVER_PORT"
    fi
    if ss -tunlp | grep -q ":3306 " 2>/dev/null; then
        info "🐘 Port 3306 utilisé (MariaDB ou autre service)"
    else
        info "🐘 Port 3306 libre"
    fi
}

check_disk_space
check_memory
check_internet
check_ports

# =============================================================================
# ÉTAPE 1/8 : INSTALLATION DES DÉPENDANCES
# =============================================================================

header "📦 Étape 1/8 - Installation des dépendances"

REQUIRED_COMMANDS=("curl" "wget" "git" "bc" "ss" "pgrep" "add-apt-repository" "ip")
MISSING_COMMANDS=()

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_COMMANDS+=("$cmd")
    fi
done

if [ ${#MISSING_COMMANDS[@]} -gt 0 ]; then
    info "🔍 Commandes manquantes détectées: ${MISSING_COMMANDS[*]}"

    declare -A CMD_TO_PKG=(
        [curl]="curl"
        [wget]="wget"
        [git]="git"
        [bc]="bc"
        [ss]="iproute2"
        [pgrep]="procps"
        [add-apt-repository]="software-properties-common"
        [ip]="iproute2"
    )

    run_with_spinner "🔄 Mise à jour APT" "apt-get update -qq"
    ask_continue_if_error $?

    for cmd in "${MISSING_COMMANDS[@]}"; do
        pkg="${CMD_TO_PKG[$cmd]}"
        run_with_spinner "📦 Installation de $pkg" "apt-get install -y -qq $pkg"
        ask_continue_if_error $?
    done
    log "✅ Toutes les commandes sont installées"
else
    info "✅ Toutes les commandes requises sont disponibles"
fi

run_with_spinner "🐍 Installation de python3-venv" "apt-get install -y -qq python3-venv python3-pip python3-dev build-essential"
ask_continue_if_error $?
log "✅ Dépendances Python installées"

# =============================================================================
# ÉTAPE 2/8 : INSTALLATION DE MARIADB
# =============================================================================

header "🐘 Étape 2/8 - Installation de MariaDB"

if ! ss -tunlp | grep -q ":3306 " 2>/dev/null; then
    info "🔍 MariaDB non détecté sur le port 3306"

    run_with_spinner "📦 Installation de MariaDB" "apt-get install -y -qq mariadb-server mariadb-client"
    ask_continue_if_error $?

    if [ "$DB_PORT" != "3306" ]; then
        run_with_spinner "⚙️ Configuration du port $DB_PORT" "sed -i 's/^port.*=.*3306/port = $DB_PORT/' /etc/mysql/mariadb.conf.d/50-server.cnf"
        ask_continue_if_error $?
    fi

    run_with_spinner "🔄 Démarrage de MariaDB" "systemctl enable mariadb && systemctl start mariadb"
    ask_continue_if_error $?

    info "⏳ Attente que MariaDB soit opérationnel..."
    RETRIES=0
    while ! ss -tunlp | grep -q ":3306 " 2>/dev/null; do
        RETRIES=$((RETRIES+1))
        if [ $RETRIES -ge 30 ]; then
            error "🐘 MariaDB ne répond pas après 60 secondes" "Vérifiez: journalctl -u mariadb -n 50"
            ask_continue
            break
        fi
        sleep 2
        printf "\r${CYAN}  → Attente... ($RETRIES/30)${NC}"
    done
    if [ $RETRIES -lt 30 ]; then
        echo ""
        log "✅ MariaDB opérationnel sur le port 3306"
    fi
else
    info "✅ MariaDB est déjà opérationnel sur le port 3306"
fi

run_with_spinner "🔐 Sécurisation de MariaDB" "mariadb -u root -e \"DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\\_%'; FLUSH PRIVILEGES;\""
ask_continue_if_error $?
log "✅ MariaDB sécurisé"

# =============================================================================
# ÉTAPE 3/8 : CLONE DU PROJET
# =============================================================================

header "🚀 Étape 3/8 - Clone du projet AirGappedCVE"

if [ -d "$INSTALL_DIR" ]; then
    info "🗑️ Le dossier $INSTALL_DIR existe déjà"
    read -t 30 -rp "   Voulez-vous le supprimer ? (o/N) : " CLEAN_CHOICE
    if [[ "$CLEAN_CHOICE" =~ ^[oOyY]$ ]]; then
        run_with_spinner "🗑️ Suppression du dossier existant" "rm -rf $INSTALL_DIR"
        ask_continue_if_error $?
    fi
fi

mkdir -p "$INSTALL_DIR" || { error "📁 Échec de la création du dossier" "$INSTALL_DIR"; ask_continue; }

run_with_spinner "🚀 Clonage du dépôt" "git clone $REPO_URL $INSTALL_DIR"
ask_continue_if_error $?

if [ ! -f "$INSTALL_DIR/main.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ] || [ ! -f "$INSTALL_DIR/sql/schema.sql" ]; then
    error "❌ Dépôt incomplet" "Vérifiez $REPO_URL"
    ask_continue
else
    log "✅ Dépôt cloné avec succès"
fi

rm -rf "$INSTALL_DIR/.devcontainer" 2>/dev/null || warn "⚠️ Nettoyage échoué (ignoré)"

# =============================================================================
# ÉTAPE 4/8 : CONFIGURATION DU .ENV
# =============================================================================

header "⚙️ Étape 4/8 - Configuration de l'environnement"

SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")

info "📝 Configuration des variables d'environnement"

read -t 30 -rp "🔑 Clé API NVD (optionnelle, Entrée pour ignorer) : " NVD_API_KEY
read -t 30 -rp "🤖 Clé API Mistral (optionnelle, Entrée pour ignorer) : " MISTRAL_API_KEY

while true; do
    read -t 30 -rp "👤 Utilisateur MariaDB : " DB_USER
    if [ -z "$DB_USER" ]; then
        echo "   ❌ Obligatoire !"
        continue
    fi
    if ! [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "   ❌ Caractères autorisés: lettres, chiffres, _"
        continue
    fi
    if [[ "$DB_USER" =~ ^(root|mysql|admin|mariadb)$ ]]; then
        echo "   ❌ Nom réservé !"
        continue
    fi
    break
done

DB_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
echo "   ✅ 🔐 Mot de passe généré automatiquement"

echo ""
info "📋 Récapitulatif de la configuration:"
echo "   🌐 SERVER_IP: $SERVER_IP"
echo "   🗄️  DB_HOST: $DB_HOST"
echo "   🔢 DB_PORT: $DB_PORT"
echo "   📊 DB_NAME: $DB_NAME"
echo "   👤 DB_USER: $DB_USER"
echo "   🔐 DB_PASSWORD: $DB_PASSWORD"
echo "   🔑 NVD_API_KEY: ${NVD_API_KEY:-non configurée}"
echo "   🤖 MISTRAL_API_KEY: ${MISTRAL_API_KEY:-non configurée}"
echo "   🎯 MISTRAL_MODEL: $MISTRAL_MODEL"
echo ""

read -t 30 -rp "✅ Confirmer cette configuration ? (o/N) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oOyY]$ ]]; then
    error "❌ Installation annulée par l'utilisateur" ""
    exit 0
fi

if [ -f "$INSTALL_DIR/.env.example" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    info "✅ Fichier .env.example copié en .env"
fi

if [ -f "$INSTALL_DIR/.env" ]; then
    cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.backup-$(date +%Y%m%d-%H%M%S)" || warn "⚠️ Sauvegarde .env échouée (ignoré)"
    info "✅ Ancien .env sauvegardé"
fi

cat > "$INSTALL_DIR/.env" << EOF
# =============================================================================
# Fichier de configuration - AirGappedCVE
# Généré par install.sh le $(date '+%Y-%m-%d %H:%M:%S')
# =============================================================================

# --- SERVER ---
SERVER_IP=$SERVER_IP
SERVER_PORT=$SERVER_PORT

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

chmod 600 "$INSTALL_DIR/.env" || warn "⚠️ chmod .env échoué (ignoré)"
log "✅ Fichier .env créé"

# =============================================================================
# ÉTAPE 5/8 : CRÉATION DU VIRTUALENV
# =============================================================================

header "🐍 Étape 5/8 - Création du virtualenv Python"

run_with_spinner "🐍 Création du virtualenv" "python3 -m venv $INSTALL_DIR/venv"
ask_continue_if_error $?

run_with_spinner "🔄 Mise à jour de pip" "$INSTALL_DIR/venv/bin/pip install --upgrade pip"
ask_continue_if_error $?

run_with_spinner "📦 Installation des dépendances Python" "$INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt"
ask_continue_if_error $?

log "✅ Virtualenv et dépendances Python configurés"

# =============================================================================
# ÉTAPE 6/8 : CONFIGURATION DE LA BASE DE DONNÉES
# =============================================================================

header "🗄️ Étape 6/8 - Configuration de la base de données"

run_with_spinner "🗄️ Création de la base $DB_NAME" \
    "mariadb -u root -e \"CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; \
    CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; \
    CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; \
    GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; \
    GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION; \
    FLUSH PRIVILEGES;\""
ask_continue_if_error $?
log "✅ Base et utilisateur créés"

SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
if [ -f "$SCHEMA_FILE" ]; then
    run_with_spinner "📜 Import du schéma SQL" "mariadb -u $DB_USER -p$DB_PASSWORD $DB_NAME < $SCHEMA_FILE"
    ask_continue_if_error $?
    log "✅ Schéma importé"
else
    error "❌ Fichier schema.sql introuvable" "$SCHEMA_FILE"
    ask_continue
fi

# Test de connexion avec le nouvel utilisateur
run_with_spinner "🔍 Test de connexion MariaDB" "mariadb -u $DB_USER -p$DB_PASSWORD -e \"SELECT 1\""
if [ $? -ne 0 ]; then
    error "❌ Échec de la connexion avec l'utilisateur $DB_USER" "Vérifiez les identifiants"
    ask_continue
else
    log "✅ Connexion MariaDB validée"
fi

# =============================================================================
# ÉTAPE 7/8 : CRÉATION DU SERVICE SYSTEMD
# =============================================================================

header "🚀 Étape 7/8 - Création du service systemd"

cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=AirGappedCVE - Asset & Vulnerability Manager
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/FastAPI.log
StandardError=append:$INSTALL_DIR/logs/FastAPI.log

[Install]
WantedBy=multi-user.target
EOF

run_with_spinner "🔄 Rechargement de systemd" "systemctl daemon-reload"
ask_continue_if_error $?

run_with_spinner "🚀 Activation du service" "systemctl enable $SERVICE_NAME"
ask_continue_if_error $?

log "✅ Service systemd configuré"

# =============================================================================
# ÉTAPE 8/8 : AJOUT AU PATH
# =============================================================================

header "📍 Étape 8/8 - Ajout au PATH"

mkdir -p "$SCRIPTS_DIR"

cat > "$PATH_FILE" << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF
chmod +x "$PATH_FILE" "$SCRIPTS_DIR/asset-manager.sh" 2>/dev/null || warn "⚠️ chmod échoué (ignoré)"

if [ -f "$USER_BASHRC" ] && ! grep -q "asset-manager" "$USER_BASHRC"; then
    echo "" >> "$USER_BASHRC"
    echo "# Ajouté par install.sh - AirGappedCVE" >> "$USER_BASHRC"
    echo 'export PATH="$PATH:/opt/asset-manager/scripts"' >> "$USER_BASHRC"
    info "✅ PATH ajouté à $USER_BASHRC"
else
    warn "⚠️ Impossible de modifier $USER_BASHRC (ignoré)"
fi

export PATH="$PATH:$SCRIPTS_DIR"
log "✅ asset-manager est maintenant dans votre PATH"
info "   Exécutez 'source $USER_BASHRC' ou relancez votre terminal pour activer les changements."

# =============================================================================
# ÉTAPE 9/9 : DÉMARRAGE ET TEST DE FASTAPI
# =============================================================================

header "🔍 Vérifications finales"

info "🚀 Démarrage de FastAPI..."
if command -v asset-manager >/dev/null 2>&1; then
    asset-manager fastapi start >> "$VERBOSE_LOG" 2>&1 || error "❌ Échec du démarrage de FastAPI" "Vérifiez les logs"
    ask_continue_if_error $?
else
    run_with_spinner "🚀 Démarrage de FastAPI" "$INSTALL_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --log-level info &"
    ask_continue_if_error $?
fi

info "⏳ Attente que FastAPI soit opérationnel..."
RETRIES=0
while ! curl -sf http://localhost:$SERVER_PORT/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES+1))
    if [ $RETRIES -ge 30 ]; then
        error "❌ FastAPI ne répond pas après 60 secondes" "Vérifiez: journalctl -u $SERVICE_NAME -n 50"
        ask_continue
        break
    fi
    sleep 2
    printf "\r${CYAN}  → Attente... ($RETRIES/30)${NC}"
done
if [ $RETRIES -lt 30 ]; then
    echo ""
    log "✅ FastAPI est opérationnel sur http://$SERVER_IP:$SERVER_PORT"
fi

run_with_spinner "🩺 Test du health endpoint" "curl -sf http://localhost:$SERVER_PORT/health"
if [ $? -eq 0 ]; then
    log "✅ Health endpoint accessible"
else
    error "❌ Health endpoint inaccessible" "Vérifiez FastAPI"
    ask_continue
fi

# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================

header "✅ Installation terminée"

ELAPSED_TIME=$(( $(date +%s) - START_TIME ))
ELAPSED_MIN=$((ELAPSED_TIME / 60))
ELAPSED_SEC=$((ELAPSED_TIME % 60))

echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 Installation terminée avec succès !${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo ""
echo "📊 Résumé :"
echo "  API Docs     : http://$SERVER_IP:$SERVER_PORT/docs"
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
echo "  Logs détaillés : $VERBOSE_LOG"
echo "  .env        : $ENV_FILE"
echo ""
echo "⏱️  Temps d'exécution total : ${ELAPSED_MIN} minute(s) et ${ELAPSED_SEC} seconde(s)"
echo ""
echo "📝 Commandes de vérification exécutées et loggées dans $VERBOSE_LOG"
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
echo "🌟 Commandes utiles :"
echo "  systemctl status $SERVICE_NAME"
echo "  journalctl -u $SERVICE_NAME -f"
echo "  mariadb -u root"
echo "  tail -f $LOG_FILE"
echo "  cat $VERBOSE_LOG"
echo "  asset-manager help"
echo ""
echo "📄 Fichier de log complet : $LOG_FILE"
echo "📄 Fichier de log détaillé : $VERBOSE_LOG"

header "Fin de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
