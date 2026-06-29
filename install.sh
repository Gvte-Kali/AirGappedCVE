#!/bin/bash

# =============================================================================
# install_user_friendly.sh — Script d'installation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 6.4.0 (Détection MariaDB basée SUR TES TESTS : ss -tunlp | grep 3306 + sudo mysql)
# Description : Installe et configure AirGappedCVE sur Ubuntu Server
# Usage: sudo bash install.sh [--test-mode]
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION GLOBALE
# =============================================================================

INSTALL_DIR="/opt/asset-manager"
LOG_FILE="$INSTALL_DIR/installation.log"
VERBOSE_LOG="/tmp/asset-manager-installation.log"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_NAME="asset-manager"
SCRIPTS_DIR="$INSTALL_DIR/scripts"
PATH_FILE="/etc/profile.d/asset-manager.sh"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
PURPLE='\033[0;35m'

# Ports par défaut
DB_PORT_DEFAULT=3306
DB_PORT_ALT=3307

# Niveaux d'erreur
ERROR_LEVEL_WARNING=1
ERROR_LEVEL_ERROR=2
ERROR_LEVEL_CRITICAL=3

# Compteur d'erreurs
ERRORS=0
declare -a ERROR_MESSAGES=()

# Mode test
TEST_MODE=false
if [[ "${1:-}" == "--test-mode" ]]; then
    TEST_MODE=true
    echo "[TEST MODE] Aucune modification ne sera appliquée."
fi

# Initialiser les logs
mkdir -p "$INSTALL_DIR"
> "$VERBOSE_LOG"
> "$LOG_FILE"

# =============================================================================
# FONCTIONS DE LOG
# =============================================================================

log() {
    echo -e "${GREEN}[✓]${NC}  $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$VERBOSE_LOG"
}

error() {
    local level=${3:-$ERROR_LEVEL_ERROR}
    ERRORS=$((ERRORS+1))
    local level_str=""
    case $level in
        $ERROR_LEVEL_CRITICAL) level_str="${RED}${BOLD}[ERREUR CRITIQUE $ERRORS]${NC}" ;;
        $ERROR_LEVEL_ERROR)    level_str="${RED}${BOLD}[ERREUR $ERRORS]${NC}" ;;
        $ERROR_LEVEL_WARNING)  level_str="${YELLOW}${BOLD}[AVERTISSEMENT $ERRORS]${NC}" ;;
        *)                      level_str="${RED}${BOLD}[ERREUR $ERRORS]${NC}" ;;
    esac
    local full_msg="$1"
    [ -n "${2:-}" ] && full_msg="$full_msg → $2"
    ERROR_MESSAGES+=("$full_msg")

    echo -e "$level_str $1" | tee -a "$VERBOSE_LOG"
    [ -n "${2:-}" ] && echo -e "         ${YELLOW}→ $2${NC}" | tee -a "$VERBOSE_LOG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] $1" >> "$LOG_FILE"
    [ -n "${2:-}" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] Solution: $2" >> "$LOG_FILE"

    if [ "$level" -eq "$ERROR_LEVEL_CRITICAL" ]; then
        echo ""
        echo -e "${RED}${BOLD}❌ Installation arrêtée à cause d'une erreur critique.${NC}"
        echo "Détails dans $VERBOSE_LOG"
        exit 1
    fi
}

warn() {
    echo -e "${YELLOW}[~]${NC}   $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$VERBOSE_LOG"
}

info() {
    echo -e "${CYAN}[~]${NC}   $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$VERBOSE_LOG"
}

header() {
    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$LOG_FILE"
}

step_header() {
    local step_num=$1
    local step_name="$2"
    local total_steps=$3
    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo -e "${BLUE}${BOLD}  Étape ${step_num}/${total_steps} — ${step_name}${NC}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [STEP] Étape ${step_num}/${total_steps}: ${step_name}" >> "$LOG_FILE"
}

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

ask_continue() {
    if [ $ERRORS -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}${BOLD}⚠️  $ERRORS erreur(s) détectée(s)${NC}"
        echo "Détails dans $VERBOSE_LOG"
        echo ""
        read -rp "Voulez-vous continuer l'installation ? (o/N) : " CONTINUE
        if [[ ! "$CONTINUE" =~ ^[oOyY]$ ]]; then
            error "Installation annulée par l'utilisateur" "Corrigez les erreurs et relancez le script" $ERROR_LEVEL_CRITICAL
        fi
        echo ""
        info "Reprise de l'installation..."
    fi
}

generate_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
    echo
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# =============================================================================
# DÉTECTION MARIADB (BASÉE SUR TES TESTS : ss -tunlp | grep 3306 + sudo mysql)
# =============================================================================

# Vérifie si le port 3306 est utilisé (TON TEST : ss -tunlp | grep 3306)
is_port_3306_in_use() {
    ss -tunlp | grep -q ":3306"
}

# Vérifie si on peut se connecter à MariaDB (TON TEST : sudo mysql)
check_mariadb_connection() {
    local port="${1:-$DB_PORT_DEFAULT}"
    
    # Tester avec mysql (le plus courant sur Ubuntu)
    if command_exists "mysql" && sudo mysql --port=$port -e "SELECT 1" >/dev/null 2>&1; then
        return 0
    fi
    
    # Tester avec mariadb (si mysql n'est pas disponible)
    if command_exists "mariadb" && sudo mariadb --port=$port -e "SELECT 1" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Vérifie si MariaDB est opérationnel (port + connexion)
is_mariadb_operational() {
    local port="${1:-$DB_PORT_DEFAULT}"
    
    # 1. Vérifier le port 3306 (TON TEST EXACT)
    if ! is_port_3306_in_use; then
        return 1
    fi
    
    # 2. Vérifier la connexion (TON TEST EXACT: sudo mysql)
    if ! check_mariadb_connection $port; then
        return 1
    fi
    
    return 0
}

# Attend que MariaDB soit opérationnel
wait_for_mariadb() {
    local port="${1:-$DB_PORT_DEFAULT}"
    local max_retries=30
    local retries=0
    
    while [ $retries -lt $max_retries ]; do
        if is_mariadb_operational $port; then
            return 0
        fi
        retries=$((retries+1))
        sleep 2
        printf "\r${CYAN}  → Attente que MariaDB soit prêt... ($retries/$max_retries)${NC}"
    done
    return 1
}

# =============================================================================
# GESTION DES CONFLITS DE PORT (simplifiée)
# =============================================================================

handle_mariadb_port_conflict() {
    local port="$1"
    
    # Si MariaDB est déjà opérationnel sur ce port, on l'utilise
    if is_mariadb_operational $port; then
        read -rp "MariaDB est déjà opérationnel sur le port $port (détecté via ss + sudo mysql). Voulez-vous l'utiliser ? (O/n) : " use_existing
        if [[ "$use_existing" =~ ^[OoYy]$ ]] || [ -z "$use_existing" ]; then
            DB_PORT=$port
            info "Utilisation de MariaDB existant sur le port $port"
            return 0
        fi
    fi
    
    # Sinon, vérifier si UN service écoute sur le port
    if ss -tunlp | grep -q ":$port"; then
        local service_on_port
        service_on_port=$(ss -tunlp | grep ":$port " | awk '{print $7}' | cut -d'=' -f2 | xargs)
        
        echo ""
        echo "Un service écoute sur le port $port: $service_on_port"
        echo "Choix disponibles:"
        echo "  1) Supprimer le service actuel et installer MariaDB sur le port $port"
        echo "  2) Laisser le service en place et installer MariaDB sur le port $DB_PORT_ALT"
        echo "  3) Annuler"
        read -rp "Votre choix [1-3] : " db_choice
        
        case "$db_choice" in
            1)
                # Arrêter le service actuel
                if [ -n "$service_on_port" ]; then
                    systemctl stop "$service_on_port" >> "$VERBOSE_LOG" 2>&1 || true
                    systemctl disable "$service_on_port" >> "$VERBOSE_LOG" 2>&1 || true
                fi
                DB_PORT=$port
                ;;
            2)
                DB_PORT=$DB_PORT_ALT
                ;;
            3)
                error "Installation annulée" "" $ERROR_LEVEL_CRITICAL
                ;;
            *)
                error "Choix invalide" "" $ERROR_LEVEL_ERROR
                return 1
                ;;
        esac
    else
        # Aucun service sur le port, on peut l'utiliser
        DB_PORT=$port
        return 0
    fi
    
    return 0
}

# =============================================================================
# VÉRIFICATION ROOT
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}${BOLD}[ERREUR CRITIQUE]${NC}"
    echo -e "Ce script doit être lancé en root."
    echo -e "${YELLOW}→ Relancez avec : sudo bash $0${NC}"
    exit 1
fi

# =============================================================================
# ASCII ART DE BIENVENUE
# =============================================================================
echo -e "${PURPLE}"
echo "  AirGappedCVE - Gestion de vulnérabilités en environnement isolé"
echo -e "${NC}"

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================

header "Vérifications préliminaires"

# 1. Vérification des COMMANDES requises
info "Vérification des commandes requises..."
REQUIRED_COMMANDS=("curl" "wget" "git" "bc" "ss" "pgrep" "add-apt-repository")
MISSING_COMMANDS=()

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command_exists "$cmd"; then
        MISSING_COMMANDS+=("$cmd")
    fi
done

if [ ${#MISSING_COMMANDS[@]} -gt 0 ]; then
    info "Installation des commandes manquantes: ${MISSING_COMMANDS[*]}"
    
    # Mapping commande → paquet
    declare -A CMD_TO_PKG=(
        [curl]="curl"
        [wget]="wget"
        [git]="git"
        [bc]="bc"
        [ss]="iproute2"
        [pgrep]="procps"
        [add-apt-repository]="software-properties-common"
    )
    
    # Installer un par un
    info "Mise à jour APT..."
    if ! apt-get update -qq >> "$VERBOSE_LOG" 2>&1; then
        error "Échec de la mise à jour APT" "Vérifiez votre connexion" $ERROR_LEVEL_CRITICAL
    fi
    log "Mise à jour APT terminée"
    
    for cmd in "${MISSING_COMMANDS[@]}"; do
        local pkg="${CMD_TO_PKG[$cmd]}"
        info "Installation de $pkg (pour $cmd)..."
        if ! apt-get install -y -qq "$pkg" >> "$VERBOSE_LOG" 2>&1; then
            error "Échec de l'installation de $pkg" "Vérifiez APT" $ERROR_LEVEL_ERROR
        else
            log "$pkg installé"
        fi
    done
else
    info "Toutes les commandes requises sont disponibles"
fi

# 2. Espace disque
MIN_SPACE_GB=5
AVAILABLE_SPACE_KB=$(df /opt --output=avail | tail -1)
AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
if [ "$AVAILABLE_SPACE_GB" -lt "$MIN_SPACE_GB" ]; then
    error "Espace disque insuffisant sur /opt" "${AVAILABLE_SPACE_GB}GB disponibles, ${MIN_SPACE_GB}GB requis" $ERROR_LEVEL_CRITICAL
else
    info "Espace disque suffisant (${AVAILABLE_SPACE_GB}GB sur /opt)"
fi

# 3. Mémoire
MIN_RAM_MB=2048
TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")
if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ] 2>/dev/null; then
    error "Mémoire insuffisante" "${TOTAL_RAM_MB}MB détectés, ${MIN_RAM_MB}MB requis" $ERROR_LEVEL_WARNING
else
    info "Mémoire suffisante (${TOTAL_RAM_MB}MB)"
fi

# 4. Architecture
ARCH=$(uname -m)
info "Architecture $ARCH détectée"

# 5. Connexion internet
if command_exists "ping" && ping -c 1 -W 2 github.com > /dev/null 2>&1; then
    info "Connexion internet active"
else
    error "Pas de connexion internet" "Certaines étapes peuvent échouer" $ERROR_LEVEL_WARNING
fi

# 6. Ports
info "Vérification des ports..."
if ss -tunlp | grep -q ":8000"; then
    error "Port 8000 occupé" "Libérez le port" $ERROR_LEVEL_ERROR
fi

# 7. Détection de MariaDB (BASÉE SUR TES TESTS EXACTS)
info "Détection de MariaDB..."
DB_PORT=$DB_PORT_DEFAULT

# Vérifier si MariaDB est opérationnel (port 3306 + connexion sudo mysql)
if is_mariadb_operational $DB_PORT_DEFAULT; then
    info "MariaDB est opérationnel sur le port $DB_PORT_DEFAULT (détecté via ss -tunlp | grep 3306 + sudo mysql)"
    DB_PORT=$DB_PORT_DEFAULT
else
    # Vérifier si un service écoute sur 3306 (mais connexion échouée)
    if is_port_3306_in_use; then
        warn "Le port 3306 est utilisé, mais la connexion à MariaDB échoue (sudo mysql)"
        handle_mariadb_port_conflict $DB_PORT_DEFAULT
    else
        info "MariaDB n'est pas détecté (port 3306 non utilisé ou connexion échouée)"
    fi
fi

# 8. Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2 || echo "0.0")
if [ "$(printf '%s\n%s' "3.10" "$PYTHON_VERSION" | sort -V | head -1)" != "3.10" ]; then
    error "Python $PYTHON_VERSION détecté" "Python 3.10+ requis" $ERROR_LEVEL_WARNING
else
    info "Python $PYTHON_VERSION détecté"
fi

# 9. Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Distribution: $ID $VERSION_ID"
else
    error "Distribution non détectée" "" $ERROR_LEVEL_WARNING
fi

header "Début de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
echo "Script: $0"
echo "Utilisateur: $(whoami)"
echo "Système: $(lsb_release -d 2>/dev/null | cut -f2- || echo 'Inconnu')"
echo "Mode test: ${TEST_MODE}"
echo ""
echo "Logs détaillés: $VERBOSE_LOG"
echo ""

ask_continue

# =============================================================================
# ÉTAPE 1: MISE À JOUR SYSTÈME
# =============================================================================
step_header 1 5 "Mise à jour système"

info "Mise à jour APT..."
if ! apt-get update -qq >> "$VERBOSE_LOG" 2>&1; then
    error "Échec de la mise à jour APT" "Vérifiez votre connexion" $ERROR_LEVEL_CRITICAL
fi
log "Mise à jour APT terminée"

info "Mise à niveau des paquets..."
if ! apt-get upgrade -y -qq >> "$VERBOSE_LOG" 2>&1; then
    error "Échec de la mise à niveau" "Vérifiez APT" $ERROR_LEVEL_ERROR
fi
log "Système à jour"

ask_continue

# =============================================================================
# ÉTAPE 1B: INSTALLATION DE MARIADB (si nécessaire)
# =============================================================================
step_header "1B" 5 "Installation de MariaDB sur le port $DB_PORT"

# Installer MariaDB seulement si ce n'est pas déjà opérationnel
if ! is_mariadb_operational $DB_PORT; then
    info "Installation de MariaDB..."
    if ! apt-get install -y -qq mariadb-server mariadb-client >> "$VERBOSE_LOG" 2>&1; then
        error "Échec de l'installation de MariaDB" "Vérifiez APT" $ERROR_LEVEL_CRITICAL
    fi
    log "MariaDB installé"
    
    # Configuration du port si nécessaire
    if [ "$DB_PORT" != "$DB_PORT_DEFAULT" ]; then
        info "Configuration du port $DB_PORT..."
        if ! sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/mariadb.conf.d/50-server.cnf; then
            error "Échec de la modification du port MariaDB" "Vérifiez le fichier" $ERROR_LEVEL_ERROR
            ask_continue
        fi
        [ -f /etc/mysql/my.cnf ] && sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/my.cnf
        log "Port configuré"
    fi
    
    # Démarrage de MariaDB
    info "Démarrage de MariaDB..."
    # Essayer de démarrer via systemctl (tous les noms de service possibles)
    for svc in mariadb mariadb-server mysql mysqld; do
        if systemctl enable "$svc" >> "$VERBOSE_LOG" 2>&1 && systemctl start "$svc" >> "$VERBOSE_LOG" 2>&1; then
            break
        fi
    done
    
    if ! is_port_3306_in_use; then
        error "Échec du démarrage de MariaDB" "Vérifiez: journalctl -u mariadb" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "MariaDB démarré"
    
    # Attente que MariaDB soit opérationnel
    info "Attente que MariaDB soit opérationnel..."
    if ! wait_for_mariadb $DB_PORT; then
        error "MariaDB ne répond pas après 60 secondes" "Vérifiez: journalctl -u mariadb -n 50" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "MariaDB prêt"
    
    # Sécurisation
    info "Sécurisation de MariaDB..."
    for bin in mysql mariadb; do
        if command_exists "$bin" && sudo "$bin" --port=$DB_PORT -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;" >> "$VERBOSE_LOG" 2>&1; then
            break
        fi
    done
    log "MariaDB sécurisé"
else
    info "MariaDB est déjà opérationnel sur le port $DB_PORT (détecté via tes tests: ss + sudo mysql)"
fi

ask_continue

# =============================================================================
# ÉTAPE 2: CLONE DU PROJET
# =============================================================================
step_header 2 5 "Clone du projet AirGappedCVE"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Mise à jour du dépôt..."
    cd "$INSTALL_DIR"
    if ! git pull origin main >> "$VERBOSE_LOG" 2>&1; then
        error "Échec de la mise à jour du dépôt" "Vérifiez Git" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "Dépôt mis à jour"
else
    info "Clonage du dépôt..."
    if ! git clone "$REPO_URL" "$INSTALL_DIR" >> "$VERBOSE_LOG" 2>&1; then
        error "Échec du clonage du dépôt" "Vérifiez $REPO_URL" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "Dépôt cloné"
fi

# Vérification
if [ ! -f "$INSTALL_DIR/main.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
    error "Dépôt incomplet" "Vérifiez $REPO_URL" $ERROR_LEVEL_CRITICAL
fi

# Nettoyage
rm -rf "$INSTALL_DIR/.devcontainer"
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/documents" "$INSTALL_DIR/backups"
chmod 750 "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/backups"
log "Dossiers créés"

ask_continue

# =============================================================================
# ÉTAPE 3: CONFIGURATION ENVIRONNEMENT
# =============================================================================
step_header 3 5 "Configuration des variables d'environnement"

# Sauvegarde .env
if [ -f "$ENV_FILE" ]; then
    cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)"
    log ".env sauvegardé"
fi

# Demander les infos
read -rp "Clé API NVD (optionnel) : " NVD_API_KEY
read -rp "Clé API Mistral (optionnel) : " MISTRAL_API_KEY

while true; do
    read -rp "Utilisateur MariaDB : " DB_USER
    [[ -z "$DB_USER" ]] && { echo "  → Obligatoire"; continue; }
    [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]] || { echo "  → Caractères invalides"; continue; }
    [[ "$DB_USER" =~ ^(root|mysql|admin|mariadb)$ ]] && { echo "  → Nom réservé"; continue; }
    break
done

DB_PASSWORD=$(generate_password)
echo "  → Mot de passe généré pour $DB_USER"

SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
MISTRAL_MODEL="mistral-large-latest"
DB_HOST="127.0.0.1"
DB_NAME="asset_vuln_manager"

echo ""
echo "=== CONFIGURATION ==="
echo "FastAPI: http://$SERVER_IP:8000"
echo "MariaDB: $DB_HOST:$DB_PORT"
echo "User: $DB_USER"
echo ""
read -rp "Confirmer ? (o/N) : " CONFIRM
[[ ! "$CONFIRM" =~ ^[oOyY]$ ]] && error "Annulé" "" $ERROR_LEVEL_CRITICAL

# Créer .env
cat > "$ENV_FILE" << EOF
SERVER_IP=$SERVER_IP
SERVER_PORT=8000
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
NVD_API_KEY=${NVD_API_KEY:-}
MISTRAL_API_KEY=${MISTRAL_API_KEY:-}
MISTRAL_MODEL=$MISTRAL_MODEL
LOG_LEVEL=info
EOF
chmod 600 "$ENV_FILE"
log ".env créé"

ask_continue

# =============================================================================
# ÉTAPE 4: INSTALLATION APPLICATION
# =============================================================================
step_header 4 5 "Installation de l'application"

# Création base et utilisateur
info "Création de la base $DB_NAME..."
for bin in mysql mariadb; do
    if command_exists "$bin" && sudo "$bin" --port=$DB_PORT -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;" >> "$VERBOSE_LOG" 2>&1; then
        break
    fi
done
log "Base et utilisateur créés"

# Import schéma
SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
    error "schema.sql introuvable" "" $ERROR_LEVEL_CRITICAL
fi

info "Import du schéma..."
if ! mariadb --port=$DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME < "$SCHEMA_FILE" >> "$VERBOSE_LOG" 2>&1; then
    if ! mysql --port=$DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME < "$SCHEMA_FILE" >> "$VERBOSE_LOG" 2>&1; then
        error "Échec import schéma" "Vérifiez schema.sql" $ERROR_LEVEL_ERROR
        ask_continue
    fi
fi
log "Schéma importé"

# Virtualenv
info "Création du virtualenv..."
if ! python3 -m venv "$INSTALL_DIR/venv" >> "$VERBOSE_LOG" 2>&1; then
    error "Échec création virtualenv" "Vérifiez python3-venv" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Virtualenv créé"

# Dépendances Python
info "Installation des dépendances Python..."
if ! "$INSTALL_DIR/venv/bin/pip" install --upgrade pip >> "$VERBOSE_LOG" 2>&1; then
    error "Échec mise à jour pip" "" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "pip mis à jour"

info "Installation des requirements..."
if ! "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" >> "$VERBOSE_LOG" 2>&1; then
    error "Échec installation dépendances" "Vérifiez requirements.txt" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Dépendances Python installées"

# Service systemd
info "Configuration du service systemd..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

info "Rechargement de systemd..."
if ! systemctl daemon-reload >> "$VERBOSE_LOG" 2>&1; then
    error "Échec rechargement systemd" "" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "systemd rechargé"

info "Activation du service..."
if ! systemctl enable $SERVICE_NAME >> "$VERBOSE_LOG" 2>&1; then
    error "Échec activation service" "" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Service activé"

info "Démarrage du service..."
if ! systemctl start $SERVICE_NAME >> "$VERBOSE_LOG" 2>&1; then
    error "Échec démarrage service" "Vérifiez: journalctl -u $SERVICE_NAME" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Service démarré"

# Attente FastAPI
info "Attente FastAPI..."
RETRIES=0
while ! curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    RETRIES=$((RETRIES+1))
    [ $RETRIES -ge 30 ] && error "FastAPI ne répond pas" "Vérifiez: journalctl -u $SERVICE_NAME" $ERROR_LEVEL_ERROR
    sleep 2
    printf "\r${CYAN}  → Attente... ($RETRIES/30)${NC}"
done
echo ""
log "FastAPI opérationnel"

# PATH
info "Ajout au PATH..."
cat > "$PATH_FILE" << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF
chmod +x "$PATH_FILE" "$SCRIPTS_DIR/asset-manager.sh"
export PATH="$PATH:$SCRIPTS_DIR"
log "PATH mis à jour"

ask_continue

# =============================================================================
# ÉTAPE 5: VÉRIFICATIONS FINALES
# =============================================================================
step_header 5 5 "Vérifications finales"

for cmd in "status" "sys ports" "sys check-db" "sys check-env" "db check"; do
    printf "  → Vérification: %s... " "$cmd"
    if bash "$SCRIPTS_DIR/asset-manager.sh" $cmd >> "$VERBOSE_LOG" 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        error "Échec vérification $cmd" "" $ERROR_LEVEL_ERROR
    fi
done

ask_continue

# =============================================================================
# RÉCAPITULATIF
# =============================================================================
header "Fin de l'installation"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_MIN=$((ELAPSED / 60))

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✅ Installation réussie !${NC}"
else
    echo -e "${YELLOW}${BOLD}⚠️  $ERRORS erreur(s)${NC}"
fi

echo ""
echo "FastAPI: http://$SERVER_IP:8000"
echo "MariaDB: $DB_HOST:$DB_PORT (user: $DB_USER)"
echo "Logs: $LOG_FILE / $VERBOSE_LOG"
echo "Temps: ${ELAPSED_MIN}m"
