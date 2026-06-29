#!/bin/bash

# =============================================================================
# install_user_friendly.sh — Script d'installation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 5.5.0 (Version finale : spinner corrigé, détection commandes, gestion erreurs)
# Description : Installe et configure automatiquement AirGappedCVE sur Ubuntu Server
# Usage: sudo bash install.sh [--test-mode]
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION GLOBALE
# =============================================================================

# Chemins et fichiers
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

# Spinner
SPINNER_CHARS="|/-\\"
SPINNER_DELAY=0.1

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

# Variable globale pour le PID du spinner
SPINNER_PID=""

# Mode test (pour éviter les actions destructives)
TEST_MODE=false
if [[ "${1:-}" == "--test-mode" ]]; then
    TEST_MODE=true
    echo "[TEST MODE] Aucune modification ne sera appliquée."
fi

# Temps de début
START_TIME=$(date +%s)

# Initialiser les fichiers de log
mkdir -p "$INSTALL_DIR"
> "$VERBOSE_LOG"
> "$LOG_FILE"

# =============================================================================
# FONCTIONS SPINNER (corrigées et simplifiées)
# =============================================================================

spinner_start() {
    local msg="$1"
    printf "[%s] %s" "${SPINNER_CHARS:0:1}" "$msg" >&2
    (
        local i=0
        while true; do
            i=$(( (i + 1) % 4 ))
            printf "\r[%s] %s" "${SPINNER_CHARS:$i:1}" "$msg" >&2
            sleep $SPINNER_DELAY
        done
    ) &
    SPINNER_PID=$!
    disown
}

spinner_stop() {
    local msg="$1"
    local exit_code="$2"
    
    # Tuer le spinner s'il tourne
    if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null || true
    fi
    
    # Effacer la ligne et afficher le résultat
    printf "\r" >&2
    if [ "$exit_code" -eq 0 ]; then
        printf "[${GREEN}✓${NC}] %s\n" "$msg" >&2
    else
        printf "[${RED}✗${NC}] %s\n" "$msg" >&2
    fi
    SPINNER_PID=""
}

# Fonction pour exécuter une commande avec spinner
run_with_spinner() {
    local msg="$1"
    shift
    local cmd="$*"
    local exit_code=0
    
    # Démarrer le spinner
    spinner_start "$msg"
    
    # Exécuter la commande
    if [ "$TEST_MODE" = true ]; then
        sleep 1  # Simulation en mode test
    else
        if ! eval "$cmd" >> "$VERBOSE_LOG" 2>&1; then
            exit_code=1
        fi
    fi
    
    # Arrêter le spinner et afficher le résultat
    spinner_stop "$msg" $exit_code
    return $exit_code
}

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

    # Tuer le spinner s'il tourne encore
    if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null
    fi

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
    echo "" | tee -a "$VERBOSE_LOG"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" | tee -a "$VERBOSE_LOG"
    echo -e "${BLUE}${BOLD}  $1${NC}" | tee -a "$VERBOSE_LOG"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" | tee -a "$VERBOSE_LOG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$LOG_FILE"
}

step_header() {
    local step_num=$1
    local step_name="$2"
    local total_steps=$3

    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" | tee -a "$VERBOSE_LOG"
    echo -e "${BLUE}${BOLD}  Étape ${step_num}/${total_steps} — ${step_name}${NC}" | tee -a "$VERBOSE_LOG"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" | tee -a "$VERBOSE_LOG"
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
            echo ""
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

is_port_in_use() {
    local port="$1"
    ss -tlnp 2>/dev/null | grep -q ":$port " || netstat -tlnp 2>/dev/null | grep -q ":$port "
}

get_service_on_port() {
    local port="$1"
    ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d':' -f2 | cut -d',' -f1 | xargs
}

# =============================================================================
# DÉTECTION MARIADB
# =============================================================================

is_mariadb_installed() {
    dpkg -l | grep -q "^ii  mariadb-server "
}

is_mariadb_running() {
    systemctl is-active mariadb >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1
}

wait_for_mariadb() {
    local port="${1:-$DB_PORT_DEFAULT}"
    local max_retries=30
    local retries=0
    
    while [ $retries -lt $max_retries ]; do
        if sudo mariadb --port=$port -e "SELECT 1" >/dev/null 2>&1; then
            return 0
        fi
        retries=$((retries+1))
        sleep 2
        printf "\r${CYAN}  → Attente que MariaDB soit prêt... ($retries/$max_retries)${NC}"
    done
    return 1
}

handle_mariadb_conflict() {
    local port="$1"
    
    if ! is_port_in_use $port; then
        DB_PORT=$port
        return 0
    fi
    
    local service_on_port
    service_on_port=$(get_service_on_port $port)
    
    if [[ "$service_on_port" == *"mariadb"* ]] || [[ "$service_on_port" == *"mysql"* ]]; then
        read -rp "Un service MariaDB/MySQL est déjà actif sur le port $port. Voulez-vous l'utiliser ? (O/n) : " use_existing
        if [[ "$use_existing" =~ ^[OoYy]$ ]] || [ -z "$use_existing" ]; then
            DB_PORT=$port
            return 0
        else
            if ! systemctl stop mariadb >> "$VERBOSE_LOG" 2>&1; then
                error "Échec de l'arrêt de MariaDB" "Vérifiez systemctl" $ERROR_LEVEL_ERROR
                return 1
            fi
            if ! apt-get purge -y mariadb-server mariadb-client >> "$VERBOSE_LOG" 2>&1; then
                error "Échec de la suppression de MariaDB" "Vérifiez APT" $ERROR_LEVEL_ERROR
                return 1
            fi
            DB_PORT=$port
            return 0
        fi
    else
        echo ""
        echo "Un service non-MariaDB écoute sur le port $port: $service_on_port"
        echo "Choix disponibles:"
        echo "  1) Supprimer le service actuel et installer MariaDB sur le port $port"
        echo "  2) Laisser le service en place et installer MariaDB sur le port $DB_PORT_ALT"
        echo "  3) Annuler"
        read -rp "Votre choix [1-3] : " db_choice
        
        case "$db_choice" in
            1)
                local service_name=$(ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'=' -f2)
                if [ -n "$service_name" ]; then
                    systemctl stop "$service_name" >> "$VERBOSE_LOG" 2>&1 || true
                    systemctl disable "$service_name" >> "$VERBOSE_LOG" 2>&1 || true
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
REQUIRED_COMMANDS=("curl" "wget" "git" "bc" "netstat" "nc" "ip" "ping" "ss" "pgrep" "add-apt-repository")
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
        [netstat]="net-tools"
        [nc]="netcat-openbsd"
        [ip]="iproute2"
        [ping]="iputils-ping"
        [ss]="iproute2"
        [pgrep]="procps"
        [add-apt-repository]="software-properties-common"
    )
    
    PKGS_TO_INSTALL=()
    for cmd in "${MISSING_COMMANDS[@]}"; do
        PKGS_TO_INSTALL+=("${CMD_TO_PKG[$cmd]}")
    done
    
    run_with_spinner "Mise à jour APT" "apt-get update -qq"
    if [ $? -ne 0 ]; then
        error "Échec de la mise à jour APT" "Vérifiez votre connexion ou les sources APT" $ERROR_LEVEL_CRITICAL
    fi
    
    run_with_spinner "Installation des paquets manquants" "apt-get install -y -qq \"${PKGS_TO_INSTALL[*]}\""
    if [ $? -ne 0 ]; then
        error "Échec de l'installation des commandes requises" "Vérifiez votre connexion ou les sources APT" $ERROR_LEVEL_CRITICAL
    fi
    log "Commandes manquantes installées"
else
    info "Toutes les commandes requises sont disponibles"
fi

# 2. Espace disque
MIN_SPACE_GB=5
AVAILABLE_SPACE_KB=$(df /opt --output=avail | tail -1)
AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
if [ "$AVAILABLE_SPACE_GB" -lt "$MIN_SPACE_GB" ]; then
    error "Espace disque insuffisant sur /opt" "Il faut au moins ${MIN_SPACE_GB}GB, vous avez ${AVAILABLE_SPACE_GB}GB" $ERROR_LEVEL_CRITICAL
else
    info "Espace disque suffisant (${AVAILABLE_SPACE_GB}GB disponible sur /opt)"
fi

# 3. Mémoire
MIN_RAM_MB=2048
TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")
if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ] 2>/dev/null; then
    error "Mémoire faible détectée (${TOTAL_RAM_MB}MB). Recommandé: ${MIN_RAM_MB}MB+" "" $ERROR_LEVEL_WARNING
else
    info "Mémoire suffisante (${TOTAL_RAM_MB}MB détectés)"
fi

# 4. Architecture
ARCH=$(uname -m)
info "Architecture $ARCH détectée"

# 5. Connexion internet
if command_exists "ping" && ping -c 1 -W 2 github.com > /dev/null 2>&1; then
    info "Connexion internet active"
else
    error "Pas de connexion internet détectée" "Certaines étapes peuvent nécessiter une connexion" $ERROR_LEVEL_WARNING
fi

# 6. Ports
info "Vérification des ports..."
if is_port_in_use 8000; then
    error "Le port 8000 est déjà utilisé par $(get_service_on_port 8000)" "Arrêtez le service ou changez le port FastAPI" $ERROR_LEVEL_ERROR
fi

# 7. Détection de MariaDB
info "Détection de MariaDB..."
DB_PORT=$DB_PORT_DEFAULT

if is_mariadb_installed; then
    info "MariaDB est installé (paquet détecté)"
    if is_mariadb_running; then
        info "MariaDB est en cours d'exécution"
        if is_port_in_use $DB_PORT_DEFAULT; then
            handle_mariadb_conflict $DB_PORT_DEFAULT
        fi
    else
        warn "MariaDB est installé mais pas en cours d'exécution"
    fi
else
    info "MariaDB n'est pas installé"
fi

# 8. Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2 || echo "0.0")
if [ "$(printf '%s\n%s' "3.10" "$PYTHON_VERSION" | sort -V | head -1)" != "3.10" ]; then
    error "Python $PYTHON_VERSION détecté. Recommandé: Python 3.10+" "" $ERROR_LEVEL_WARNING
else
    info "Python $PYTHON_VERSION détecté"
fi

# 9. Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Distribution: $ID $VERSION_ID"
else
    error "Impossible de détecter la distribution Linux" "" $ERROR_LEVEL_WARNING
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
# ÉTAPE 1: MISE À JOUR SYSTÈME ET INSTALLATION DES DÉPENDANCES
# =============================================================================
step_header 1 5 "Mise à jour système et installation des dépendances"

run_with_spinner "Mise à jour APT" "apt-get update -qq"
if [ $? -ne 0 ]; then
    error "Échec de la mise à jour APT" "Vérifiez votre connexion ou les sources APT" $ERROR_LEVEL_CRITICAL
fi
log "Mise à jour APT terminée"

run_with_spinner "Mise à niveau des paquets" "apt-get upgrade -y -qq"
if [ $? -ne 0 ]; then
    error "Échec de la mise à niveau" "Vérifiez APT" $ERROR_LEVEL_ERROR
fi
log "Système à jour"

# Dépendances système (hors MariaDB)
info "Installation des dépendances système..."
SYSTEM_DEPS=("python3" "python3-pip" "python3-venv" "python3-dev" "build-essential")
run_with_spinner "Installation des dépendances Python" "apt-get install -y -qq \"${SYSTEM_DEPS[*]}\""
if [ $? -ne 0 ]; then
    error "Échec de l'installation des dépendances système" "Vérifiez les logs dans $VERBOSE_LOG" $ERROR_LEVEL_ERROR
else
    log "Dépendances système installées"
fi

ask_continue

# =============================================================================
# ÉTAPE 1B: INSTALLATION DE MARIADB
# =============================================================================
step_header "1B" 5 "Installation de MariaDB sur le port $DB_PORT"

# Installer MariaDB seulement si ce n'est pas déjà fait
if ! is_mariadb_installed; then
    run_with_spinner "Installation de MariaDB" "apt-get install -y -qq mariadb-server mariadb-client"
    if [ $? -ne 0 ]; then
        error "Échec de l'installation de MariaDB" "Vérifiez les logs APT" $ERROR_LEVEL_CRITICAL
    fi
    log "MariaDB installé"
else
    info "MariaDB déjà installé"
fi

# Configuration du port si nécessaire
if [ "$DB_PORT" != "$DB_PORT_DEFAULT" ]; then
    info "Configuration du port $DB_PORT..."
    if ! sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/mariadb.conf.d/50-server.cnf; then
        error "Échec de la modification du port MariaDB" "Vérifiez le fichier de configuration" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    if [ -f /etc/mysql/my.cnf ]; then
        sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/my.cnf
    fi
    log "Port MariaDB configuré sur $DB_PORT"
fi

# Démarrage et activation de MariaDB
if ! is_mariadb_running; then
    run_with_spinner "Démarrage de MariaDB" "systemctl enable mariadb && systemctl start mariadb"
    if [ $? -ne 0 ]; then
        error "Échec du démarrage de MariaDB" "Vérifiez les logs : journalctl -u mariadb -n 30" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "MariaDB démarré et activé"
else
    info "MariaDB est déjà en cours d'exécution"
fi

# Attendre que MariaDB soit prêt
info "Attente que MariaDB soit opérationnel..."
if ! wait_for_mariadb $DB_PORT; then
    error "MariaDB ne répond pas après 60 secondes" "Vérifiez les logs: journalctl -u mariadb -n 50" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "MariaDB est prêt"

# Sécurisation de base (avec sudo pour root)
run_with_spinner "Sécurisation de MariaDB" "sudo mariadb --port=$DB_PORT -e \"DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;\""
if [ $? -ne 0 ]; then
    error "Échec de la sécurisation de MariaDB" "Vérifiez les permissions root" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "MariaDB sécurisé"

# Vérification de la version de MariaDB
MARIADB_VERSION=$(mariadb --version 2>/dev/null | awk '{print $5}' | cut -d. -f1-2)
if [ -z "$MARIADB_VERSION" ]; then
    error "MariaDB n'est pas installé correctement" "Vérifiez l'installation" $ERROR_LEVEL_CRITICAL
else
    info "MariaDB $MARIADB_VERSION installé"
fi

ask_continue

# =============================================================================
# ÉTAPE 2: CRÉATION DU DOSSIER ET CLONE DU PROJET
# =============================================================================
step_header 2 5 "Clone du projet AirGappedCVE"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Dépôt existant détecté — mise à jour..."
    cd "$INSTALL_DIR"
    run_with_spinner "Mise à jour du dépôt" "git pull origin main"
    if [ $? -ne 0 ]; then
        error "Échec de la mise à jour du dépôt" "Vérifiez votre connexion ou les permissions" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "Dépôt mis à jour"
else
    run_with_spinner "Clonage du dépôt" "git clone \"$REPO_URL\" \"$INSTALL_DIR\""
    if [ $? -ne 0 ]; then
        error "Échec du clonage du dépôt GitHub" "Vérifiez que $REPO_URL est accessible" $ERROR_LEVEL_ERROR
        ask_continue
    fi
    log "Dépôt cloné dans $INSTALL_DIR"
fi

# Vérification de l'intégrité du dépôt
if [ ! -f "$INSTALL_DIR/main.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
    error "Le dépôt semble incomplet ou corrompu" "Vérifiez que $REPO_URL est valide" $ERROR_LEVEL_CRITICAL
fi

# Supprimer les fichiers inutiles
rm -rf "$INSTALL_DIR/.devcontainer"
log ".devcontainer supprimé"

# Créer les dossiers nécessaires
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/documents" "$INSTALL_DIR/backups"
chmod 750 "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/backups"
log "Dossiers créés"

ask_continue

# =============================================================================
# ÉTAPE 3: CONFIGURATION DES VARIABLES D'ENVIRONNEMENT
# =============================================================================
step_header 3 5 "Configuration des variables d'environnement"

echo ""
echo "Configuration des variables nécessaires."
echo ""

# Sauvegarde du .env existant
if [ -f "$ENV_FILE" ]; then
    info "Sauvegarde du fichier .env existant..."
    cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)"
    log "Fichier .env sauvegardé"
fi

# Demander NVD_API_KEY
while true; do
    read -rp "Clé API NVD (laisser vide si absent) : " NVD_API_KEY
    if [ -z "$NVD_API_KEY" ]; then
        echo "  → Aucune clé NVD fournie (optionnel)"
        break
    fi
    if [ ${#NVD_API_KEY} -lt 10 ]; then
        echo "  → Clé trop courte. Vérifiez-la."
        continue
    fi
    break
done

# Demander MISTRAL_API_KEY
while true; do
    read -rp "Clé API Mistral (laisser vide si absent) : " MISTRAL_API_KEY
    if [ -z "$MISTRAL_API_KEY" ]; then
        echo "  → Aucune clé Mistral fournie (optionnel)"
        break
    fi
    if [ ${#MISTRAL_API_KEY} -lt 10 ]; then
        echo "  → Clé trop courte. Vérifiez-la."
        continue
    fi
    break
done

# Demander DB_USER
while true; do
    read -rp "Nom d'utilisateur MariaDB (obligatoire) : " DB_USER
    if [ -z "$DB_USER" ]; then
        echo "  → Obligatoire !"
        continue
    fi
    if ! [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "  → Caractères autorisés : lettres, chiffres, _"
        continue
    fi
    if [[ "$DB_USER" =~ ^(root|mysql|admin|mariadb)$ ]]; then
        echo "  → Nom réservé. Choisissez-en un autre."
        continue
    fi
    break
done

# Générer DB_PASSWORD
DB_PASSWORD=$(generate_password)
echo "  → Mot de passe généré pour $DB_USER"

# Valeurs par défaut
SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
MISTRAL_MODEL="mistral-large-latest"
DB_HOST="127.0.0.1"
DB_NAME="asset_vuln_manager"

echo ""
echo "========================================"
echo "  RÉSUMÉ DE LA CONFIGURATION"
echo "========================================"
echo ""
echo "  SERVER_IP       : $SERVER_IP"
echo "  DB_HOST         : $DB_HOST"
echo "  DB_PORT         : $DB_PORT"
echo "  DB_NAME         : $DB_NAME"
echo "  DB_USER         : $DB_USER"
echo "  DB_PASSWORD     : $DB_PASSWORD"
echo "  NVD_API_KEY     : ${NVD_API_KEY:-non configurée}"
echo "  MISTRAL_API_KEY : ${MISTRAL_API_KEY:-non configurée}"
echo ""

read -rp "Confirmer cette configuration ? (o/N) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oOyY]$ ]]; then
    error "Installation annulée" "Modifiez les valeurs et relancez" $ERROR_LEVEL_CRITICAL
fi

# Test des clés API
if [ -n "$NVD_API_KEY" ]; then
    read -rp "Tester la clé NVD ? (o/N) : " TEST_NVD
    if [[ "$TEST_NVD" =~ ^[oOyY]$ ]]; then
        if curl -s -I "https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=$NVD_API_KEY" | grep -q "200 OK"; then
            log "Clé API NVD valide"
        else
            warn "Clé API NVD invalide ou problème de connexion"
        fi
    fi
fi

if [ -n "$MISTRAL_API_KEY" ]; then
    read -rp "Tester la clé Mistral ? (o/N) : " TEST_MISTRAL
    if [[ "$TEST_MISTRAL" =~ ^[oOyY]$ ]]; then
        if curl -s -I "https://api.mistral.ai/v1/models" -H "Authorization: Bearer $MISTRAL_API_KEY" | grep -q "200 OK"; then
            log "Clé API Mistral valide"
        else
            warn "Clé API Mistral invalide ou problème de connexion"
        fi
    fi
fi

# Créer le fichier .env
info "Création du fichier .env..."
cat > "$ENV_FILE" << EOF
# Généré par install.sh - $(date '+%Y-%m-%d %H:%M:%S')
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
cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)"
log "Fichier .env créé"

ask_continue

# =============================================================================
# ÉTAPE 4: INSTALLATION DE LA BASE DE DONNÉES ET DE L'APPLICATION
# =============================================================================
step_header 4 5 "Installation de la base de données et de l'application"

# Création de la base et de l'utilisateur (avec sudo pour root)
run_with_spinner "Création de la base $DB_NAME" "sudo mariadb --port=$DB_PORT -e \"CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;\""
if [ $? -ne 0 ]; then
    error "Échec de la création de la base ou de l'utilisateur" "Vérifiez les permissions MariaDB" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Base et utilisateur créés"

# Import du schéma
SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
    error "Fichier schema.sql introuvable" "Vérifiez le dépôt" $ERROR_LEVEL_CRITICAL
fi

run_with_spinner "Import du schéma SQL" "mariadb --port=$DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME < \"$SCHEMA_FILE\""
if [ $? -ne 0 ]; then
    error "Échec de l'import du schéma SQL" "Vérifiez le fichier sql/schema.sql" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Schéma importé"

# Création du virtualenv
run_with_spinner "Création du virtualenv Python" "python3 -m venv \"$INSTALL_DIR/venv\""
if [ $? -ne 0 ]; then
    error "Échec de la création du virtualenv" "Vérifiez python3-venv" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Virtualenv créé"

# Installation des dépendances Python
run_with_spinner "Mise à jour de pip" "$INSTALL_DIR/venv/bin/pip install --upgrade pip"
if [ $? -ne 0 ]; then
    error "Échec de la mise à jour de pip" "" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "pip mis à jour"

run_with_spinner "Installation des dépendances Python" "$INSTALL_DIR/venv/bin/pip install -r \"$INSTALL_DIR/requirements.txt\""
if [ $? -ne 0 ]; then
    error "Échec de l'installation des dépendances Python" "Vérifiez requirements.txt" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Dépendances Python installées"

# Configuration du service systemd
info "Configuration du service systemd..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
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

run_with_spinner "Rechargement de systemd" "systemctl daemon-reload"
if [ $? -ne 0 ]; then
    error "Échec du rechargement de systemd" "Vérifiez les permissions" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "systemd rechargé"

run_with_spinner "Activation du service" "systemctl enable $SERVICE_NAME"
if [ $? -ne 0 ]; then
    error "Échec de l'activation du service" "" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Service activé"

run_with_spinner "Démarrage du service" "systemctl start $SERVICE_NAME"
if [ $? -ne 0 ]; then
    error "Échec du démarrage du service" "Vérifiez : journalctl -u $SERVICE_NAME -n 30" $ERROR_LEVEL_ERROR
    ask_continue
fi
log "Service démarré"

# Attendre que FastAPI soit prêt
info "Attente que FastAPI soit opérationnel..."
RETRIES=0
MAX_RETRIES=30
while ! curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    RETRIES=$((RETRIES+1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        error "FastAPI ne répond pas après $((MAX_RETRIES * 2)) secondes" "Vérifiez : journalctl -u $SERVICE_NAME -n 50" $ERROR_LEVEL_ERROR
        ask_continue
        break
    fi
    sleep 2
    printf "\r${CYAN}  → Attente... ($RETRIES/$MAX_RETRIES)${NC}"
done
if [ "$RETRIES" -lt "$MAX_RETRIES" ]; then
    echo ""
    log "FastAPI opérationnel"
fi

# Ajout au PATH
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

info "Exécution des vérifications..."
VERIFICATION_RESULTS=()

run_verification() {
    local cmd_name="$1"
    local cmd="$2"
    echo -n "  → Vérification: $cmd_name..."
    if eval "$cmd" >> "$VERBOSE_LOG" 2>&1; then
        echo -e " ${GREEN}✓${NC}"
        VERIFICATION_RESULTS+=("✓ $cmd_name")
        return 0
    else
        echo -e " ${RED}✗${NC}"
        error "Échec de $cmd_name" "Vérifiez les services" $ERROR_LEVEL_ERROR
        VERIFICATION_RESULTS+=("✗ $cmd_name")
        return 1
    fi
}

run_verification "asset-manager status" "bash \"$SCRIPTS_DIR/asset-manager.sh\" status"
run_verification "asset-manager sys ports" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys ports"
run_verification "asset-manager sys check-db" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-db"
run_verification "asset-manager sys check-env" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-env"
run_verification "asset-manager db check" "bash \"$SCRIPTS_DIR/asset-manager.sh\" db check"

ask_continue

# =============================================================================
# CRÉATION DU FICHIER INSTALL_INFO.TXT
# =============================================================================
info "Création du fichier INSTALL_INFO.txt..."

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_MIN=$((ELAPSED / 60))
ELAPSED_SEC=$((ELAPSED % 60))

cat > "$INSTALL_DIR/INSTALL_INFO.txt" << EOF
=================================================================
INFORMATIONS D'INSTALLATION - $(date '+%Y-%m-%d %H:%M:%S')
=================================================================

FastAPI URL: http://$SERVER_IP:8000
API Docs:    http://$SERVER_IP:8000/docs

MariaDB:
  Host: $DB_HOST
  Port: $DB_PORT
  Base: $DB_NAME
  User: $DB_USER
  Pass: $DB_PASSWORD

Fichier .env: $ENV_FILE
Logs:        $INSTALL_DIR/logs/
Install log: $LOG_FILE
Verbose log: $VERBOSE_LOG

Temps: ${ELAPSED_MIN}m${ELAPSED_SEC}s

Commandes utiles:
  systemctl status $SERVICE_NAME
  journalctl -u $SERVICE_NAME -f
  asset-manager status
  tail -f $LOG_FILE

=================================================================
EOF

log "Fichier INSTALL_INFO.txt créé"

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

# Nettoyage final
if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
    kill "$SPINNER_PID" 2>/dev/null
fi