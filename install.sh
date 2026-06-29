#!/bin/bash

# =============================================================================
# install_user_friendly.sh — Script d'installation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 7.0.0 (NE S'ARRÊTE JAMAIS - Gestion d'erreur ultra-tolérante)
# Description : Installe et configure AirGappedCVE sur Ubuntu Server
# Usage: sudo bash install.sh [--test-mode]
# =============================================================================

# =============================================================================
# CONFIGURATION GLOBALE (NE PAS CHANGER)
# =============================================================================

# Désactiver set -e pour éviter les arrêts automatiques
# On gère manuellement les erreurs avec des codes de retour
set -uo pipefail  # Garde pipefail pour les pipes, mais pas -e

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

# =============================================================================
# INITIALISATION DES LOGS (AVANT TOUTE OPÉRATION)
# =============================================================================

# Créer le dossier des logs AVANT toute opération
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$INSTALL_DIR" 2>/dev/null || true

# Initialiser les fichiers de log (avec || true pour éviter les arrêts)
> "$VERBOSE_LOG" 2>/dev/null || true
> "$LOG_FILE" 2>/dev/null || true

# =============================================================================
# FONCTIONS DE LOG (tolérantes aux erreurs)
# =============================================================================

log() {
    echo -e "${GREEN}[✓]${NC}  $1" 2>/dev/null || echo "[✓] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$VERBOSE_LOG" 2>/dev/null || true
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

    echo -e "$level_str $1" | tee -a "$VERBOSE_LOG" 2>/dev/null || echo "$level_str $1"
    [ -n "${2:-}" ] && echo -e "         ${YELLOW}→ $2${NC}" | tee -a "$VERBOSE_LOG" 2>/dev/null || echo "         ${YELLOW}→ $2${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] $1" >> "$LOG_FILE" 2>/dev/null || true
    [ -n "${2:-}" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] Solution: $2" >> "$LOG_FILE" 2>/dev/null || true

    if [ "$level" -eq "$ERROR_LEVEL_CRITICAL" ]; then
        echo ""
        echo -e "${RED}${BOLD}❌ Installation arrêtée à cause d'une erreur critique.${NC}"
        echo "Détails dans $VERBOSE_LOG"
        exit 1
    fi
    # NE PAS S'ARRÊTER POUR LES AUTRES ERREURS
}

warn() {
    echo -e "${YELLOW}[~]${NC}   $1" 2>/dev/null || echo "[~] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$LOG_FILE" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$VERBOSE_LOG" 2>/dev/null || true
}

info() {
    echo -e "${CYAN}[~]${NC}   $1" 2>/dev/null || echo "[~] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$LOG_FILE" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $1" >> "$VERBOSE_LOG" 2>/dev/null || true
}

header() {
    echo "" 2>/dev/null || true
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" 2>/dev/null || echo "=============================================================================="
    echo -e "${BLUE}${BOLD}  $1${NC}" 2>/dev/null || echo "  $1"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" 2>/dev/null || echo "=============================================================================="
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$LOG_FILE" 2>/dev/null || true
}

step_header() {
    local step_num=$1
    local step_name="$2"
    local total_steps=$3
    echo "" 2>/dev/null || true
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" 2>/dev/null || echo "=============================================================================="
    echo -e "${BLUE}${BOLD}  Étape ${step_num}/${total_steps} — ${step_name}${NC}" 2>/dev/null || echo "  Étape ${step_num}/${total_steps} — ${step_name}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}" 2>/dev/null || echo "=============================================================================="
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [STEP] Étape ${step_num}/${total_steps}: ${step_name}" >> "$LOG_FILE" 2>/dev/null || true
}

# =============================================================================
# FONCTIONS UTILITAIRES (tolérantes aux erreurs)
# =============================================================================

ask_continue() {
    if [ $ERRORS -gt 0 ]; then
        echo "" 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}⚠️  $ERRORS erreur(s) détectée(s)${NC}"
        echo "Détails dans $VERBOSE_LOG"
        echo "" 2>/dev/null || true
        read -t 30 -rp "Voulez-vous continuer l'installation ? (o/N) : " CONTINUE
        if [[ ! "$CONTINUE" =~ ^[oOyY]$ ]]; then
            error "Installation annulée par l'utilisateur" "Corrigez les erreurs et relancez le script" $ERROR_LEVEL_CRITICAL
        fi
        echo "" 2>/dev/null || true
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
# DÉTECTION MARIADB (basée sur le port 3306)
# =============================================================================

is_port_3306_used() {
    ss -tunlp | grep -q ":3306" 2>/dev/null || false
}

get_service_on_port() {
    local port="$1"
    ss -tunlp | grep ":$port " | awk '{print $7}' | cut -d'=' -f2 | tr -d ',' | xargs 2>/dev/null || echo ""
}

# =============================================================================
# GESTION DES CONFLITS DE PORT (ultra-tolérante)
# =============================================================================

handle_port_3306_conflict() {
    local port=3306
    
    if ! is_port_3306_used; then
        DB_PORT=$port
        return 0
    fi
    
    local service_on_port
    service_on_port=$(get_service_on_port $port)
    
    echo "" 2>/dev/null || true
    echo "Un service écoute sur le port $port: $service_on_port"
    echo "Choix disponibles:"
    echo "  1) Supprimer le service actuel et installer MariaDB sur le port $port"
    echo "  2) Laisser le service en place et installer MariaDB sur le port $DB_PORT_ALT"
    echo "  3) Annuler"
    
    read -t 30 -rp "Votre choix [1-3] : " db_choice
    
    if [ -z "$db_choice" ]; then
        db_choice=1
        echo "1"
    fi
    
    case "$db_choice" in
        1)
            # Arrêter le service actuel (si valide)
            if [ -n "$service_on_port" ] && [[ "$service_on_port" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                info "Arrêt du service $service_on_port..."
                systemctl stop "$service_on_port" >> "$VERBOSE_LOG" 2>&1 || warn "Échec de l'arrêt de $service_on_port (ignoré)"
                systemctl disable "$service_on_port" >> "$VERBOSE_LOG" 2>&1 || warn "Échec du désactivation de $service_on_port (ignoré)"
            else
                warn "Nom de service invalide: $service_on_port (ne peut pas être arrêté, ignoré)"
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
            error "Choix invalide" "Veuillez entrer 1, 2 ou 3" $ERROR_LEVEL_ERROR
            return 1
            ;;
    esac
    
    return 0
}

# =============================================================================
# VÉRIFICATION ROOT (seule erreur critique)
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}${BOLD}[ERREUR CRITIQUE]${NC}" 2>/dev/null || echo "[ERREUR CRITIQUE]"
    echo -e "Ce script doit être lancé en root." 2>/dev/null || echo "Ce script doit être lancé en root."
    echo -e "${YELLOW}→ Relancez avec : sudo bash $0${NC}" 2>/dev/null || echo "→ Relancez avec : sudo bash $0"
    exit 1
fi

# =============================================================================
# ASCII ART DE BIENVENUE
# =============================================================================
echo -e "${PURPLE}" 2>/dev/null || echo ""
echo "  AirGappedCVE - Gestion de vulnérabilités en environnement isolé"
echo -e "${NC}" 2>/dev/null || echo ""

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES (toutes les erreurs sont non-critiques)
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
    
    declare -A CMD_TO_PKG=(
        [curl]="curl"
        [wget]="wget"
        [git]="git"
        [bc]="bc"
        [ss]="iproute2"
        [pgrep]="procps"
        [add-apt-repository]="software-properties-common"
    )
    
    info "Mise à jour APT..."
    apt-get update -qq >> "$VERBOSE_LOG" 2>&1 || warn "Échec de la mise à jour APT (continué)"
    log "Mise à jour APT terminée"
    
    for cmd in "${MISSING_COMMANDS[@]}"; do
        local pkg="${CMD_TO_PKG[$cmd]}"
        info "Installation de $pkg (pour $cmd)..."
        apt-get install -y -qq "$pkg" >> "$VERBOSE_LOG" 2>&1 || warn "Échec de l'installation de $pkg (continué)"
        log "$pkg installé"
    done
else
    info "Toutes les commandes requises sont disponibles"
fi

# 2. Espace disque
MIN_SPACE_GB=5
AVAILABLE_SPACE_KB=$(df /opt --output=avail | tail -1 2>/dev/null || echo "0")
AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
if [ "$AVAILABLE_SPACE_GB" -lt "$MIN_SPACE_GB" ]; then
    warn "Espace disque insuffisant sur /opt (${AVAILABLE_SPACE_GB}GB disponibles, ${MIN_SPACE_GB}GB requis)"
else
    info "Espace disque suffisant (${AVAILABLE_SPACE_GB}GB sur /opt)"
fi

# 3. Mémoire
MIN_RAM_MB=2048
TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")
if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ] 2>/dev/null; then
    warn "Mémoire insuffisante (${TOTAL_RAM_MB}MB détectés, ${MIN_RAM_MB}MB requis)"
else
    info "Mémoire suffisante (${TOTAL_RAM_MB}MB)"
fi

# 4. Architecture
ARCH=$(uname -m 2>/dev/null || echo "inconnu")
info "Architecture $ARCH détectée"

# 5. Connexion internet
if command_exists "ping" && ping -c 1 -W 2 github.com > /dev/null 2>&1; then
    info "Connexion internet active"
else
    warn "Pas de connexion internet (certaines étapes peuvent échouer)"
fi

# 6. Ports
info "Vérification des ports..."
if ss -tunlp | grep -q ":8000" 2>/dev/null; then
    warn "Port 8000 occupé (continué)"
fi

# 7. Détection du port MariaDB
info "Détection de MariaDB..."
DB_PORT=$DB_PORT_DEFAULT

if is_port_3306_used; then
    info "Le port 3306 est utilisé (MariaDB ou autre service)"
    handle_port_3306_conflict
else
    info "Le port 3306 est libre"
fi

# 8. Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2 || echo "0.0")
if [ "$(printf '%s\n%s' "3.10" "$PYTHON_VERSION" | sort -V | head -1)" != "3.10" ]; then
    warn "Python $PYTHON_VERSION détecté (Python 3.10+ recommandé)"
else
    info "Python $PYTHON_VERSION détecté"
fi

# 9. Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release 2>/dev/null || true
    info "Distribution: ${ID:-inconnue} ${VERSION_ID:-}"
else
    warn "Distribution non détectée"
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
apt-get update -qq >> "$VERBOSE_LOG" 2>&1 || warn "Mise à jour APT échouée (continué)"
log "Mise à jour APT terminée"

info "Mise à niveau des paquets..."
apt-get upgrade -y -qq >> "$VERBOSE_LOG" 2>&1 || warn "Mise à niveau échouée (continué)"
log "Système à jour"

ask_continue

# =============================================================================
# ÉTAPE 1B: INSTALLATION DE MARIADB
# =============================================================================
step_header "1B" 5 "Installation de MariaDB sur le port $DB_PORT"

info "Installation de MariaDB..."
apt-get install -y -qq mariadb-server mariadb-client >> "$VERBOSE_LOG" 2>&1 || warn "Installation de MariaDB échouée (continué)"
log "MariaDB installé"

# Configuration du port si nécessaire
if [ "$DB_PORT" != "$DB_PORT_DEFAULT" ]; then
    info "Configuration du port $DB_PORT..."
    sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/mariadb.conf.d/50-server.cnf 2>/dev/null || warn "Échec de la modification du port (continué)"
    [ -f /etc/mysql/my.cnf ] && sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/my.cnf 2>/dev/null || true
    log "Port configuré"
fi

# Démarrage de MariaDB
info "Démarrage de MariaDB..."
systemctl enable mariadb >> "$VERBOSE_LOG" 2>&1 || warn "Activation de MariaDB échouée (continué)"
systemctl start mariadb >> "$VERBOSE_LOG" 2>&1 || warn "Démarrage de MariaDB échoué (continué)"
log "MariaDB démarré"

# Attendre que le port 3306 soit utilisé
info "Attente que MariaDB soit opérationnel sur le port $DB_PORT..."
RETRIES=0
MAX_RETRIES=30
while ! is_port_3306_used; do
    RETRIES=$((RETRIES+1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        warn "MariaDB ne répond pas après $((MAX_RETRIES * 2)) secondes (continué)"
        break
    fi
    sleep 2
    printf "\r${CYAN}  → Attente... ($RETRIES/$MAX_RETRIES)${NC}"
done
if [ "$RETRIES" -lt "$MAX_RETRIES" ]; then
    echo ""
    log "MariaDB opérationnel sur le port $DB_PORT"
fi

# Sécurisation de MariaDB (on est root)
info "Sécurisation de MariaDB..."
mariadb -u root -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;" >> "$VERBOSE_LOG" 2>&1 || warn "Sécurisation de MariaDB échouée (continué)"
log "MariaDB sécurisé"

ask_continue

# =============================================================================
# ÉTAPE 2: CLONE DU PROJET (avec gestion du dossier existant)
# =============================================================================
step_header 2 5 "Clone du projet AirGappedCVE"

# Supprimer le dossier s'il existe
if [ -d "$INSTALL_DIR" ]; then
    info "Suppression du dossier existant $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR" 2>/dev/null || warn "Échec de la suppression du dossier (continué)"
    log "Dossier existant supprimé"
fi

# Créer le dossier
mkdir -p "$INSTALL_DIR" 2>/dev/null || warn "Échec de la création du dossier (continué)"

# Cloner le dépôt
info "Clonage du dépôt..."
git clone "$REPO_URL" "$INSTALL_DIR" >> "$VERBOSE_LOG" 2>&1 || warn "Clonage échoué (continué)"
log "Dépôt cloné"

# Vérification
if [ ! -f "$INSTALL_DIR/main.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
    warn "Dépôt incomplet (continué)"
else
    log "Dépôt vérifié"
fi

# Nettoyage
rm -rf "$INSTALL_DIR/.devcontainer" 2>/dev/null || warn "Nettoyage échoué (continué)"
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/documents" "$INSTALL_DIR/backups" 2>/dev/null || warn "Création des dossiers échouée (continué)"
chmod 750 "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/backups" 2>/dev/null || warn "Chmod échoué (continué)"
log "Dossiers créés"

ask_continue

# =============================================================================
# ÉTAPE 3: CONFIGURATION ENVIRONNEMENT
# =============================================================================
step_header 3 5 "Configuration des variables d'environnement"

# Sauvegarde .env
if [ -f "$ENV_FILE" ]; then
    cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || warn "Sauvegarde .env échouée (continué)"
    log ".env sauvegardé"
fi

# Demander les infos
read -t 30 -rp "Clé API NVD (optionnel, appuyer sur Entrée pour ignorer) : " NVD_API_KEY
read -t 30 -rp "Clé API Mistral (optionnel, appuyer sur Entrée pour ignorer) : " MISTRAL_API_KEY

while true; do
    read -t 30 -rp "Utilisateur MariaDB (obligatoire) : " DB_USER
    if [ -z "$DB_USER" ]; then
        echo "  → Obligatoire !"
        continue
    fi
    if ! [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "  → Caractères invalides (lettres, chiffres, _)"
        continue
    fi
    if [[ "$DB_USER" =~ ^(root|mysql|admin|mariadb)$ ]]; then
        echo "  → Nom réservé"
        continue
    fi
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
read -t 30 -rp "Confirmer ? (o/N) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oOyY]$ ]]; then
    error "Annulé" "" $ERROR_LEVEL_CRITICAL
fi

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
chmod 600 "$ENV_FILE" 2>/dev/null || warn "chmod .env échoué (continué)"
log ".env créé"

ask_continue

# =============================================================================
# ÉTAPE 4: INSTALLATION APPLICATION
# =============================================================================
step_header 4 5 "Installation de l'application"

# Création base et utilisateur
info "Création de la base $DB_NAME..."
mariadb -u root -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;" >> "$VERBOSE_LOG" 2>&1 || warn "Création base échouée (continué)"
log "Base et utilisateur créés"

# Import schéma
SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
    warn "schema.sql introuvable (continué)"
else
    info "Import du schéma..."
    mariadb -u $DB_USER -p$DB_PASSWORD $DB_NAME < "$SCHEMA_FILE" >> "$VERBOSE_LOG" 2>&1 || warn "Import schéma échoué (continué)"
    log "Schéma importé"
fi

# Virtualenv
info "Création du virtualenv..."
python3 -m venv "$INSTALL_DIR/venv" >> "$VERBOSE_LOG" 2>&1 || warn "Création virtualenv échouée (continué)"
log "Virtualenv créé"

# Dépendances Python
info "Installation des dépendances Python..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip >> "$VERBOSE_LOG" 2>&1 || warn "Mise à jour pip échouée (continué)"
log "pip mis à jour"

"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" >> "$VERBOSE_LOG" 2>&1 || warn "Installation dépendances échouée (continué)"
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

systemctl daemon-reload >> "$VERBOSE_LOG" 2>&1 || warn "Rechargement systemd échoué (continué)"
log "systemd rechargé"

systemctl enable $SERVICE_NAME >> "$VERBOSE_LOG" 2>&1 || warn "Activation service échouée (continué)"
log "Service activé"

systemctl start $SERVICE_NAME >> "$VERBOSE_LOG" 2>&1 || warn "Démarrage service échoué (continué)"
log "Service démarré"

# Attente FastAPI
info "Attente FastAPI..."
RETRIES=0
while ! curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    RETRIES=$((RETRIES+1))
    if [ "$RETRIES" -ge 30 ]; then
        warn "FastAPI ne répond pas après 60 secondes (continué)"
        break
    fi
    sleep 2
    printf "\r${CYAN}  → Attente... ($RETRIES/30)${NC}"
done
if [ "$RETRIES" -lt 30 ]; then
    echo ""
    log "FastAPI opérationnel"
fi

# PATH
info "Ajout au PATH..."
cat > "$PATH_FILE" << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF
chmod +x "$PATH_FILE" "$SCRIPTS_DIR/asset-manager.sh" 2>/dev/null || warn "chmod PATH échoué (continué)"
export PATH="$PATH:$SCRIPTS_DIR" 2>/dev/null || true
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
        warn "Vérification $cmd échouée (continué)"
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
    echo -e "${YELLOW}${BOLD}⚠️  $ERRORS erreur(s) détectée(s) mais installation continuée${NC}"
fi

echo ""
echo "FastAPI: http://$SERVER_IP:8000"
echo "MariaDB: $DB_HOST:$DB_PORT (user: $DB_USER)"
echo "Logs: $LOG_FILE / $VERBOSE_LOG"
echo "Temps: ${ELAPSED_MIN}m"

echo ""
echo "Toutes les erreurs ont été ignorées. Vérifiez $VERBOSE_LOG pour les détails."
