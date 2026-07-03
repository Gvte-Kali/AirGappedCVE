#!/bin/bash
# =============================================================================
# Script de configuration pour AirGappedCVE
# Auteur : KaliGvte
# Version : 1.0.0
# Description : Crée le virtualenv, installe les dépendances, configure la BDD,
#               configure le service systemd, ajoute la commande au PATH et vérifie FastAPI.
# =============================================================================

set -euo pipefail

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
LOG_FILE="$INSTALL_DIR/installation.log"
VERBOSE_LOG="/tmp/asset-manager-setup.log"
SERVICE_NAME="asset-manager"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
SCRIPT_PATH="$INSTALL_DIR/scripts/asset-manager.sh"
SYMLINK_PATH="/usr/local/bin/asset-manager"
FASTAPI_PORT=8000

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Compteur d'erreurs
ERRORS=0
declare -a ERROR_MESSAGES=()

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

# Affiche un spinner pendant l'exécution d'une commande
run_with_spinner() {
    local msg="$1"
    local cmd="$2"
    printf "  ${CYAN}⠋ %s${NC}\r" "$msg"
    (
        trap '' SIGINT
        eval "$cmd" > /tmp/spinner_output 2>&1 &
        local pid=$!
        local spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        local i=0
        while kill -0 "$pid" 2>/dev/null; do
            i=$(( (i+1) % ${#spinner_chars} ))
            printf "  ${CYAN}${spinner_chars:$i:1} %s${NC}\r" "$msg"
            sleep 0.1
        done
        wait "$pid"
    )
    local exit_code=$?
    printf "  ${CYAN}✓ %s${NC}\n" "$msg"
    if [ $exit_code -ne 0 ]; then
        ERRORS=$((ERRORS+1))
        ERROR_MESSAGES+=("Échec: $msg. Sortie: $(cat /tmp/spinner_output)")
        return 1
    else
        cat /tmp/spinner_output >> "$VERBOSE_LOG"
        return 0
    fi
}

# Affiche un message de log
log() {
    local msg="$1"
    echo -e "${GREEN}[✓]${NC} $msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $msg" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $msg" >> "$VERBOSE_LOG"
}

# Affiche un message d'erreur
error() {
    local msg="$1"
    ERRORS=$((ERRORS+1))
    ERROR_MESSAGES+=("$msg")
    echo -e "${RED}[✗]${NC} $msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERREUR] $msg" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERREUR] $msg" >> "$VERBOSE_LOG"
}

# Affiche un message d'information
info() {
    local msg="$1"
    echo -e "${BLUE}[i]${NC} $msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $msg" >> "$VERBOSE_LOG"
}

# Affiche un en-tête de section
header() {
    local msg="$1"
    echo ""
    echo -e "${BOLD}${CYAN}==============================================================================${NC}"
    echo -e "${BOLD}${CYAN}  $msg${NC}"
    echo -e "${BOLD}${CYAN}==============================================================================${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $msg" >> "$VERBOSE_LOG"
}

# Demande à l'utilisateur s'il veut continuer après une erreur
ask_continue() {
    if [ $ERRORS -gt 0 ]; then
        echo ""
        echo -e "${RED}⚠️  $ERRORS erreur(s) détectée(s):${NC}"
        for err in "${ERROR_MESSAGES[@]}"; do
            echo -e "  ${RED}- $err${NC}"
        done
        read -rp "Voulez-vous continuer ? (o/N) : " choice
        if [[ ! "$choice" =~ ^[oOyY]$ ]]; then
            echo -e "${RED}Configuration annulée.${NC}"
            exit 1
        fi
        ERRORS=0
        ERROR_MESSAGES=()
    fi
}

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================
header "Vérifications préliminaires"

# Créer les fichiers de log
mkdir -p "$INSTALL_DIR" /tmp 2>/dev/null
> "$LOG_FILE"
> "$VERBOSE_LOG"

# Vérifier que le dossier d'installation existe
if [ ! -d "$INSTALL_DIR" ]; then
    error "Le dossier $INSTALL_DIR n'existe pas. Exécutez d'abord le script d'installation."
    exit 1
fi
log "Dossier $INSTALL_DIR trouvé."

# Vérifier que .env existe
if [ ! -f "$INSTALL_DIR/.env" ]; then
    error "Le fichier $INSTALL_DIR/.env est introuvable. Copiez .env.example et configurez-le."
    exit 1
fi
log "Fichier .env trouvé."

# Charger les variables d'environnement
source "$INSTALL_DIR/.env"
export DB_USER DB_PASSWORD DB_NAME DB_HOST DB_PORT
log "Variables d'environnement chargées depuis .env."

# =============================================================================
# CRÉATION DU VIRTUALENV ET INSTALLATION DES DÉPENDANCES
# =============================================================================
header "Création du virtualenv et installation des dépendances"

run_with_spinner "Création du virtualenv" \
    "python3 -m venv $INSTALL_DIR/venv"
ask_continue

run_with_spinner "Activation du virtualenv et mise à jour de pip" \
    "source $INSTALL_DIR/venv/bin/activate && pip install --upgrade pip"
ask_continue

run_with_spinner "Installation des dépendances depuis requirements.txt" \
    "source $INSTALL_DIR/venv/bin/activate && pip install -r $INSTALL_DIR/requirements.txt"
ask_continue

# Vérification des dépendances critiques
info "Vérification des dépendances critiques..."
source "$INSTALL_DIR/venv/bin/activate"
for pkg in fastapi pymysql reportlab uvicorn python-dotenv; do
    if pip show "$pkg" > /dev/null 2>&1; then
        log "Dépendance $pkg installée."
    else
        error "Dépendance $pkg manquante."
    fi
done
ask_continue

# =============================================================================
# CONFIGURATION DE LA BASE DE DONNÉES
# =============================================================================
header "Configuration de la base de données"

run_with_spinner "Exécution de setup_database.py" \
    "$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/setup_database.py"
ask_continue

# Test de connexion à MariaDB
info "Test de connexion à MariaDB..."
if mariadb -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1;" > /dev/null 2>&1; then
    log "Connexion à MariaDB réussie."
else
    error "Échec de la connexion à MariaDB. Vérifiez DB_USER, DB_PASSWORD, DB_HOST et DB_PORT dans .env."
    ask_continue
fi

# =============================================================================
# CONFIGURATION DU SERVICE SYSTEMD
# =============================================================================
header "Configuration du service systemd"

# Copier le fichier de service
if [ -f "$INSTALL_DIR/$SERVICE_NAME.service" ]; then
    run_with_spinner "Copie du fichier de service systemd" \
        "cp $INSTALL_DIR/$SERVICE_NAME.service $SERVICE_FILE"
else
    error "Fichier $INSTALL_DIR/$SERVICE_NAME.service introuvable."
    ask_continue
fi

run_with_spinner "Rechargement de systemd" \
    "systemctl daemon-reload"
ask_continue

run_with_spinner "Activation et démarrage du service $SERVICE_NAME" \
    "systemctl enable --now $SERVICE_NAME"
ask_continue

# Afficher le statut du service
info "Statut du service $SERVICE_NAME :"
systemctl status "$SERVICE_NAME" --no-pager
echo ""

# =============================================================================
# AJOUT DE LA COMMANDE AU PATH
# =============================================================================
header "Ajout de la commande 'asset-manager' au PATH"

if [ -f "$SCRIPT_PATH" ]; then
    run_with_spinner "Création du lien symbolique pour asset-manager" \
        "ln -sf $SCRIPT_PATH $SYMLINK_PATH && chmod +x $SYMLINK_PATH"
else
    error "Script $SCRIPT_PATH introuvable."
    ask_continue
fi
log "Lien symbolique $SYMLINK_PATH créé."

# =============================================================================
# VÉRIFICATION DE FASTAPI
# =============================================================================
header "Vérification de FastAPI"

run_with_spinner "Démarrage de FastAPI via asset-manager" \
    "asset-manager fastapi start"
ask_continue

info "Attente de 10 secondes pour que FastAPI démarre..."
sleep 10

info "Test du endpoint /health..."
if curl -sf "http://localhost:$FASTAPI_PORT/health" > /dev/null 2>&1; then
    log "FastAPI est opérationnel sur http://localhost:$FASTAPI_PORT."
else
    error "FastAPI ne répond pas. Vérifiez les logs avec : journalctl -u $SERVICE_NAME -n 50"
    ask_continue
fi

# =============================================================================
# RÉSUMÉ
# =============================================================================
header "Configuration terminée"

echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  ✅ Configuration terminée avec succès !${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo -e "${BOLD}Prochaines étapes:${NC}"
echo "  1. Vérifiez les logs de FastAPI avec : journalctl -u $SERVICE_NAME -f"
echo "  2. Testez l'API avec : curl http://localhost:$FASTAPI_PORT/docs"
echo "  3. Accédez à l'interface web (si configurée)."
echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  - Logs principaux : $LOG_FILE"
echo "  - Logs détaillés : $VERBOSE_LOG"