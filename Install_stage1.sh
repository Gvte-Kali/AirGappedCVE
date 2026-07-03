#!/bin/bash
# =============================================================================
# Script d'installation pour AirGappedCVE
# Auteur : KaliGvte
# Version : 1.0.0
# Description : Installe les dépendances, configure MariaDB, clone le dépôt et prépare l'environnement.
# =============================================================================

set -euo pipefail

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
LOG_FILE="$INSTALL_DIR/installation.log"
VERBOSE_LOG="/tmp/asset-manager-installation.log"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"
USERNAME=$(whoami)

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Compteur d'erreurs
ERRORS=0
declare -a ERROR_MESSAGES=()

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

# Affiche un spinner pendant l'exécution d'une commande
# Usage: run_with_spinner "Message" "commande"
run_with_spinner() {
    local msg="$1"
    local cmd="$2"
    printf "  ${CYAN}⠋ %s${NC}\r" "$msg"
    local pid
    (
        trap '' SIGINT
        eval "$cmd" > /tmp/spinner_output 2>&1 &
        pid=$!
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
            echo -e "${RED}Installation annulée.${NC}"
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

# Créer les dossiers de log
mkdir -p "$INSTALL_DIR" /tmp 2>/dev/null
> "$LOG_FILE"
> "$VERBOSE_LOG"

# Vérifier les droits root
if [ "$(id -u)" -ne 0 ]; then
    error "Ce script doit être exécuté en tant que root (sudo)."
    exit 1
fi
log "Script exécuté en tant que root."

# Vérifier la connexion internet
if ! ping -c 1 github.com > /dev/null 2>&1; then
    error "Pas de connexion internet. Impossible de cloner le dépôt."
    ask_continue
fi
log "Connexion internet active."

# =============================================================================
# MISE À JOUR DES DÉPÔTS ET INSTALLATION DES OUTILS
# =============================================================================
header "Mise à jour du système et installation des dépendances"

run_with_spinner "Mise à jour des dépôts APT" "apt update -y"
ask_continue

run_with_spinner "Mise à niveau des paquets" "apt upgrade -y"
ask_continue

run_with_spinner "Installation des outils (curl, wget, git, etc.)" \
    "apt-get install -y curl wget git bc iproute2 procps software-properties-common python3-venv python3-pip python3-dev build-essential"
ask_continue

# =============================================================================
# INSTALLATION ET CONFIGURATION DE MARIADB
# =============================================================================
header "Installation et configuration de MariaDB"

run_with_spinner "Installation de MariaDB" \
    "apt-get install -y mariadb-server mariadb-client"
ask_continue

run_with_spinner "Activation et démarrage de MariaDB" \
    "systemctl enable --now mariadb"
ask_continue

info "Lancez 'sudo mariadb-secure-installation' manuellement après ce script pour sécuriser MariaDB."
info "Répondez 'n' à la question 'Switch to unix_socket authentication' pour conserver l'authentification par mot de passe."

# =============================================================================
# CONFIGURATION DU DOSSIER D'INSTALLATION
# =============================================================================
header "Configuration du dossier d'installation"

# Supprimer l'ancien dossier s'il existe
if [ -d "$INSTALL_DIR" ]; then
    run_with_spinner "Suppression de l'ancien dossier $INSTALL_DIR" \
        "rm -rf $INSTALL_DIR"
    ask_continue
fi

# Créer le dossier
run_with_spinner "Création du dossier $INSTALL_DIR" \
    "mkdir -p $INSTALL_DIR && chown $USERNAME:$USERNAME $INSTALL_DIR"
ask_continue

# =============================================================================
# CLONE DU DÉPÔT GIT
# =============================================================================
header "Clone du dépôt GitHub"

run_with_spinner "Clone du dépôt $REPO_URL" \
    "git clone $REPO_URL $INSTALL_DIR"
ask_continue

# =============================================================================
# CONFIGURATION DE L'ENVIRONNEMENT
# =============================================================================
header "Configuration de l'environnement"

run_with_spinner "Copie de .env.example vers .env" \
    "cd $INSTALL_DIR && [ -f .env.example ] && mv .env.example .env || echo '.env.example introuvable, création d un .env vide' && touch .env"
ask_continue

# =============================================================================
# RÉSUMÉ
# =============================================================================
header "Installation terminée"

echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  ✅ Installation terminée avec succès !${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo -e "${BOLD}Prochaines étapes:${NC}"
echo "  1. Exécutez 'sudo mariadb-secure-installation' pour sécuriser MariaDB."
echo "  2. Configurez le fichier .env dans $INSTALL_DIR."
echo "  3. Activez le virtualenv avec :"
echo "     cd $INSTALL_DIR"
echo "     python3 -m venv venv"
echo "     source venv/bin/activate"
echo "     pip install -r requirements.txt"
echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  - Logs principaux : $LOG_FILE"
echo "  - Logs détaillés : $VERBOSE_LOG"