#!/bin/bash
# =============================================================================
# Install_stage1.sh — Script d'installation pour AirGappedCVE (Étape 1)
# Auteur : KaliGvte
# Version : 1.0.0
# Description : Vérifications préliminaires, mise à jour du système, installation des dépendances, MariaDB, et clone du dépôt.
# =============================================================================

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
VERBOSE_LOG="/tmp/asset-manager-installation.log"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialiser le fichier de log avec les bonnes permissions
touch "$VERBOSE_LOG" 2>/dev/null || {
    echo -e "${RED}[✗] Impossible de créer $VERBOSE_LOG. Vérifiez les permissions.${NC}"
    exit 1
}
chmod 666 "$VERBOSE_LOG"

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

# Affiche un spinner pendant l'exécution d'une commande
spinner() {
    local msg="$1"
    local pid=$!
    local delay=0.1
    local spinner_chars="|/-\\"
    local i=0
    printf "  ${CYAN}%s${NC}\r" "${spinner_chars:$i:1} $msg"
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "  ${CYAN}%s${NC}\r" "${spinner_chars:$i:1} $msg"
        sleep "$delay"
    done
    printf "  ${GREEN}✓ %s${NC}\n" "$msg"
}

# Exécute une commande avec un spinner
run_with_spinner() {
    local msg="$1"
    shift
    printf "  ${CYAN}⠋ %s${NC}\r" "$msg"
    "$@" > /tmp/spinner_output 2>&1 &
    spinner "$msg" &
    wait $!
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "  ${RED}✗ $msg${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERREUR] $msg: $(cat /tmp/spinner_output)" >> "$VERBOSE_LOG"
        return 1
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $msg" >> "$VERBOSE_LOG"
        return 0
    fi
}

# Affiche un en-tête
header() {
    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$VERBOSE_LOG"
}

# Affiche un message d'erreur
error() {
    echo -e "${RED}[✗] $1${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERREUR] $1" >> "$VERBOSE_LOG"
}

# Affiche un message de succès
success() {
    echo -e "${GREEN}[✓] $1${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$VERBOSE_LOG"
}

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================
header "Vérifications préliminaires"

# Vérifier les droits root
if [ "$(id -u)" -ne 0 ]; then
    error "Ce script doit être exécuté en tant que root (sudo)."
    exit 1
fi
success "Script exécuté en tant que root."

# Vérifier l'espace disque
if [ "$(df /opt --output=avail | tail -1)" -lt 10000000 ]; then
    error "Espace disque insuffisant sur /opt (moins de 10GB)."
    exit 1
fi
success "Espace disque suffisant sur /opt."

# Vérifier la mémoire
if [ "$(free -m | awk '/Mem:/ {print $4}')" -lt 2000 ]; then
    error "Mémoire insuffisante (moins de 2GB)."
    exit 1
fi
success "Mémoire suffisante."

# Vérifier la connexion internet
if ! ping -c 1 github.com > /dev/null 2>&1; then
    error "Pas de connexion internet."
    exit 1
fi
success "Connexion internet active."

# Vérifier l'architecture
if [ "$(uname -m)" != "x86_64" ]; then
    error "Architecture non supportée (seul x86_64 est pris en charge)."
    exit 1
fi
success "Architecture x86_64 détectée."

# Vérifier les outils de base
for cmd in curl wget git; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        error "Outils manquant : $cmd."
        exit 1
    fi
done
success "Outils de base (curl, wget, git) disponibles."

# =============================================================================
# MISE À JOUR DU SYSTÈME
# =============================================================================
header "Mise à jour du système"

run_with_spinner "Mise à jour des dépôts APT" apt update -y
run_with_spinner "Mise à niveau des paquets" apt upgrade -y

# =============================================================================
# INSTALLATION DES DÉPENDANCES
# =============================================================================
header "Installation des dépendances"

run_with_spinner "Installation des outils système" \
    apt-get install -y curl wget git bc iproute2 procps software-properties-common

run_with_spinner "Installation des dépendances Python" \
    apt-get install -y python3-venv python3-pip python3-dev build-essential

# =============================================================================
# INSTALLATION DE MARIADB
# =============================================================================
header "Installation de MariaDB"

run_with_spinner "Installation de MariaDB" \
    apt-get install -y mariadb-server mariadb-client

run_with_spinner "Activation et démarrage de MariaDB" \
    systemctl enable --now mariadb

# =============================================================================
# CLONE DU DÉPÔT
# =============================================================================
header "Clone du dépôt GitHub"

# Supprimer l'ancien dossier s'il existe
if [ -d "$INSTALL_DIR" ]; then
    run_with_spinner "Suppression de l'ancien dossier $INSTALL_DIR" \
        rm -rf "$INSTALL_DIR"
fi

run_with_spinner "Création du dossier $INSTALL_DIR" \
    mkdir -p "$INSTALL_DIR"

run_with_spinner "Clone du dépôt $REPO_URL" \
    git clone "$REPO_URL" "$INSTALL_DIR"

# =============================================================================
# RÉSUMÉ
# =============================================================================
header "Installation de l'étape 1 terminée"

echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  ✅ Étape 1 terminée avec succès !${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo -e "Logs détaillés : $VERBOSE_LOG"
