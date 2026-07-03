#!/bin/bash
# =============================================================================
# install.sh — Script d'installation complet pour AirGappedCVE
# Auteur : KaliGvte
# Version : 1.0.0
# Description :
#   1. Vérifications préliminaires
#   2. Mise à jour du système et installation des dépendances
#   3. Clone du dépôt GitHub
#   4. Copie du .env local dans /opt/asset-manager/
#   5. Configuration complète (virtualenv, BDD, service systemd, FastAPI)
# =============================================================================

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
REPO_URL="https://github.com/Gvte-Kali/AirGappedCVE.git"
SERVICE_NAME="asset-manager"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
SCRIPT_PATH="$INSTALL_DIR/scripts/asset-manager.sh"
SYMLINK_PATH="/usr/local/bin/asset-manager"
FASTAPI_PORT=8000

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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
    "$@" > /dev/null 2>&1 &
    spinner "$msg" &
    wait $!
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "  ${RED}✗ $msg${NC}"
        return 1
    fi
    return 0
}

# Affiche un en-tête
header() {
    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

# Affiche un message de succès
success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# Affiche un message d'erreur
error() {
    echo -e "${RED}[✗] $1${NC}"
    exit 1
}

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================
header "Vérifications préliminaires"

# Vérifier les droits root
if [ "$(id -u)" -ne 0 ]; then
    error "Ce script doit être exécuté en tant que root (sudo)."
fi
success "Script exécuté en tant que root."

# Vérifier l'espace disque
if [ "$(df /opt --output=avail | tail -1)" -lt 10000000 ]; then
    error "Espace disque insuffisant sur /opt (moins de 10GB)."
fi
success "Espace disque suffisant sur /opt."

# Vérifier la mémoire
if [ "$(free -m | awk '/Mem:/ {print $4}')" -lt 2000 ]; then
    error "Mémoire insuffisante (moins de 2GB)."
fi
success "Mémoire suffisante."

# Vérifier la connexion internet
if ! ping -c 1 github.com > /dev/null 2>&1; then
    error "Pas de connexion internet."
fi
success "Connexion internet active."

# Vérifier l'architecture
if [ "$(uname -m)" != "x86_64" ]; then
    error "Architecture non supportée (seul x86_64 est pris en charge)."
fi
success "Architecture x86_64 détectée."

# Vérifier les outils de base
for cmd in curl wget git; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        error "Outils manquant : $cmd."
    fi
done
success "Outils de base (curl, wget, git) disponibles."

# Vérifier que .env existe dans le dossier courant
if [ ! -f "./.env" ]; then
    error "Fichier .env introuvable dans le dossier courant. Placez-le ici avant de lancer le script."
fi
success "Fichier .env trouvé dans le dossier courant."

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
# CLONE DU DÉPÔT ET COPIE DU .ENV
# =============================================================================
header "Clone du dépôt GitHub et copie du fichier .env"

# Supprimer l'ancien dossier s'il existe
if [ -d "$INSTALL_DIR" ]; then
    run_with_spinner "Suppression de l'ancien dossier $INSTALL_DIR" \
        rm -rf "$INSTALL_DIR"
fi

run_with_spinner "Création du dossier $INSTALL_DIR" \
    mkdir -p "$INSTALL_DIR"

run_with_spinner "Clone du dépôt $REPO_URL" \
    git clone "$REPO_URL" "$INSTALL_DIR"

# Copier le .env du dossier courant vers /opt/asset-manager/
run_with_spinner "Copie du fichier .env vers $INSTALL_DIR/" \
    cp "./.env" "$INSTALL_DIR/.env"

# Sécuriser le fichier .env
run_with_spinner "Sécurisation du fichier .env (chmod 600)" \
    chmod 600 "$INSTALL_DIR/.env"

success "Fichier .env copié et sécurisé dans $INSTALL_DIR/."

# =============================================================================
# CHARGEMENT DES VARIABLES D'ENVIRONNEMENT
# =============================================================================
source "$INSTALL_DIR/.env"
export DB_USER DB_PASSWORD DB_NAME DB_HOST DB_PORT SERVER_IP NVD_API_KEY MISTRAL_API_KEY MISTRAL_MODEL
success "Variables d'environnement chargées depuis $INSTALL_DIR/.env."

# =============================================================================
# CRÉATION DU VIRTUALENV ET INSTALLATION DES DÉPENDANCES
# =============================================================================
header "Création du virtualenv et installation des dépendances"

run_with_spinner "Création du virtualenv" \
    python3 -m venv "$INSTALL_DIR/venv"

run_with_spinner "Mise à jour de pip" \
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip

run_with_spinner "Installation des dépendances (requirements.txt)" \
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Vérification des dépendances critiques
for pkg in fastapi pymysql reportlab uvicorn python-dotenv; do
    if "$INSTALL_DIR/venv/bin/pip" show "$pkg" > /dev/null 2>&1; then
        success "Dépendance $pkg installée."
    else
        error "Dépendance $pkg manquante."
    fi
done

# =============================================================================
# CONFIGURATION DE LA BASE DE DONNÉES
# =============================================================================
header "Configuration de la base de données"

run_with_spinner "Exécution de setup_database.py" \
    "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/setup_database.py"

# Test de connexion à MariaDB
if mariadb -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1;" > /dev/null 2>&1; then
    success "Connexion à MariaDB réussie."
else
    error "Échec de la connexion à MariaDB. Vérifiez DB_USER, DB_PASSWORD, DB_HOST et DB_PORT dans .env."
fi

# =============================================================================
# CONFIGURATION DU SERVICE SYSTEMD
# =============================================================================
header "Configuration du service systemd"

# Copier le fichier de service
if [ -f "$INSTALL_DIR/$SERVICE_NAME.service" ]; then
    run_with_spinner "Copie du fichier de service systemd" \
        cp "$INSTALL_DIR/$SERVICE_NAME.service" "$SERVICE_FILE"
else
    error "Fichier $INSTALL_DIR/$SERVICE_NAME.service introuvable."
fi

run_with_spinner "Rechargement de systemd" \
    systemctl daemon-reload

run_with_spinner "Activation et démarrage du service $SERVICE_NAME" \
    systemctl enable --now "$SERVICE_NAME"

echo ""
echo -e "${BLUE}Statut du service $SERVICE_NAME:${NC}"
systemctl status "$SERVICE_NAME" --no-pager
echo ""

# =============================================================================
# AJOUT DE LA COMMANDE AU PATH
# =============================================================================
header "Ajout de la commande 'asset-manager' au PATH"

if [ -f "$SCRIPT_PATH" ]; then
    run_with_spinner "Création du lien symbolique pour asset-manager" \
        ln -sf "$SCRIPT_PATH" "$SYMLINK_PATH" && chmod +x "$SYMLINK_PATH"
else
    error "Script $SCRIPT_PATH introuvable."
fi
success "Lien symbolique $SYMLINK_PATH créé."

# =============================================================================
# VÉRIFICATION DE FASTAPI
# =============================================================================
header "Vérification de FastAPI"

run_with_spinner "Démarrage de FastAPI via asset-manager" \
    asset-manager fastapi start

echo -e "${BLUE}Attente de 10 secondes pour que FastAPI démarre...${NC}"
sleep 10

if curl -sf "http://localhost:$FASTAPI_PORT/health" > /dev/null 2>&1; then
    success "FastAPI est opérationnel sur http://localhost:$FASTAPI_PORT."
else
    error "FastAPI ne répond pas. Vérifiez les logs avec : journalctl -u $SERVICE_NAME -n 50"
fi

# =============================================================================
# RÉSUMÉ
# =============================================================================
header "Installation complète terminée"

echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  ✅ Installation terminée avec succès !${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo -e "${BLUE}Prochaines étapes:${NC}"
echo "  1. Vérifiez les logs de FastAPI avec : journalctl -u $SERVICE_NAME -f"
echo "  2. Testez l'API avec : curl http://localhost:$FASTAPI_PORT/docs"
echo "  3. Accédez à l'interface web (si configurée)."