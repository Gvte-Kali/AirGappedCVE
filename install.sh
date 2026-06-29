#!/bin/bash

# =============================================================================
# install_user_friendly.sh — Script d'installation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 5.0.0 (avec gestion des conflits MariaDB, détection des outils, et couleurs)
# Description : Installe et configure automatiquement AirGappedCVE sur Ubuntu Server
# Usage: sudo bash install.sh
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
PURPLE='\033[0;35m'; ORANGE='\033[0;33m'

# Ports par défaut
DB_PORT_DEFAULT=3306
DB_PORT_ALT=3307

# Niveaux d'erreur
ERROR_LEVEL_NONE=0
ERROR_LEVEL_WARNING=1
ERROR_LEVEL_ERROR=2
ERROR_LEVEL_CRITICAL=3

# Compteur d'erreurs
ERRORS=0
declare -a ERROR_MESSAGES=()

# Temps de début
START_TIME=$(date +%s)

# Initialiser les fichiers de log
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
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] $1" >> "$VERBOSE_LOG"
  [ -n "${2:-}" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] Solution: $2" >> "$VERBOSE_LOG"

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
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [HEADER] $1" >> "$VERBOSE_LOG"
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

# Vérifie si un paquet est installé
is_package_installed() {
  dpkg -l | grep -q "^ii  $1 "
}

# Vérifie si une commande existe
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Vérifie si un service écoute sur un port
get_service_on_port() {
  local port="$1"
  ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d':' -f2 | cut -d',' -f1 | xargs
}

# Vérifie si un port est utilisé
is_port_in_use() {
  local port="$1"
  ss -tlnp 2>/dev/null | grep -q ":$port " || netstat -tlnp 2>/dev/null | grep -q ":$port "
}

# Gestion des conflits de port pour MariaDB
handle_mariadb_conflict() {
  local port="$1"
  local service_on_port
  service_on_port=$(get_service_on_port "$port")

  if [ -z "$service_on_port" ]; then
    # Aucun service sur le port, on peut installer MariaDB
    return 0
  fi

  # Vérifier si le service est déjà MariaDB
  if [[ "$service_on_port" == *"mariadb"* ]] || [[ "$service_on_port" == *"mysql"* ]]; then
    read -rp "Un service MariaDB/MySQL est déjà actif sur le port $port. Voulez-vous l'utiliser ? (O/n) : " use_existing
    if [[ "$use_existing" =~ ^[OoYy]$ ]] || [ -z "$use_existing" ]; then
      DB_PORT=$port
      echo "Utilisation du service MariaDB existant sur le port $port"
      return 0
    else
      # Supprimer le service existant
      info "Suppression du service MariaDB existant..."
      if ! systemctl stop mariadb >> "$VERBOSE_LOG" 2>&1; then
        error "Échec de l'arrêt de MariaDB" "Vérifiez les logs systemd" $ERROR_LEVEL_ERROR
        return 1
      fi
      if ! apt-get purge -y mariadb-server mariadb-client mariadb-common >> "$VERBOSE_LOG" 2>&1; then
        error "Échec de la suppression de MariaDB" "Vérifiez les logs APT" $ERROR_LEVEL_ERROR
        return 1
      fi
      return 0
    fi
  else
    # Ce n'est pas MariaDB, proposer les options
    echo ""
    echo "Un service non-MariaDB écoute sur le port $port: $service_on_port"
    echo "Choix disponibles:"
    echo "  1) Supprimer le service actuel et installer MariaDB sur le port $port"
    echo "  2) Laisser le service en place et installer MariaDB sur le port $DB_PORT_ALT"
    echo "  3) Annuler l'installation"
    read -rp "Votre choix [1-3] : " db_choice

    case "$db_choice" in
      1)
        info "Suppression du service actuel sur le port $port..."
        local service_name=$(ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'=' -f2)
        if [ -n "$service_name" ]; then
          if ! systemctl stop "$service_name" >> "$VERBOSE_LOG" 2>&1; then
            error "Échec de l'arrêt du service $service_name" "Vérifiez systemctl" $ERROR_LEVEL_ERROR
            return 1
          fi
          if ! systemctl disable "$service_name" >> "$VERBOSE_LOG" 2>&1; then
            warn "Impossible de désactiver $service_name"
          fi
        fi
        DB_PORT=$port
        ;;
      2)
        info "Installation de MariaDB sur le port alternatif $DB_PORT_ALT"
        DB_PORT=$DB_PORT_ALT
        ;;
      3)
        error "Installation annulée par l'utilisateur" "" $ERROR_LEVEL_CRITICAL
        ;;
      *)
        error "Choix invalide" "" $ERROR_LEVEL_ERROR
        return 1
        ;;
    esac
    return 0
  fi
}

# Fonction pour exécuter une commande avec affichage minimal
run_command() {
  local message="$1"
  local command="$2"
  
  echo -e "${CYAN}  → $message...${NC}"
  if eval "$command" >> "$VERBOSE_LOG" 2>&1; then
    echo -e "  ${GREEN}✓ $message terminé${NC}"
    return 0
  else
    echo -e "  ${RED}✗ Échec de $message${NC}"
    echo "Détails de l'erreur dans $VERBOSE_LOG"
    return 1
  fi
}

# =============================================================================
# VÉRIFICATION ROOT
# =============================================================================
if [ "$EUID" -ne 0 ]; then
  error "Ce script doit être lancé en root." "Relancez avec : sudo bash $0" $ERROR_LEVEL_CRITICAL
fi

# =============================================================================
# ASCII ART DE BIENVENUE (corrigé pour les couleurs)
# =============================================================================
echo -e "${PURPLE}"
echo "  AirGappedCVE - Gestion de vulnérabilités en environnement isolé"
echo -e "${NC}"

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================

header "Vérifications préliminaires"

# 1. Vérification des outils requis (corrigé pour 'ping')
info "Vérification des outils requis..."
REQUIRED_TOOLS=("curl" "wget" "git" "bc" "net-tools" "netcat-openbsd" "software-properties-common" "iproute2" "iputils-ping")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command_exists "$tool"; then
    MISSING_TOOLS+=("$tool")
  fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
  info "Installation des outils manquants: ${MISSING_TOOLS[*]}"
  if ! apt-get update >> "$VERBOSE_LOG" 2>&1; then
    error "Échec de la mise à jour des paquets" "Vérifiez votre connexion ou les sources APT" $ERROR_LEVEL_CRITICAL
  fi
  if ! apt-get install -y "${MISSING_TOOLS[@]}" >> "$VERBOSE_LOG" 2>&1; then
    error "Échec de l'installation des outils requis: ${MISSING_TOOLS[*]}" "Vérifiez votre connexion ou les sources APT" $ERROR_LEVEL_CRITICAL
  fi
  log "Outils manquants installés"
else
  info "Tous les outils requis sont installés"
fi

# 2. Vérification de l'espace disque
MIN_SPACE_GB=5
AVAILABLE_SPACE_KB=$(df /opt --output=avail | tail -1)
AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))

if [ "$AVAILABLE_SPACE_GB" -lt "$MIN_SPACE_GB" ]; then
  error "Espace disque insuffisant sur /opt" "Il faut au moins ${MIN_SPACE_GB}GB, vous avez ${AVAILABLE_SPACE_GB}GB" $ERROR_LEVEL_CRITICAL
else
  info "Espace disque suffisant (${AVAILABLE_SPACE_GB}GB disponible sur /opt)"
fi

# 3. Vérification de la mémoire
MIN_RAM_MB=2048
TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")

if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ] 2>/dev/null; then
  error "Mémoire faible détectée (${TOTAL_RAM_MB}MB). Recommandé: ${MIN_RAM_MB}MB+" "" $ERROR_LEVEL_WARNING
else
  info "Mémoire suffisante (${TOTAL_RAM_MB}MB détectés)"
fi

# 4. Détection de l'architecture
ARCH=$(uname -m)
if [[ "$ARCH" == *"arm"* || "$ARCH" == *"aarch64"* ]]; then
  info "Architecture ARM détectée ($ARCH) - Compatible Raspberry Pi"
else
  info "Architecture $ARCH détectée"
fi

# 5. Vérification de la connectivité internet
if command_exists "ping" && ping -c 1 -W 2 github.com > /dev/null 2>&1; then
  info "Connexion internet active"
else
  error "Pas de connexion internet détectée" "Certaines étapes peuvent nécessiter une connexion" $ERROR_LEVEL_WARNING
fi

# 6. Vérification des ports (avant installation de MariaDB)
info "Vérification des ports..."
if is_port_in_use 8000; then
  error "Le port 8000 est déjà utilisé par $(get_service_on_port 8000)" "Arrêtez le service ou changez le port FastAPI" $ERROR_LEVEL_ERROR
fi

# Vérification du port MariaDB (3306 ou alternatif)
DB_PORT=$DB_PORT_DEFAULT
if is_port_in_use $DB_PORT_DEFAULT; then
  handle_mariadb_conflict $DB_PORT_DEFAULT
fi

# 7. Vérification de Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2 || echo "0.0")
if [ "$(printf '%s\n%s' "3.10" "$PYTHON_VERSION" | sort -V | head -1)" != "3.10" ]; then
  error "Python $PYTHON_VERSION détecté. Recommandé: Python 3.10+" "" $ERROR_LEVEL_WARNING
else
  info "Python $PYTHON_VERSION détecté"
fi

# 8. Vérification de la distribution
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
    error "Ce script est optimisé pour Ubuntu/Debian. Distribution détectée: $ID" "" $ERROR_LEVEL_WARNING
  else
    info "Distribution: $ID $VERSION_ID"
  fi
else
  error "Impossible de détecter la distribution Linux" "" $ERROR_LEVEL_WARNING
fi

header "Début de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
echo "Script: $0"
echo "Utilisateur: $(whoami)"
echo "Système: $(lsb_release -d 2>/dev/null | cut -f2- || echo 'Inconnu')"
echo ""
echo "Tous les logs détaillés sont disponibles dans : $VERBOSE_LOG"
echo ""

ask_continue

# =============================================================================
# ÉTAPE 1: MISE À JOUR SYSTÈME ET INSTALLATION DES DÉPENDANCES
# =============================================================================
step_header 1 5 "Mise à jour système et installation des dépendances"

# Mise à jour des paquets
info "Mise à jour des paquets..."
if ! apt-get update >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de la mise à jour des paquets" "Vérifiez votre connexion ou les sources APT (/etc/apt/sources.list)" $ERROR_LEVEL_CRITICAL
fi
log "Mise à jour APT terminée"

# Mise à niveau des paquets
info "Mise à niveau des paquets..."
if ! apt-get upgrade -y >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de la mise à niveau des paquets" "Vérifiez votre connexion" $ERROR_LEVEL_ERROR
fi
log "Système à jour"

# Installation des dépendances (sans mariadb-server, géré plus tard)
info "Installation des dépendances (cela peut prendre plusieurs minutes)..."
ALL_DEPS=(
  "curl" "wget" "git" "bc" "net-tools" "netcat-openbsd" "software-properties-common" "iproute2" "iputils-ping"
  "python3" "python3-pip" "python3-venv" "python3-dev" "build-essential"
)

if ! apt-get install -y "${ALL_DEPS[@]}" >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de l'installation des dépendances" "Vérifiez les logs dans $VERBOSE_LOG pour plus de détails" $ERROR_LEVEL_ERROR
else
  log "Dépendances système installées"
fi

ask_continue

# =============================================================================
# ÉTAPE 1B: INSTALLATION DE MARIADB (après gestion des conflits)
# =============================================================================
step_header "1B" 5 "Installation de MariaDB sur le port $DB_PORT"

# Installation de MariaDB
info "Installation de MariaDB..."
if ! apt-get install -y mariadb-server mariadb-client >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de l'installation de MariaDB" "Vérifiez les logs APT" $ERROR_LEVEL_CRITICAL
fi

# Configuration du port si nécessaire
if [ "$DB_PORT" != "$DB_PORT_DEFAULT" ]; then
  info "Configuration de MariaDB sur le port $DB_PORT..."
  if ! sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/mariadb.conf.d/50-server.cnf; then
    error "Échec de la modification du port MariaDB" "Vérifiez le fichier de configuration" $ERROR_LEVEL_ERROR
    ask_continue
  fi
  # Mettre à jour le port dans my.cnf aussi
  if [ -f /etc/mysql/my.cnf ]; then
    sed -i "s/^port.*=.*3306/port = $DB_PORT/" /etc/mysql/my.cnf
  fi
fi

# Démarrage et activation de MariaDB
info "Démarrage de MariaDB..."
if ! systemctl enable mariadb >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de l'activation de MariaDB" "Vérifiez systemctl" $ERROR_LEVEL_ERROR
  ask_continue
fi

if ! systemctl start mariadb >> "$VERBOSE_LOG" 2>&1; then
  error "Échec du démarrage de MariaDB" "Vérifiez les logs : journalctl -u mariadb -n 30" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "MariaDB démarré et activé"

# Attendre que MariaDB soit prêt (timeout: 60s)
info "Attente que MariaDB soit opérationnel (timeout: 60s)..."
RETRIES=0
MAX_RETRIES=30
until mariadb --port=$DB_PORT -u root -e "SELECT 1" > /dev/null 2>&1; do
  RETRIES=$((RETRIES+1))
  if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
    error "MariaDB ne répond pas après $((MAX_RETRIES * 2)) secondes" "Vérifiez les logs: journalctl -u mariadb -n 50" $ERROR_LEVEL_ERROR
    ask_continue
    break
  fi
  sleep 2
  printf "\r${CYAN}  → Attente... ($RETRIES/$MAX_RETRIES)${NC}"
done
if [ "$RETRIES" -lt "$MAX_RETRIES" ]; then
  echo ""
  log "MariaDB opérationnel après $RETRIES tentatives"
fi

# Sécurisation de base
info "Sécurisation de MariaDB..."
if mariadb --port=$DB_PORT -u root << 'EOF' > /dev/null 2>&1
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
then
  log "MariaDB sécurisé"
else
  error "Échec de la sécurisation de MariaDB" "Vérifiez les permissions root" $ERROR_LEVEL_ERROR
  ask_continue
fi

# Vérification de la version de MariaDB
MARIADB_VERSION=$(mariadb --version 2>/dev/null | awk '{print $5}' | cut -d. -f1-2)
if [ -z "$MARIADB_VERSION" ]; then
  error "MariaDB n'est pas installé correctement" "Vérifiez l'installation avec: apt-get install -y mariadb-server" $ERROR_LEVEL_CRITICAL
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
    if ! git pull origin main >> "$VERBOSE_LOG" 2>&1; then
      error "Échec de la mise à jour du dépôt" "Vérifiez votre connexion ou les permissions" $ERROR_LEVEL_ERROR
      ask_continue
    fi
    log "Dépôt mis à jour"
else
    if ! git clone "$REPO_URL" "$INSTALL_DIR" >> "$VERBOSE_LOG" 2>&1; then
      error "Échec du clonage du dépôt GitHub" "Vérifiez que $REPO_URL est accessible" $ERROR_LEVEL_ERROR
      ask_continue
    fi
    log "Dépôt cloné dans $INSTALL_DIR"
fi

# Vérification de l'intégrité du dépôt
if [ ! -f "$INSTALL_DIR/main.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
  error "Le dépôt semble incomplet ou corrompu" "Vérifiez que $REPO_URL est valide et accessible" $ERROR_LEVEL_CRITICAL
fi

# Supprimer les fichiers inutiles en production
rm -rf "$INSTALL_DIR/.devcontainer"
log ".devcontainer supprimé"

# Créer les dossiers nécessaires
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/documents" "$INSTALL_DIR/backups"
chmod 750 "$INSTALL_DIR/logs" "$INSTALL_DIR/data" "$INSTALL_DIR/backups"
log "Dossiers créés avec les permissions appropriées"

ask_continue

# =============================================================================
# ÉTAPE 3: CONFIGURATION DES VARIABLES D'ENVIRONNEMENT
# =============================================================================
step_header 3 5 "Configuration des variables d'environnement"

echo ""
echo "Nous allons maintenant configurer les variables nécessaires."
echo ""

# Sauvegarde du .env existant si présent
if [ -f "$ENV_FILE" ]; then
  info "Sauvegarde du fichier .env existant..."
  cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)"
  log "Fichier .env existant sauvegardé"
fi

# Demander NVD_API_KEY (optionnel)
while true; do
  read -rp "Entrez votre clé API NVD (laisser vide si vous n'en avez pas) : " NVD_API_KEY
  if [ -z "$NVD_API_KEY" ]; then
    echo "  → Aucune clé NVD fournie (optionnel)"
    break
  fi
  # Validation basique (longueur minimale)
  if [ ${#NVD_API_KEY} -lt 10 ]; then
    echo "  → La clé API NVD semble trop courte. Vérifiez-la."
    continue
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
  # Validation basique (longueur minimale)
  if [ ${#MISTRAL_API_KEY} -lt 10 ]; then
    echo "  → La clé API Mistral semble trop courte. Vérifiez-la."
    continue
  fi
  break
done

# Demander DB_USER (obligatoire)
while true; do
  read -rp "Entrez le nom d'utilisateur pour la base de données (obligatoire) : " DB_USER
  if [ -z "$DB_USER" ]; then
    echo "  → Le nom d'utilisateur est obligatoire !"
    continue
  fi
  # Vérifier que le nom ne contient que des caractères alphanumériques et _
  if ! [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "  → Le nom d'utilisateur ne doit contenir que des lettres, chiffres ou _"
    continue
  fi
  # Vérifier que le nom n'est pas réservé
  if [[ "$DB_USER" =~ ^(root|mysql|admin|mariadb)$ ]]; then
    echo "  → Ce nom est réservé. Choisissez-en un autre."
    continue
  fi
  break
done

# Générer DB_PASSWORD automatiquement
DB_PASSWORD=$(generate_password)
echo "  → Mot de passe généré automatiquement pour $DB_USER"

# Définir les valeurs par défaut
SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
MISTRAL_MODEL="mistral-large-latest"
DB_HOST="127.0.0.1"
DB_NAME="asset_vuln_manager"

echo ""
echo "======================================="
echo "  RÉSUMÉ DE LA CONFIGURATION"
echo "======================================="
echo ""
echo "  SERVER_IP       : $SERVER_IP"
echo "  DB_HOST         : $DB_HOST"
echo "  DB_PORT         : $DB_PORT"
echo "  DB_NAME         : $DB_NAME"
echo "  DB_USER         : $DB_USER"
echo "  DB_PASSWORD     : $DB_PASSWORD"
echo "  NVD_API_KEY     : ${NVD_API_KEY:-non configurée}"
echo "  MISTRAL_API_KEY : ${MISTRAL_API_KEY:-non configurée}"
echo "  MISTRAL_MODEL   : $MISTRAL_MODEL"
echo ""

read -rp "Confirmez-vous cette configuration ? (o/N) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oOyY]$ ]]; then
  echo ""
  error "Installation annulée par l'utilisateur" "Modifiez les valeurs et relancez le script" $ERROR_LEVEL_CRITICAL
fi

# Test des clés API (optionnel)
if [ -n "$NVD_API_KEY" ]; then
  read -rp "Voulez-vous tester la clé API NVD ? (o/N) : " TEST_NVD
  if [[ "$TEST_NVD" =~ ^[oOyY]$ ]]; then
    info "Test de la clé API NVD..."
    if curl -s -I "https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=$NVD_API_KEY" | grep -q "200 OK"; then
      log "Clé API NVD valide"
    else
      warn "Clé API NVD invalide ou problème de connexion"
    fi
  fi
fi

if [ -n "$MISTRAL_API_KEY" ]; then
  read -rp "Voulez-vous tester la clé API Mistral ? (o/N) : " TEST_MISTRAL
  if [[ "$TEST_MISTRAL" =~ ^[oOyY]$ ]]; then
    info "Test de la clé API Mistral..."
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
# =============================================================================
# Généré automatiquement par install_user_friendly.sh
# Date: $(date '+%Y-%m-%d %H:%M:%S')
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
cp "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)"
log "Fichier .env créé et sauvegardé"

ask_continue

# =============================================================================
# ÉTAPE 4: INSTALLATION DE LA BASE DE DONNÉES, FASTAPI ET SERVICES
# =============================================================================
step_header 4 5 "Installation de la base de données et de l'application"

# Création de la base et import du schéma
info "Création de la base de données '$DB_NAME'..."
if mariadb --port=$DB_PORT -u root << EOF > /dev/null 2>&1
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
then
  log "Base et utilisateur créés"
else
  error "Échec de la création de la base ou de l'utilisateur" "Vérifiez les permissions MariaDB" $ERROR_LEVEL_ERROR
  ask_continue
fi

# Vérification de l'existence de schema.sql
SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
  error "Fichier schema.sql introuvable dans $INSTALL_DIR/sql/" "Vérifiez que le dépôt a été cloné correctement" $ERROR_LEVEL_CRITICAL
fi

# Import du schéma
info "Import du schéma SQL..."
if mariadb --port=$DB_PORT -u root "$DB_NAME" < "$SCHEMA_FILE" >> "$VERBOSE_LOG" 2>&1; then
  log "Schéma importé"
else
  error "Échec de l'import du schéma SQL" "Vérifiez le fichier sql/schema.sql" $ERROR_LEVEL_ERROR
  ask_continue
fi

# Création du virtualenv Python
info "Création de l'environnement virtuel Python..."
if ! python3 -m venv "$INSTALL_DIR/venv" >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de la création du virtualenv" "Vérifiez que python3-venv est bien installé" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "Virtualenv créé"

# Installation des dépendances Python
info "Installation des dépendances Python (cela peut prendre plusieurs minutes)..."
if ! "$INSTALL_DIR/venv/bin/pip" install --upgrade pip >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de la mise à jour de pip" "Vérifiez l'environnement virtuel" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "pip mis à jour"

if ! "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de l'installation des dépendances Python" "Vérifiez le fichier requirements.txt ou votre connexion internet" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "Dépendances Python installées"

# Configuration du service systemd
info "Configuration du service systemd..."
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
cat > "$SERVICE_FILE" << EOF
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

if ! systemctl daemon-reload >> "$VERBOSE_LOG" 2>&1; then
  error "Échec du rechargement de systemd" "Vérifiez les permissions" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "systemd rechargé"

# Activation du service
if ! systemctl enable "$SERVICE_NAME" >> "$VERBOSE_LOG" 2>&1; then
  error "Échec de l'activation du service" "Vérifiez le fichier de service" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "Service activé"

info "Démarrage du service..."
if ! systemctl start "$SERVICE_NAME" >> "$VERBOSE_LOG" 2>&1; then
  error "Échec du démarrage du service" "Vérifiez : journalctl -u $SERVICE_NAME -n 30" $ERROR_LEVEL_ERROR
  ask_continue
fi
log "Service démarré"

# Attendre que le service FastAPI soit prêt (timeout: 60s)
info "Attente que FastAPI soit opérationnel (timeout: 60s)..."
RETRIES=0
MAX_RETRIES=30
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  RETRIES=$((RETRIES+1))
  if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
    error "Service FastAPI ne répond pas après $((MAX_RETRIES * 2)) secondes" "Vérifiez les logs : journalctl -u $SERVICE_NAME -n 50" $ERROR_LEVEL_ERROR
    ask_continue
    break
  fi
  sleep 2
  printf "\r${CYAN}  → Attente... ($RETRIES/$MAX_RETRIES)${NC}"
done
if [ "$RETRIES" -lt "$MAX_RETRIES" ]; then
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
step_header 5 5 "Vérifications finales"

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

# Exécuter toutes les commandes de vérification
run_verification "asset-manager status" "bash \"$SCRIPTS_DIR/asset-manager.sh\" status"
run_verification "asset-manager sys ports" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys ports"
run_verification "asset-manager sys check-db" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-db"
run_verification "asset-manager sys check-env" "bash \"$SCRIPTS_DIR/asset-manager.sh\" sys check-env"
run_verification "asset-manager db check" "bash \"$SCRIPTS_DIR/asset-manager.sh\" db check"

ask_continue

# =============================================================================
# CRÉATION DU FICHIER INSTALL_INFO.TXT
# =============================================================================
info "Création du fichier d'informations d'installation..."

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

Temps d'exécution: ${ELAPSED_MIN} minute(s) et ${ELAPSED_SEC} seconde(s)

Commandes utiles:
  systemctl status $SERVICE_NAME
  journalctl -u $SERVICE_NAME -f
  asset-manager status
  asset-manager help
  tail -f $LOG_FILE
  cat $VERBOSE_LOG

=================================================================
EOF

log "Fichier INSTALL_INFO.txt créé dans $INSTALL_DIR"

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

# Afficher le résumé des erreurs
if [ $ERRORS -gt 0 ]; then
  echo ""
  echo -e "${RED}${BOLD}📝 Liste des erreurs :${NC}"
  for msg in "${ERROR_MESSAGES[@]}"; do
    echo "  - $msg"
  done
fi

echo ""
echo "🌐 Configuration :"
echo "  FastAPI      : http://$SERVER_IP:8000"
echo "  API Docs     : http://$SERVER_IP:8000/docs"
echo "  MariaDB      : localhost:$DB_PORT (base: $DB_NAME)"
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
echo "  INSTALL_INFO.txt : $INSTALL_DIR/INSTALL_INFO.txt"
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
echo "  mariadb --port=$DB_PORT -u root"
echo "  tail -f $LOG_FILE"
echo "  cat $VERBOSE_LOG"
echo "  asset-manager help"
echo "  cat $INSTALL_DIR/INSTALL_INFO.txt"
echo ""
echo "📄 Fichier de log complet : $LOG_FILE"
echo "📄 Fichier de log détaillé : $VERBOSE_LOG"

header "Fin de l'installation - $(date '+%Y-%m-%d %H:%M:%S')"
