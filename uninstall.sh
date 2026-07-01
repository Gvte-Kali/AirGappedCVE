#!/bin/bash
# =============================================================================
# uninstall.sh — Script de désinstallation pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 1.1.0
# Description : Désinstalle complètement AirGappedCVE
# Usage: sudo bash uninstall.sh
# =============================================================================

set +euo pipefail

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================
INSTALL_DIR="/opt/asset-manager"
SERVICE_NAME="asset-manager"
PATH_FILE="/etc/profile.d/asset-manager.sh"
USER_BASHRC="$HOME/.bashrc"
LOG_FILE="/tmp/asset-manager-uninstall.log"

# Variables par défaut pour la base de données (au cas où .env n'existe plus)
DB_NAME="asset_vuln_manager"
DB_USER=""

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Initialisation du log
> "$LOG_FILE"

log() {
    echo -e "${GREEN}[✅]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[❌]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[⚠️]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $1" >> "$LOG_FILE"
}

info() {
    echo -e "${CYAN}[ℹ️]${NC} $1"
}

header() {
    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
}

# =============================================================================
# VÉRIFICATION PRÉLIMINAIRE
# =============================================================================
header "🔍 Vérification préliminaire"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}${BOLD}❌ ERREUR CRITIQUE: Ce script doit être lancé en root.${NC}"
    echo -e "${YELLOW}→ Relancez avec: sudo bash $0${NC}"
    exit 1
fi

# Essayer de récupérer DB_USER et DB_NAME depuis .env si le fichier existe
if [ -f "$INSTALL_DIR/.env" ]; then
    DB_NAME=$(. "$INSTALL_DIR/.env" && echo "$DB_NAME")
    DB_USER=$(. "$INSTALL_DIR/.env" && echo "$DB_USER")
fi

# =============================================================================
# ÉTAPE 1 : ARRÊT ET DÉSACTIVATION DU SERVICE SYSTEMD
# =============================================================================
header "🛑 Étape 1/5 - Arrêt du service systemd"

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Arrêt du service $SERVICE_NAME..."
    if systemctl stop "$SERVICE_NAME" 2>/dev/null; then
        log "Service $SERVICE_NAME arrêté"
    else
        warn "Impossible d'arrêter $SERVICE_NAME (peut-être déjà arrêté)"
    fi
else
    info "Le service $SERVICE_NAME n'est pas actif"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Désactivation du service $SERVICE_NAME..."
    if systemctl disable "$SERVICE_NAME" 2>/dev/null; then
        log "Service $SERVICE_NAME désactivé"
    else
        warn "Impossible de désactiver $SERVICE_NAME"
    fi
else
    info "Le service $SERVICE_NAME n'est pas activé"
fi

# Suppression du fichier de service
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    info "Suppression du fichier de service..."
    if rm -f "/etc/systemd/system/$SERVICE_NAME.service"; then
        systemctl daemon-reload 2>/dev/null
        log "Fichier de service supprimé"
    else
        error "Échec de la suppression du fichier de service"
    fi
else
    info "Fichier de service introuvable"
fi

# =============================================================================
# ÉTAPE 2 : SUPPRESSION DE LA BASE DE DONNÉES ET DE L'UTILISATEUR
# =============================================================================
header "🗄️ Étape 2/5 - Suppression de la base de données"

if [ -z "$DB_USER" ]; then
    info "Aucun utilisateur MariaDB configuré à supprimer (DB_USER non défini)"
else
    read -rp "Voulez-vous supprimer la base de données '$DB_NAME' et l'utilisateur '$DB_USER' ? (o/N) : " DB_CONFIRM
    if [[ "$DB_CONFIRM" =~ ^[oOyY]$ ]]; then
        if command -v mariadb >/dev/null 2>&1; then
            info "Suppression de la base de données $DB_NAME et de l'utilisateur $DB_USER..."
            if mariadb -u root -e "DROP DATABASE IF EXISTS $DB_NAME; DROP USER IF EXISTS '$DB_USER'@'localhost'; DROP USER IF EXISTS '$DB_USER'@'%'; FLUSH PRIVILEGES;" 2>/dev/null; then
                log "Base de données et utilisateur supprimés"
            else
                error "Échec de la suppression de la base de données (vérifiez les identifiants root)"
            fi
        else
            warn "MariaDB n'est pas installé, impossible de supprimer la base de données"
        fi
    else
        info "Suppression de la base de données annulée"
    fi
fi

# =============================================================================
# ÉTAPE 3 : SUPPRESSION DU DOSSIER D'INSTALLATION
# =============================================================================
header "🗑️ Étape 3/5 - Suppression du dossier d'installation"

if [ -d "$INSTALL_DIR" ]; then
    read -rp "Voulez-vous supprimer le dossier $INSTALL_DIR ? (o/N) : " DIR_CONFIRM
    if [[ "$DIR_CONFIRM" =~ ^[oOyY]$ ]]; then
        info "Suppression de $INSTALL_DIR..."
        if rm -rf "$INSTALL_DIR"; then
            log "Dossier $INSTALL_DIR supprimé"
        else
            error "Échec de la suppression de $INSTALL_DIR"
        fi
    else
        info "Suppression de $INSTALL_DIR annulée"
    fi
else
    info "Le dossier $INSTALL_DIR n'existe pas"
fi

# =============================================================================
# ÉTAPE 4 : SUPPRESSION DES ENTRÉES PATH
# =============================================================================
header "📍 Étape 4/5 - Suppression des entrées PATH"

# Suppression dans /etc/profile.d/
if [ -f "$PATH_FILE" ]; then
    info "Suppression de $PATH_FILE..."
    if rm -f "$PATH_FILE"; then
        log "Fichier $PATH_FILE supprimé"
    else
        error "Échec de la suppression de $PATH_FILE"
    fi
else
    info "Fichier $PATH_FILE introuvable"
fi

# Suppression dans .bashrc
if [ -f "$USER_BASHRC" ]; then
    if grep -q "asset-manager" "$USER_BASHRC"; then
        info "Suppression de l'entrée PATH dans $USER_BASHRC..."
        if sed -i '/# Ajouté par install.sh - AirGappedCVE/,/export PATH.*asset-manager/d' "$USER_BASHRC"; then
            log "Entrée PATH supprimée de $USER_BASHRC"
        else
            error "Échec de la suppression de l'entrée PATH dans $USER_BASHRC"
        fi
    else
        info "Aucune entrée asset-manager trouvée dans $USER_BASHRC"
    fi
else
    info "Fichier $USER_BASHRC introuvable"
fi

# =============================================================================
# ÉTAPE 5 : RÉSUMÉ FINAL
# =============================================================================
header "✅ Désinstallation terminée"

echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 Désinstallation terminée${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo ""
echo "📝 Résumé des actions effectuées :"
echo "  - Service systemd : désactivé et supprimé"
if [ -n "$DB_USER" ]; then
    echo "  - Base de données : ${DB_CONFIRM:-non} supprimée"
else
    echo "  - Base de données : non configurée (DB_USER non défini)"
fi
echo "  - Dossier $INSTALL_DIR : ${DIR_CONFIRM:-non} supprimé"
echo "  - Entrées PATH : supprimées"
echo ""
echo "📄 Logs de désinstallation : $LOG_FILE"
echo ""
echo "⚠️  Actions manuelles possibles :"
echo "  - Redémarrer le terminal pour appliquer les changements de PATH"
echo "  - Vérifier que MariaDB est toujours fonctionnel si vous l'utilisez pour d'autres projets"
