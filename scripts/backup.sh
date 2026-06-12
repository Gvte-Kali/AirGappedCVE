#!/bin/bash

# =============================================================================
# backup.sh — Script de sauvegarde double (locale + NAS) pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 5.1.0
# Description :
#   - Lit TOUTES les configurations depuis .env (dossier parent)
#   - Sauvegarde la base MariaDB/MySQL en dump SQL compressé
#   - Effectue une sauvegarde LOCALE + sur un NAS (configurable via .env)
#   - Conserve uniquement les 5 backups les plus récents par destination
# Usage: bash scripts/backup.sh
# =============================================================================

set -euo pipefail

# =============================================================================
# DÉTECTION AUTOMATIQUE DU PROJET ET CHARGEMENT DE .env
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"
LOG_FILE="$PROJECT_DIR/logs/backup.log"

# Charger .env si présent (priorité aux variables déjà exportées)
if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^['\"]//" -e "s/['\"]$//")
        if [ -z "${!key:-}" ]; then
            export "$key=$value"
        fi
    done < "$ENV_FILE"
fi

# =============================================================================
# CONFIGURATION (TOUT EST CHARGÉ DEPUIS .env)
# =============================================================================
# --- Sauvegarde locale ---
LOCAL_BACKUP_DIR="${LOCAL_BACKUP_DIR:-backups}"

# --- Sauvegarde NAS ---
ENABLE_NAS_BACKUP="${ENABLE_NAS_BACKUP:-false}"
NAS_PROTOCOL="${NAS_PROTOCOL:-smb}"  # smb, ssh, rsync, local

# --- Paramètres SMB ---
NAS_SMB_SERVER="${NAS_SMB_SERVER:-}"
NAS_SMB_SHARE="${NAS_SMB_SHARE:-backup}"
NAS_SMB_USER="${NAS_SMB_USER:-}"
NAS_SMB_PASSWORD="${NAS_SMB_PASSWORD:-}"
NAS_SMB_DIR="${NAS_SMB_DIR:-AirGappedCVE}"
NAS_SMB_MOUNT="${NAS_SMB_MOUNT:-/mnt/nas_backup}"

# --- Paramètres SSH ---
NAS_SSH_SERVER="${NAS_SSH_SERVER:-}"
NAS_SSH_USER="${NAS_SSH_USER:-}"
NAS_SSH_PASSWORD="${NAS_SSH_PASSWORD:-}"
NAS_SSH_PORT="${NAS_SSH_PORT:-22}"
NAS_SSH_DIR="${NAS_SSH_DIR:-/backup/AirGappedCVE}"

# --- Paramètres RSYNC ---
NAS_RSYNC_SERVER="${NAS_RSYNC_SERVER:-}"
NAS_RSYNC_USER="${NAS_RSYNC_USER:-}"
NAS_RSYNC_DIR="${NAS_RSYNC_DIR:-backup/AirGappedCVE}"

# --- Paramètres dossier local monté ---
NAS_LOCAL_MOUNT="${NAS_LOCAL_MOUNT:-/mnt/nas/backup/AirGappedCVE}"

# --- Base de données ---
DB_NAME="${DB_NAME:-asset_vuln_manager}"
DB_USER="${DB_USER:-avea}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"

# --- Autres ---
MAX_BACKUPS="${MAX_BACKUPS:-5}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILENAME="backup_${DB_NAME}_$TIMESTAMP.sql.gz"

# Chemins absolus
LOCAL_BACKUP_DIR="$PROJECT_DIR/$LOCAL_BACKUP_DIR"
LOCAL_BACKUP_FILE="$LOCAL_BACKUP_DIR/$BACKUP_FILENAME"

# =============================================================================
# COULEURS
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# FONCTIONS DE LOG
# =============================================================================
log() {
    local message="$1"
    echo -e "${GREEN}[✓]${NC} $message" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $message" >> "$LOG_FILE"
}

error() {
    local message="$1"
    echo -e "${RED}[✗]${NC} $message" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] $message" >> "$LOG_FILE"
    exit 1
}

warn() {
    local message="$1"
    echo -e "${YELLOW}[⚠]${NC} $message" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARN] $message" >> "$LOG_FILE"
}

info() {
    local message="$1"
    echo -e "${BLUE}[~]${NC} $message" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] $message" >> "$LOG_FILE"
}

title() {
    local message="$1"
    echo -e "${PURPLE}=== $message ===${NC}" | tee -a "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [TITLE] $message" >> "$LOG_FILE"
}

# =============================================================================
# VÉRIFIER LES PRÉREQUIS
# =============================================================================
check_prerequisites() {
    info 'Vérification des prérequis...'
    if ! command -v mysqldump &> /dev/null; then
        error 'mysqldump n est pas installé. Installez MariaDB/MySQL client.'
    fi
    if ! command -v gzip &> /dev/null; then
        error 'gzip n est pas installé. Installez-le avec apt install gzip.'
    fi
    if [ -z "$DB_PASSWORD" ]; then
        error 'DB_PASSWORD n est pas défini dans .env. Ajoutez-le et réessayez.'
    fi

    # Vérifier les outils pour le NAS si activé
    if [ "$ENABLE_NAS_BACKUP" = 'true' ]; then
        case "$NAS_PROTOCOL" in
            smb)
                if ! command -v mount.cifs &> /dev/null && ! command -v smbclient &> /dev/null; then
                    error 'Les outils SMB (cifs-utils) ne sont pas installés. Exécutez: sudo apt install cifs-utils'
                fi
                if [ -z "$NAS_SMB_SERVER" ] || [ -z "$NAS_SMB_USER" ] || [ -z "$NAS_SMB_PASSWORD" ]; then
                    error 'Pour SMB, définissez NAS_SMB_SERVER, NAS_SMB_USER et NAS_SMB_PASSWORD dans .env'
                fi
                ;;
            ssh)
                if ! command -v scp &> /dev/null; then
                    error 'scp n est pas installé. Installez openssh-client.'
                fi
                if [ -z "$NAS_SSH_SERVER" ] || [ -z "$NAS_SSH_USER" ]; then
                    error 'Pour SSH, définissez NAS_SSH_SERVER et NAS_SSH_USER dans .env'
                fi
                ;;
            rsync)
                if ! command -v rsync &> /dev/null; then
                    error 'rsync n est pas installé. Installez rsync.'
                fi
                if [ -z "$NAS_RSYNC_SERVER" ] || [ -z "$NAS_RSYNC_USER" ]; then
                    error 'Pour RSYNC, définissez NAS_RSYNC_SERVER et NAS_RSYNC_USER dans .env'
                fi
                ;;
            local)
                if [ -z "$NAS_LOCAL_MOUNT" ]; then
                    error 'Pour le mode local, définissez NAS_LOCAL_MOUNT dans .env'
                fi
                ;;
        esac
    fi
    log 'Prérequis vérifiés.'
}

# =============================================================================
# CRÉER UN DOSSIER DE BACKUP
# =============================================================================
create_backup_dir() {
    local dir="$1"
    info "Création du dossier de backup: $dir"
    if [ ! -d "$dir" ]; then
        if ! mkdir -p "$dir"; then
            error "Impossible de créer le dossier $dir. Vérifiez les permissions."
        fi
        log "Dossier $dir créé."
    else
        log "Dossier $dir existe déjà."
    fi
}

# =============================================================================
# ROTATION DES BACKUPS (TOUS NOMS CONFONDUS)
# =============================================================================
rotate_backups() {
    local backup_dir="$1"
    local max_backups="$2"
    info "Vérification des backups dans $backup_dir..."
    local BACKUP_COUNT
    BACKUP_COUNT=$(find "$backup_dir" -type f -name '*.sql.gz' 2>/dev/null | wc -l)
    info "Nombre de backups existants: $BACKUP_COUNT/$max_backups"

    if [ "$BACKUP_COUNT" -ge "$max_backups" ]; then
        info 'Suppression du backup le plus ancien dans $backup_dir...'
        local OLDEST_BACKUP
        OLDEST_BACKUP=$(find "$backup_dir" -type f -name '*.sql.gz' -printf '%T@ %p\n' 2>/dev/null | sort -n | head -n 1 | cut -d' ' -f2-)
        if [ -n "$OLDEST_BACKUP" ]; then
            if rm -f "$OLDEST_BACKUP"; then
                log "Backup supprimé: $OLDEST_BACKUP"
            else
                error "Impossible de supprimer le backup: $OLDEST_BACKUP"
            fi
        else
            warn 'Aucun backup ancien trouvé à supprimer.'
        fi
    fi
}

# =============================================================================
# EFFECTUER LE DUMP DE LA BASE DE DONNÉES
# =============================================================================
dump_database() {
    local output_file="$1"
    info "Début du dump de la base de données $DB_NAME vers $output_file..."
    if mysqldump \
        --host="$DB_HOST" \
        --port="$DB_PORT" \
        --user="$DB_USER" \
        --password="$DB_PASSWORD" \
        --single-transaction \
        --routines \
        --triggers \
        --events \
        --skip-ssl \
        --skip-add-drop-table \
        "$DB_NAME" | gzip > "$output_file"; then

        if [ -s "$output_file" ]; then
            local BACKUP_SIZE
            BACKUP_SIZE=$(du -h "$output_file" | cut -f1)
            log "Backup créé avec succès: $output_file (taille: $BACKUP_SIZE)"
            return 0
        else
            error "Le fichier de backup est vide: $output_file"
        fi
    else
        error 'Échec du dump de la base de données. Vérifiez les identifiants ou la connexion.'
    fi
}

# =============================================================================
# VÉRIFIER L'INTÉGRITÉ DU BACKUP
# =============================================================================
verify_backup() {
    local backup_file="$1"
    info "Vérification de l intégrité du backup: $backup_file"
    if gzip -t "$backup_file" 2>/dev/null; then
        log "Backup vérifié: $backup_file est valide."
        return 0
    else
        error "Le backup est corrompu: $backup_file"
    fi
}

# =============================================================================
# SAUVEGARDE SUR NAS (SMB)
# =============================================================================
backup_to_nas_smb() {
    title 'Sauvegarde sur NAS (SMB)'
    local nas_backup_file="$NAS_SMB_DIR/$BACKUP_FILENAME"

    info "Montage du partage SMB //${NAS_SMB_SERVER}/${NAS_SMB_SHARE}..."
    if ! mkdir -p "$NAS_SMB_MOUNT"; then
        error "Impossible de créer le point de montage $NAS_SMB_MOUNT"
    fi

    if mount -t cifs "//$NAS_SMB_SERVER/$NAS_SMB_SHARE" "$NAS_SMB_MOUNT" \
        -o username="$NAS_SMB_USER",password="$NAS_SMB_PASSWORD",vers=3.0,uid=$(id -u),gid=$(id -g) 2>/dev/null; then
        log 'Partage SMB monté avec succès.'

        if ! mkdir -p "$NAS_SMB_MOUNT/$NAS_SMB_DIR"; then
            error "Impossible de créer le dossier $NAS_SMB_DIR sur le NAS"
        fi

        info 'Copie du backup vers le NAS...'
        if cp "$LOCAL_BACKUP_FILE" "$NAS_SMB_MOUNT/$NAS_SMB_DIR/$BACKUP_FILENAME"; then
            log 'Backup copié vers le NAS.'
            rotate_backups "$NAS_SMB_MOUNT/$NAS_SMB_DIR" "$MAX_BACKUPS"
            verify_backup "$NAS_SMB_MOUNT/$NAS_SMB_DIR/$BACKUP_FILENAME"
        else
            error 'Échec de la copie vers le NAS'
        fi

        info 'Démontage du partage SMB...'
        if ! umount "$NAS_SMB_MOUNT"; then
            warn "Impossible de démonter $NAS_SMB_MOUNT. Essayez: sudo umount -l $NAS_SMB_MOUNT"
        else
            log 'Partage SMB démonté.'
        fi
    else
        error 'Échec du montage du partage SMB. Vérifiez les identifiants, le réseau ou le partage.'
    fi
}

# =============================================================================
# SAUVEGARDE SUR NAS (SSH/SCP)
# =============================================================================
backup_to_nas_ssh() {
    title 'Sauvegarde sur NAS (SSH/SCP)'
    local nas_backup_path="$NAS_SSH_DIR/$BACKUP_FILENAME"

    info "Copie du backup vers $NAS_SSH_USER@$NAS_SSH_SERVER:$nas_backup_path..."
    if scp -P "$NAS_SSH_PORT" "$LOCAL_BACKUP_FILE" "$NAS_SSH_USER@$NAS_SSH_SERVER:$nas_backup_path"; then
        log 'Backup copié vers le NAS via SCP.'

        info 'Rotation des backups sur le NAS...'
        if ! ssh -p "$NAS_SSH_PORT" "$NAS_SSH_USER@$NAS_SSH_SERVER" \
            "cd '$(dirname "$nas_backup_path")' && \
            find . -type f -name '*.sql.gz' -printf '%T@ %p\n' | sort -n | head -n -$MAX_BACKUPS | cut -d' ' -f2- | xargs -I {} rm -f {} 2>/dev/null"; then
            warn 'Rotation des backups sur le NAS impossible. Faites-le manuellement.'
        fi
    else
        error 'Échec de la copie vers le NAS via SCP.'
    fi
}

# =============================================================================
# SAUVEGARDE SUR NAS (RSYNC)
# =============================================================================
backup_to_nas_rsync() {
    title 'Sauvegarde sur NAS (RSYNC)'
    local nas_backup_path="$NAS_RSYNC_DIR/$BACKUP_FILENAME"

    info "Copie du backup vers $NAS_RSYNC_USER@$NAS_RSYNC_SERVER::$nas_backup_path..."
    if rsync -avz -e ssh "$LOCAL_BACKUP_FILE" "$NAS_RSYNC_USER@$NAS_RSYNC_SERVER::$nas_backup_path"; then
        log 'Backup copié vers le NAS via RSYNC.'

        info 'Rotation des backups sur le NAS...'
        if ! ssh "$NAS_RSYNC_USER@$NAS_RSYNC_SERVER" \
            "cd '$(dirname \"$nas_backup_path\")' && \
            find . -type f -name '*.sql.gz' -printf '%T@ %p\n' | sort -n | head -n -$MAX_BACKUPS | cut -d' ' -f2- | xargs -I {} rm -f {} 2>/dev/null"; then
            warn 'Rotation des backups sur le NAS impossible. Faites-le manuellement.'
        fi
    else
        error 'Échec de la copie vers le NAS via RSYNC.'
    fi
}

# =============================================================================
# SAUVEGARDE SUR NAS (DOSSIER LOCAL MONTÉ)
# =============================================================================
backup_to_nas_local() {
    title 'Sauvegarde sur NAS (dossier monté)'
    local nas_backup_file="$NAS_LOCAL_MOUNT/$BACKUP_FILENAME"

    info "Copie du backup vers $NAS_LOCAL_MOUNT..."
    if cp "$LOCAL_BACKUP_FILE" "$nas_backup_file"; then
        log 'Backup copié vers le NAS.'
        rotate_backups "$NAS_LOCAL_MOUNT" "$MAX_BACKUPS"
        verify_backup "$nas_backup_file"
    else
        error "Échec de la copie vers $NAS_LOCAL_MOUNT. Vérifiez les permissions."
    fi
}

# =============================================================================
# SAUVEGARDE SUR NAS (DISPATCHER)
# =============================================================================
backup_to_nas() {
    if [ "$ENABLE_NAS_BACKUP" != 'true' ]; then
        info 'Sauvegarde sur NAS désactivée (ENABLE_NAS_BACKUP=false).'
        return 0
    fi

    case "$NAS_PROTOCOL" in
        smb)
            backup_to_nas_smb
            ;;
        ssh)
            backup_to_nas_ssh
            ;;
        rsync)
            backup_to_nas_rsync
            ;;
        local)
            backup_to_nas_local
            ;;
        *)
            error "Protocole NAS non supporté: $NAS_PROTOCOL. Utilisez smb, ssh, rsync ou local."
            ;;
    esac
}

# =============================================================================
# AFFICHER LE RÉCAPITULATIF
# =============================================================================
show_summary() {
    title 'RÉCAPITULATIF DU BACKUP'
    echo -e "${CYAN}Date:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}Projet:${NC} $PROJECT_DIR"
    echo -e "${CYAN}Base de données:${NC} $DB_NAME"
    echo -e "${CYAN}Hôte DB:${NC} $DB_HOST:$DB_PORT"
    echo -e "${CYAN}Utilisateur DB:${NC} $DB_USER"
    echo -e "${CYAN}--- Sauvegarde locale ---${NC}"
    echo -e "${CYAN}Dossier:${NC} $LOCAL_BACKUP_DIR"
    echo -e "${CYAN}Fichier:${NC} $LOCAL_BACKUP_FILE"
    echo -e "${CYAN}Taille:${NC} $(du -h "$LOCAL_BACKUP_FILE" | cut -f1)"
    echo -e "${CYAN}Backups locaux:${NC} $(find "$LOCAL_BACKUP_DIR" -type f -name '*.sql.gz' 2>/dev/null | wc -l)/$MAX_BACKUPS"

    if [ "$ENABLE_NAS_BACKUP" = 'true' ]; then
        echo -e "${CYAN}--- Sauvegarde NAS ---${NC}"
        echo -e "${CYAN}Protocole:${NC} $NAS_PROTOCOL"
        case "$NAS_PROTOCOL" in
            smb)
                echo -e "${CYAN}Serveur:${NC} $NAS_SMB_SERVER/$NAS_SMB_SHARE/$NAS_SMB_DIR"
                ;;
            ssh)
                echo -e "${CYAN}Serveur:${NC} $NAS_SSH_SERVER:$NAS_SSH_PORT$NAS_SSH_DIR"
                ;;
            rsync)
                echo -e "${CYAN}Serveur:${NC} $NAS_RSYNC_SERVER::$NAS_RSYNC_DIR"
                ;;
            local)
                echo -e "${CYAN}Chemin:${NC} $NAS_LOCAL_MOUNT"
                ;;
        esac
    fi
    title 'Backup terminé avec succès'
}

# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    title 'Démarrage du script de backup double destination'
    info "Répertoire du projet: $PROJECT_DIR"
    info "Fichier .env utilisé: $ENV_FILE"

    check_prerequisites

    # Sauvegarde locale
    title 'Sauvegarde LOCALE'
    create_backup_dir "$LOCAL_BACKUP_DIR"
    rotate_backups "$LOCAL_BACKUP_DIR" "$MAX_BACKUPS"
    dump_database "$LOCAL_BACKUP_FILE"
    verify_backup "$LOCAL_BACKUP_FILE"

    # Sauvegarde sur NAS
    backup_to_nas

    show_summary
}

main "$@"