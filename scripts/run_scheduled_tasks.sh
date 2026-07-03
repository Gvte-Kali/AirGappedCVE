#!/bin/bash

# =============================================================================
# run_scheduled_tasks.sh — Exécute les tâches planifiées séquentiellement
# Auteur : Gvte-Kali / Vibe Code
# Version : 1.2.0
# Description :
#   - Exécute les 4 scripts de synchronisation (download_nvd.py, import_vendors_models.py,
#     cve_sync.py, extract_os_versions.py) dans la TÂCHE 1
#   - Exécute correlate_and_analyze.py et backup.sh ensuite
#   - Affiche la sortie en temps réel ET log tout dans /opt/asset-manager/logs/cron.log
#   - Gère les erreurs pour chaque sous-tâche
# Usage: bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
# =============================================================================

set -o pipefail

# =============================================================================
# 📂 DÉTECTION DU RÉPERTOIRE DU PROJET
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_DIR/logs/cron.log"

# Créer le dossier de logs s'il n'existe pas
mkdir -p "$(dirname "$LOG_FILE")"

# =============================================================================
# 🎨 COULEURS (pour les logs en console)
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# 📝 FONCTIONS DE LOG
# =============================================================================
log() {
    local message="$1"
    echo -e "${GREEN}[✓]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
}

error() {
    local message="$1"
    echo -e "${RED}[✗]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
}

warn() {
    local message="$1"
    echo -e "${YELLOW}[⚠]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
}

info() {
    local message="$1"
    echo -e "${BLUE}[~]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
}

# =============================================================================
# 🚀 EXÉCUTION D'UNE SOUS-TÂCHE AVEC GESTION D'ERREUR ET AFFICHAGE EN TEMPS RÉEL
# =============================================================================
run_subtask() {
    local subtask_name="$1"
    local subtask_command="$2"

    info "  → Sous-tâche: $subtask_name"

    # Exécuter la commande, afficher la sortie en temps réel ET logger dans le fichier
    if eval "$subtask_command" 2>&1 | tee -a "$LOG_FILE"; then
        log "  → Sous-tâche terminée: $subtask_name"
        return 0
    else
        local exit_code=${PIPESTATUS[0]}
        error "  → Échec de la sous-tâche: $subtask_name (code: $exit_code)"
        return 1
    fi
}

# =============================================================================
# 🎯 POINT D'ENTRÉE
# =============================================================================
main() {
    info "========================================"
    info "Démarrage des tâches planifiées"
    info "Projet: $PROJECT_DIR"
    info "Log: $LOG_FILE"
    info "========================================"

    # =========================================================================
    # TÂCHE 1: SYNCHRONISATION COMPLÈTE (4 scripts)
    # =========================================================================
    info "Début de la TÂCHE 1: Synchronisation complète (NVD, Vendors, CVE, OS)"

    # Sous-tâche 1.1: Téléchargement NVD
    run_subtask \
        "Téléchargement NVD (download_nvd.py)" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/download_nvd.py"

    # Sous-tâche 1.2: Import des vendors/modèles
    run_subtask \
        "Import Vendors/Modèles (import_vendors_models.py)" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/import_vendors_models.py"

    # Sous-tâche 1.3: Synchronisation CVE
    run_subtask \
        "Synchronisation CVE (cve_sync.py)" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/cve_sync.py"

    # Sous-tâche 1.4: Extraction des versions OS
    run_subtask \
        "Extraction OS Versions (extract_os_versions.py)" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/extract_os_versions.py"

    log "Tâche 1 terminée: Synchronisation complète"

    # =========================================================================
    # TÂCHE 2: CORRÉLATION ET ANALYSE IA
    # =========================================================================
    info "Début de la TÂCHE 2: Corrélation et analyse IA"
    run_subtask \
        "Corrélation et analyse IA (correlate_and_analyze.py)" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/correlate_and_analyze.py"
    log "Tâche 2 terminée: Corrélation et analyse IA"

    # =========================================================================
    # TÂCHE 3: BACKUP DE LA BASE DE DONNÉES
    # =========================================================================
    info "Début de la TÂCHE 3: Backup de la base de données"
    run_subtask \
        "Backup de la base de données (backup.sh)" \
        "cd $PROJECT_DIR && bash $PROJECT_DIR/scripts/backup.sh"
    log "Tâche 3 terminée: Backup de la base de données"

    info "========================================"
    info "Toutes les tâches planifiées terminées"
    info "========================================"
}

# Exécuter le script
main "$@"