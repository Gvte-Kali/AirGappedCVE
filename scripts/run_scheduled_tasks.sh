#!/bin/bash

# =============================================================================
# run_scheduled_tasks.sh — Exécute les tâches planifiées séquentiellement
# Auteur : Gvte-Kali / Vibe Code
# Version : 1.1.0
# Description :
#   - Exécute sync_all.py, correlate_and_analyze.py et backup.sh les uns après les autres
#   - Affiche la sortie en temps réel ET log tout dans /opt/asset-manager/logs/cron.log
#   - Gère les erreurs pour chaque tâche
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
# 🚀 EXÉCUTION D'UNE TÂCHE AVEC GESTION D'ERREUR ET AFFICHAGE EN TEMPS RÉEL
# =============================================================================
run_task() {
    local task_name="$1"
    local task_command="$2"
    local log_prefix="$3"

    info "Début de la tâche: $task_name"

    # Exécuter la commande, afficher la sortie en temps réel ET logger dans le fichier
    if eval "$task_command" 2>&1 | tee -a "$LOG_FILE"; then
        log "Tâche terminée avec succès: $task_name"
        return 0
    else
        local exit_code=${PIPESTATUS[0]}
        error "Échec de la tâche: $task_name (code: $exit_code)"
        warn "La tâche suivante sera exécutée malgré l'échec de $task_name"
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

    # Tâche 1: Synchronisation NVD (sync_all.py)
    run_task \
        "Synchronisation NVD" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/sync_all.py" \
        "sync_all"

    # Tâche 2: Corrélation et analyse (correlate_and_analyze.py)
    run_task \
        "Corrélation et analyse IA" \
        "cd $PROJECT_DIR && $PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/correlate_and_analyze.py" \
        "correlate_and_analyze"

    # Tâche 3: Backup de la base de données (backup.sh)
    run_task \
        "Backup de la base de données" \
        "cd $PROJECT_DIR && bash $PROJECT_DIR/scripts/backup.sh" \
        "backup"

    info "========================================"
    info "Toutes les tâches planifiées terminées"
    info "========================================"
}

# Exécuter le script
main "$@"