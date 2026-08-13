#!/bin/bash

# =============================================================================
# run_scheduled_tasks.sh — Exécute les tâches planifiées pour cron
# Version : 1.6.0
# Description :
#   - Logue uniquement l'heure, la date de lancement et le statut (succès/échec)
#   - Chaque script gère ses propres logs détaillés
# =============================================================================

set -euo pipefail

# =============================================================================
# 📂 DÉTECTION DU RÉPERTOIRE DU PROJET
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"
MAIN_LOG_FILE="$LOG_DIR/scheduled_tasks.log"

# Créer le dossier de logs s'il n'existe pas
mkdir -p "$LOG_DIR"

# =============================================================================
# 📝 FONCTIONS DE LOG POUR MAIN_LOG_FILE
# =============================================================================
log_main() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    if [ ! -f "$MAIN_LOG_FILE" ]; then
        echo "=== Logs des tâches planifiées — Créé le $timestamp ===" > "$MAIN_LOG_FILE"
    fi
    
    echo "[$timestamp] $message" >> "$MAIN_LOG_FILE"
}

error_main() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    if [ ! -f "$MAIN_LOG_FILE" ]; then
        echo "=== Logs des tâches planifiées — Créé le $timestamp ===" > "$MAIN_LOG_FILE"
    fi
    
    echo "[$timestamp] ERREUR: $message" >> "$MAIN_LOG_FILE"
}

# =============================================================================
# 🚀 EXÉCUTION D'UN SCRIPT AVEC SUIVI DANS MAIN_LOG
# =============================================================================
run_script() {
    cd $PROJECT_DIR
    local script_name="$1"
    local script_command="$2"

    log_main "Début du script: $script_name"

    # Exécuter la commande (le script gère lui-même ses logs détaillés)
    if eval "$script_command" 2>/dev/null; then
        log_main "Script terminé avec succès: $script_name"
        return 0
    else
        local exit_code=${PIPESTATUS[0]}
        error_main "Échec du script: $script_name (code: $exit_code)"
        return 1
    fi
}

# =============================================================================
# 🎯 POINT D'ENTRÉE
# =============================================================================
main() {
    local start_time="$(date '+%Y-%m-%d %H:%M:%S')"
    
    log_main "========================================"
    log_main "Démarrage des tâches planifiées — $start_time"
    log_main "Projet: $PROJECT_DIR"
    log_main "========================================"

    # TÂCHE 1: SYNCHRONISATION COMPLÈTE (4 scripts)
    log_main "Début de la TÂCHE 1: Synchronisation complète (NVD, Vendors, CVE, OS)"

    run_script \
        "download_nvd" \
        "$PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/download_nvd.py"

    run_script \
        "import_vendors_models" \
        "$PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/import_vendors_models.py"

    run_script \
        "cve_sync" \
        "$PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/cve_sync.py"

    run_script \
        "extract_os_versions" \
        "$PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/extract_os_versions.py"

    # TÂCHE 2: CORRÉLATION ET ANALYSE IA
    log_main "Début de la TÂCHE 2: Corrélation et analyse IA"
    run_script \
        "correlate_and_analyze" \
        "$PROJECT_DIR/venv/bin/python $PROJECT_DIR/scripts/correlate_and_analyze.py"

    # TÂCHE 3: BACKUP DE LA BASE DE DONNÉES
    log_main "Début de la TÂCHE 3: Backup de la base de données"
    run_script \
        "backup" \
        "bash $PROJECT_DIR/scripts/backup.sh"

    local end_time="$(date '+%Y-%m-%d %H:%M:%S')"
    log_main "========================================"
    log_main "Toutes les tâches planifiées terminées — $end_time"
    log_main "========================================"
}

# Exécuter le script
main "$@"
