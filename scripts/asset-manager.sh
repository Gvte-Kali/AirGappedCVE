#!/bin/bash

# =============================================================================
# asset-manager — CLI de maintenance pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 1.0.0
# Description : Outil tout-en-un pour gérer le service, la BDD, les logs,
#               les corrélations, les documents, et les audits.
# =============================================================================

# --- VARIABLES GLOBALES (dynamiques dev/prod) ------------------------------------

# Détection automatique de l'environnement
if [ -d "/opt/asset-manager" ]; then
    # Environnement de production
    PROJECT_DIR="/opt/asset-manager"
    LOG_FILE="/opt/asset-manager/logs/FastAPI.log"
    VENV_PYTHON="/opt/asset-manager/venv/bin/python"
    SERVICE_NAME="asset-manager"
    DB_USER="${DB_USER:-avea}"
    DB_NAME="${DB_NAME:-asset_vuln_manager}"
    DOCS_DIR="/opt/asset-manager/documents"
    BACKUP_DIR="/tmp"
else
    # Environnement de développement (Codespaces, local)
    PROJECT_DIR="/workspace/Gvte-Kali__AirGappedCVE"
    LOG_FILE="/workspace/Gvte-Kali__AirGappedCVE/logs/FastAPI.log"
    VENV_PYTHON="/workspace/Gvte-Kali__AirGappedCVE/venv/bin/python"
    SERVICE_NAME="asset-manager-dev"  # À adapter si nécessaire
    DB_USER="${DB_USER:-root}"       # En dev, on utilise souvent root
    DB_NAME="${DB_NAME:-asset_vuln_manager}"
    DOCS_DIR="/workspace/Gvte-Kali__AirGappedCVE/documents"
    BACKUP_DIR="/tmp"
fi

# Charger les variables depuis .env si le fichier existe
ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs -0)
fi

# Variables par défaut (peuvent être écrasées par .env)
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_PASSWORD="${DB_PASSWORD:-}"
MISTRAL_API_KEY="${MISTRAL_API_KEY:-}"
NVD_API_KEY="${NVD_API_KEY:-}"

# --- FONCTIONS UTILITAIRES ------------------------------------------------------

# Afficher l'aide
show_help() {
    cat <<EOF
╔════════════════════════════════════════════════════════════════════════════╗
║                    ASSET-MANAGER CLI v1.0.0                                ║
║  Outil de maintenance pour AirGappedCVE (Gvte-Kali)                        ║
╚════════════════════════════════════════════════════════════════════════════╝

📌 ENVIRONNEMENT DÉTECTÉ :
   Project Dir : $PROJECT_DIR
   Mode        : $(if [ -d "/opt/asset-manager" ]; then echo "PROD"; else echo "DEV"; fi)

📌 USAGE :
   ./asset-manager <commande> [options]

📌 COMMANDES DISPONIBLES :

┌─ FASTAPI ─────────────────────────────────────────────────────────────┐
│ start       Démarre le service systemd FastAPI                        │
│ stop        Arrête le service FastAPI                                 │
│ restart     Redémarre le service FastAPI                              │
│ status      Affiche le statut systemd + PID + port                    │
└───────────────────────────────────────────────────────────────────────┘

┌─ LOGS ────────────────────────────────────────────────────────────────┐
│ logs        Affiche les 50 dernières lignes de FastAPI.log            │
│ logs-err    Filtre les lignes contenant ERROR/EXCEPTION               │
│ logs-corr   Filtre les lignes de corrélation                          │
└───────────────────────────────────────────────────────────────────────┘

┌─ BASE DE DONNÉES ─────────────────────────────────────────────────────────┐
│ db          Affiche la commande MySQL complète pour se connecter          │
│ db-connect  Se connecte directement à MariaDB                             │
│ db-backup   Effectue un dump complet → $BACKUP_DIR/am_backup_YYYYMMDD.sql │
│ db-schema   Effectue un dump du schéma → schema.sql                       │
│ db-size     Affiche la taille de chaque table en Mo                       │
│ db-vacuum   Optimise les tables corrélations + cve                        │
│ db-check    Vérifie l'intégrité des tables (CHECK TABLE)                  │
└───────────────────────────────────────────────────────────────────────────┘

┌─ CORRÉLATIONS ────────────────────────────────────────────────────────────┐
│ correlate         Lance le pipeline complet (corrélation + analyse)       │
│ corr-clear        Supprime TOUTES les corrélations (avec confirmation)    │
│ corr-clear-asset  Supprime les corrélations d'un asset (id interactif)    │
│ corr-stats        Affiche le COUNT des corrélations par statut            │
│ corr-rejects      Affiche les 20 derniers rejets de corrélation           │
│ corr-clear-rejects Supprime tous les rejets de corrélation                │
│ corr-top          Affiche le top 10 des assets par nombre de corrélations │
└───────────────────────────────────────────────────────────────────────────┘

┌─ DOCUMENTS ───────────────────────────────────────────────────────────┐
│ docs-list   Liste les PDFs avec taille et date                        │
│ docs-clear  Supprime TOUS les PDFs (avec confirmation)                │
│ docs-size   Affiche la taille totale du dossier documents             │
└───────────────────────────────────────────────────────────────────────┘

┌─ CVE ─────────────────────────────────────────────────────────────────┐
│ cve-stats   Affiche le COUNT des CVE par vendor                       │
│ cve-last    Affiche les 10 dernières CVE importées                    │
└───────────────────────────────────────────────────────────────────────┘

┌─ AUDIT ───────────────────────────────────────────────────────────────┐
│ audit-assets   Affiche les assets sans vendor NVD (jamais corrélés)   │
│ audit-os       Affiche les assets sans OS normalisé                   │
│ audit-orphans  Affiche les corrélations sans asset ou CVE valide      │
└───────────────────────────────────────────────────────────────────────┘

┌─ SYSTÈME ─────────────────────────────────────────────────────────────┐
│ sys-info      Affiche RAM, CPU, température, uptime                   │
│ sys-ports     Vérifie les ports 3000 (Grafana) et 8000 (FastAPI)      │
│ sys-services  Affiche le statut de FastAPI, MariaDB, Grafana          │
│ check-env     Vérifie que les variables .env sont présentes           │
│ check-db      Vérifie la connexion à la BDD + COUNT des tables        │
│ check-disk    Affiche l'espace disque (documents + logs)              │
│ update-deps   Met à jour les dépendances Python (pip install -r reqs) │
│ version       Affiche les versions de Python, FastAPI, MariaDB        │
└───────────────────────────────────────────────────────────────────────┘

📌 OPTIONS :
   --help, -h    Affiche cette aide
   --verbose, -v Mode verbeux (pour certaines commandes)

📌 EXEMPLES :
   ./asset-manager start
   ./asset-manager logs-err
   ./asset-manager db-backup
   ./asset-manager sys-info

📌 ALIAS RECOMMANDÉ :
   Ajoutez ceci à votre ~/.bashrc ou ~/.zshrc :
   alias asset-manager="$PROJECT_DIR/scripts/asset-manager"

EOF
}

# Vérifier si une commande existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Vérifier si MariaDB est accessible
check_mariadb() {
    if ! command_exists mysql; then
        echo "❌ ERREUR : mysql (client MariaDB) n'est pas installé."
        return 1
    fi
    if ! mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" -e "SELECT 1;" "$DB_NAME" >/dev/null 2>&1; then
        echo "❌ ERREUR : Impossible de se connecter à MariaDB."
        echo "   Vérifiez DB_HOST, DB_PORT, DB_USER, DB_PASSWORD dans .env"
        return 1
    fi
    return 0
}

# Vérifier si systemd est disponible (pour FastAPI)
check_systemd() {
    if ! command_exists systemctl; then
        echo "⚠️  systemctl n'est pas disponible (environnement non-systemd ?)."
        return 1
    fi
    return 0
}

# --- COMMANDES FASTAPI --------------------------------------------------------

cmd_fastapi_start() {
    if ! check_systemd; then
        echo "❌ Impossible de démarrer le service (systemd requis)."
        exit 1
    fi
    echo "🚀 Démarrage du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl start "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_stop() {
    if ! check_systemd; then
        echo "❌ Impossible d'arrêter le service (systemd requis)."
        exit 1
    fi
    echo "🛑 Arrêt du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl stop "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_restart() {
    if ! check_systemd; then
        echo "❌ Impossible de redémarrer le service (systemd requis)."
        exit 1
    fi
    echo "🔄 Redémarrage du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl restart "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_status() {
    if ! check_systemd; then
        echo "⚠️  systemd non disponible. Vérification manuelle..."
        if pgrep -f "uvicorn.*main:app" >/dev/null; then
            PID=$(pgrep -f "uvicorn.*main:app")
            PORT=$(grep -oP 'port=\K[0-9]+' "$PROJECT_DIR/main.py" || echo "8000")
            echo "✅ FastAPI est en cours d'exécution (PID: $PID, Port: $PORT)"
        else
            echo "❌ FastAPI n'est pas en cours d'exécution."
        fi
        return
    fi
    echo "📊 Statut du service FastAPI ($SERVICE_NAME) :"
    sudo systemctl status "$SERVICE_NAME" --no-pager
    if [ $? -eq 0 ]; then
        PID=$(sudo systemctl show "$SERVICE_NAME" -p MainPID --value)
        PORT=$(grep -oP 'port=\K[0-9]+' "$PROJECT_DIR/main.py" || echo "8000")
        echo "   PID: $PID | Port: $PORT"
    fi
}

# --- COMMANDES LOGS ----------------------------------------------------------

cmd_logs() {
    local filter="$1"
    local tail_lines=50
    if [ ! -f "$LOG_FILE" ]; then
        echo "❌ Fichier de log introuvable : $LOG_FILE"
        echo "   Vérifiez LOG_FILE dans .env ou l'emplacement du projet."
        exit 1
    fi
    if [ -n "$filter" ]; then
        echo "🔍 Filtre appliqué : '$filter' (50 dernières lignes)"
        tail -n "$tail_lines" "$LOG_FILE" | grep -i --color=always "$filter"
    else
        echo "📜 Dernières lignes de $LOG_FILE :"
        tail -n "$tail_lines" "$LOG_FILE"
    fi
}

cmd_logs_err() {
    cmd_logs "ERROR\|EXCEPTION\|Traceback"
}

cmd_logs_corr() {
    cmd_logs "correlate\|CVE\|correlation"
}

# --- COMMANDES BASE DE DONNÉES ----------------------------------------------

cmd_db() {
    echo "🗃️  Commande MySQL pour se connecter à $DB_NAME :"
    echo "   mysql --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD $DB_NAME"
}

cmd_db_connect() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔌 Connexion à MariaDB ($DB_NAME)..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" "$DB_NAME"
}

cmd_db_backup() {
    if ! check_mariadb; then
        exit 1
    fi
    local backup_file="$BACKUP_DIR/am_backup_$(date +%Y%m%d).sql"
    echo "💾 Sauvegarde de $DB_NAME vers $backup_file..."
    mysqldump --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
              --single-transaction --routines --triggers --events "$DB_NAME" > "$backup_file"
    if [ $? -eq 0 ]; then
        echo "✅ Sauvegarde terminée : $backup_file"
        ls -lh "$backup_file"
    else
        echo "❌ Échec de la sauvegarde."
        exit 1
    fi
}

cmd_db_schema() {
    if ! check_mariadb; then
        exit 1
    fi
    local schema_file="$PROJECT_DIR/sql/schema.sql"
    echo "📄 Génération du schéma vers $schema_file..."
    mysqldump --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
              --no-data --routines --triggers "$DB_NAME" > "$schema_file"
    if [ $? -eq 0 ]; then
        echo "✅ Schéma généré : $schema_file"
    else
        echo "❌ Échec de la génération du schéma."
        exit 1
    fi
}

cmd_db_size() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "📏 Taille des tables de $DB_NAME (en Mo) :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT table_name AS 'Table',
                     ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Taille (Mo)'
              FROM information_schema.TABLES
              WHERE table_schema = '$DB_NAME'
              ORDER BY (data_length + index_length) DESC;" "$DB_NAME"
}

cmd_db_vacuum() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🧹 Optimisation des tables corrélations et cve..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "OPTIMIZE TABLE correlations, cve;" "$DB_NAME"
    echo "✅ Optimisation terminée."
}

cmd_db_check() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Vérification de l'intégrité des tables..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "CHECK TABLE clients, sites, assets, cve, correlations, equipment_types;" "$DB_NAME"
    echo "✅ Vérification terminée."
}

# --- COMMANDES CORRÉLATIONS --------------------------------------------------

cmd_correlate() {
    echo "🔄 Lancement du pipeline de corrélation + analyse..."
    cd "$PROJECT_DIR" || exit 1
    if [ -f "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" "$PROJECT_DIR/scripts/correlate_and_analyze.py" --verbose
    else
        python3 "$PROJECT_DIR/scripts/correlate_and_analyze.py" --verbose
    fi
}

cmd_corr_clear() {
    read -p "⚠️  Êtes-vous sûr de vouloir SUPPRIMER TOUTES les corrélations ? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Annulé."
        exit 0
    fi
    if ! check_mariadb; then
        exit 1
    fi
    echo "🗑️  Suppression de toutes les corrélations..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "TRUNCATE TABLE correlations;" "$DB_NAME"
    echo "✅ Toutes les corrélations ont été supprimées."
}

cmd_corr_clear_asset() {
    if ! check_mariadb; then
        exit 1
    fi
    read -p "🔢 Entrez l'ID de l'asset à nettoyer : " asset_id
    if [ -z "$asset_id" ]; then
        echo "❌ Aucun ID fourni."
        exit 1
    fi
    read -p "⚠️  Êtes-vous sûr de vouloir supprimer les corrélations de l'asset $asset_id ? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Annulé."
        exit 0
    fi
    echo "🗑️  Suppression des corrélations pour l'asset $asset_id..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "DELETE FROM correlations WHERE asset_id = $asset_id;" "$DB_NAME"
    echo "✅ Corrélations supprimées pour l'asset $asset_id."
}

cmd_corr_stats() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "📊 Statistiques des corrélations :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT statut, COUNT(*) AS 'Nombre'
              FROM correlations
              GROUP BY statut
              ORDER BY COUNT(*) DESC;" "$DB_NAME"
}

cmd_corr_rejects() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🚫 20 derniers rejets de corrélation :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT id, asset_id, cve_id, raison, created_at
              FROM correlation_rejects
              ORDER BY created_at DESC
              LIMIT 20;" "$DB_NAME"
}

cmd_corr_clear_rejects() {
    read -p "⚠️  Êtes-vous sûr de vouloir vider la table correlation_rejects ? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Annulé."
        exit 0
    fi
    if ! check_mariadb; then
        exit 1
    fi
    echo "🗑️  Vidage de la table correlation_rejects..."
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "TRUNCATE TABLE correlation_rejects;" "$DB_NAME"
    echo "✅ Table correlation_rejects vidée."
}

cmd_corr_top() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🏆 Top 10 des assets par nombre de corrélations :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT a.id, a.nom, COUNT(c.id) AS 'Nombre de corrélations'
              FROM assets a
              LEFT JOIN correlations c ON a.id = c.asset_id
              GROUP BY a.id, a.nom
              ORDER BY COUNT(c.id) DESC
              LIMIT 10;" "$DB_NAME"
}

# --- COMMANDES DOCUMENTS ------------------------------------------------------

cmd_docs_list() {
    if [ ! -d "$DOCS_DIR" ]; then
        echo "❌ Dossier documents introuvable : $DOCS_DIR"
        exit 1
    fi
    echo "📄 Liste des documents dans $DOCS_DIR :"
    ls -lh "$DOCS_DIR"/*.pdf 2>/dev/null || echo "   Aucun PDF trouvé."
}

cmd_docs_clear() {
    read -p "⚠️  Êtes-vous sûr de vouloir SUPPRIMER TOUS les PDFs ? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Annulé."
        exit 0
    fi
    if [ ! -d "$DOCS_DIR" ]; then
        echo "❌ Dossier documents introuvable : $DOCS_DIR"
        exit 1
    fi
    echo "🗑️  Suppression de tous les PDFs..."
    rm -f "$DOCS_DIR"/*.pdf
    echo "✅ Tous les PDFs ont été supprimés."
}

cmd_docs_size() {
    if [ ! -d "$DOCS_DIR" ]; then
        echo "❌ Dossier documents introuvable : $DOCS_DIR"
        exit 1
    fi
    local size=$(du -sh "$DOCS_DIR" 2>/dev/null | cut -f1)
    echo "📏 Taille totale de $DOCS_DIR : $size"
}

# --- COMMANDES CVE ------------------------------------------------------------

cmd_cve_stats() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "📊 Statistiques des CVE par vendor :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT vendor, COUNT(*) AS 'Nombre de CVE'
              FROM cve
              GROUP BY vendor
              ORDER BY COUNT(*) DESC
              LIMIT 20;" "$DB_NAME"
}

cmd_cve_last() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🆕 10 dernières CVE importées :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT id, cve_id, cvss_v3_score, published_date
              FROM cve
              ORDER BY published_date DESC
              LIMIT 10;" "$DB_NAME"
}

# --- COMMANDES AUDIT ----------------------------------------------------------

cmd_audit_assets() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Assets sans vendor NVD (jamais corrélés) :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT a.id, a.nom, a.vendor, a.produit
              FROM assets a
              LEFT JOIN product_vendors pv ON a.vendor = pv.vendor_name
              WHERE pv.id IS NULL AND a.vendor IS NOT NULL;" "$DB_NAME"
}

cmd_audit_os() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Assets sans OS normalisé :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT a.id, a.nom, a.os, a.os_version
              FROM assets a
              WHERE a.os IS NULL OR a.os = '';" "$DB_NAME"
}

cmd_audit_orphans() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Corrélations orphelines (sans asset ou CVE valide) :"
    mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
          -e "SELECT c.id, c.asset_id, c.cve_id
              FROM correlations c
              LEFT JOIN assets a ON c.asset_id = a.id
              LEFT JOIN cve cv ON c.cve_id = cv.id
              WHERE a.id IS NULL OR cv.id IS NULL;" "$DB_NAME"
}

# --- COMMANDES SYSTÈME --------------------------------------------------------

cmd_sys_info() {
    echo "💻 Informations système :"
    echo "   --- Mémoire ---"
    free -h
    echo ""
    echo "   --- CPU ---"
    lscpu | grep -E "Model name|CPU(s):|Thread(s) per core|Core(s) per socket"
    echo ""
    echo "   --- Température (si disponible) ---"
    if command_exists sensors; then
        sensors | head -n 5
    else
        echo "   (sensors non installé)"
    fi
    echo ""
    echo "   --- Uptime ---"
    uptime
}

cmd_sys_ports() {
    echo "🌐 Vérification des ports :"
    for port in 3000 8000; do
        if command_exists nc; then
            if nc -z localhost "$port" 2>/dev/null; then
                echo "   ✅ Port $port : OUVERT"
            else
                echo "   ❌ Port $port : FERMÉ"
            fi
        else
            echo "   ⚠️  netcat (nc) non installé. Impossible de vérifier le port $port."
        fi
    done
}

cmd_sys_services() {
    echo "🛠️  Statut des services :"
    if check_systemd; then
        for service in "$SERVICE_NAME" mariadb grafana-server; do
            if sudo systemctl list-unit-files | grep -q "$service"; then
                status=$(sudo systemctl is-active "$service" 2>/dev/null)
                echo "   $service : $status"
            else
                echo "   $service : ❌ Non installé"
            fi
        done
    else
        echo "   ⚠️  systemd non disponible. Vérification manuelle requise."
    fi
}

cmd_check_env() {
    echo "🔑 Vérification des variables d'environnement :"
    local env_vars=("DB_HOST" "DB_PORT" "DB_USER" "DB_NAME" "DB_PASSWORD" "NVD_API_KEY" "MISTRAL_API_KEY" "SERVER_IP" "MISTRAL_MODEL")
    local missing=0
    for var in "${env_vars[@]}"; do
        if [ -z "${!var}" ]; then
            echo "   ❌ $var : NON DÉFINI"
            missing=$((missing + 1))
        else
            echo "   ✅ $var : Définie"
        fi
    done
    if [ $missing -eq 0 ]; then
        echo "✅ Toutes les variables sont définies."
    else
        echo "⚠️  $missing variable(s) manquante(s)."
    fi
}

cmd_check_db() {
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Vérification de la base de données :"
    local tables=("clients" "sites" "assets" "cve" "correlations" "equipment_types" "product_vendors")
    for table in "${tables[@]}"; do
        count=$(mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" \
                     -e "SELECT COUNT(*) FROM $table;" "$DB_NAME" | tail -n 1)
        echo "   $table : $count entrées"
    done
    echo "✅ Connexion et requêtes réussies."
}

cmd_check_disk() {
    echo "💽 Espace disque :"
    echo "   --- Dossier documents ($DOCS_DIR) ---"
    if [ -d "$DOCS_DIR" ]; then
        du -sh "$DOCS_DIR" 2>/dev/null || echo "   (dossier vide ou inaccessible)"
    else
        echo "   ❌ Dossier introuvable"
    fi
    echo ""
    echo "   --- Dossier logs ($PROJECT_DIR/logs) ---"
    if [ -d "$PROJECT_DIR/logs" ]; then
        du -sh "$PROJECT_DIR/logs" 2>/dev/null || echo "   (dossier vide ou inaccessible)"
    else
        echo "   ❌ Dossier introuvable"
    fi
}

cmd_update_deps() {
    echo "🔄 Mise à jour des dépendances Python..."
    cd "$PROJECT_DIR" || exit 1
    if [ -f "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" -m pip install -r requirements.txt
    else
        pip install -r requirements.txt
    fi
    echo "✅ Mise à jour terminée."
}

cmd_version() {
    echo "📋 Versions des composants :"
    echo "   --- Python ---"
    python3 --version 2>/dev/null || echo "   (non trouvé)"
    echo ""
    echo "   --- FastAPI ---"
    if [ -f "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" -c "import fastapi; print(fastapi.__version__)" 2>/dev/null || echo "   (non installé)"
    else
        python3 -c "import fastapi; print(fastapi.__version__)" 2>/dev/null || echo "   (non installé)"
    fi
    echo ""
    echo "   --- MariaDB ---"
    mysql --version 2>/dev/null || echo "   (non trouvé)"
}

# --- DISPATCHER PRINCIPAL ----------------------------------------------------

# Dictionnaire des commandes (pour l'autocomplétion future)
declare -A COMMANDS=(
    # FastAPI
    ["start"]="cmd_fastapi_start"
    ["stop"]="cmd_fastapi_stop"
    ["restart"]="cmd_fastapi_restart"
    ["status"]="cmd_fastapi_status"

    # Logs
    ["logs"]="cmd_logs"
    ["logs-err"]="cmd_logs_err"
    ["logs-corr"]="cmd_logs_corr"

    # BDD
    ["db"]="cmd_db"
    ["db-connect"]="cmd_db_connect"
    ["db-backup"]="cmd_db_backup"
    ["db-schema"]="cmd_db_schema"
    ["db-size"]="cmd_db_size"
    ["db-vacuum"]="cmd_db_vacuum"
    ["db-check"]="cmd_db_check"

    # Corrélations
    ["correlate"]="cmd_correlate"
    ["corr-clear"]="cmd_corr_clear"
    ["corr-clear-asset"]="cmd_corr_clear_asset"
    ["corr-stats"]="cmd_corr_stats"
    ["corr-rejects"]="cmd_corr_rejects"
    ["corr-clear-rejects"]="cmd_corr_clear_rejects"
    ["corr-top"]="cmd_corr_top"

    # Documents
    ["docs-list"]="cmd_docs_list"
    ["docs-clear"]="cmd_docs_clear"
    ["docs-size"]="cmd_docs_size"

    # CVE
    ["cve-stats"]="cmd_cve_stats"
    ["cve-last"]="cmd_cve_last"

    # Audit
    ["audit-assets"]="cmd_audit_assets"
    ["audit-os"]="cmd_audit_os"
    ["audit-orphans"]="cmd_audit_orphans"

    # Système
    ["sys-info"]="cmd_sys_info"
    ["sys-ports"]="cmd_sys_ports"
    ["sys-services"]="cmd_sys_services"
    ["check-env"]="cmd_check_env"
    ["check-db"]="cmd_check_db"
    ["check-disk"]="cmd_check_disk"
    ["update-deps"]="cmd_update_deps"
    ["version"]="cmd_version"
)

# Vérifier les arguments
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

# Gérer --help ou -h
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

# Exécuter la commande
COMMAND="$1"
shift  # Retirer le premier argument

if [ -n "${COMMANDS[$COMMAND]}" ]; then
    ${COMMANDS[$COMMAND]} "$@"
else
    echo "❌ Commande inconnue : '$COMMAND'"
    echo "   Utilisez --help pour voir la liste des commandes."
    exit 1
fi