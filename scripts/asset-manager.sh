#!/bin/bash

# =============================================================================
# asset-manager — CLI de maintenance pour AirGappedCVE
# Auteur : Gvte-Kali / Vibe Code
# Version : 1.1.0
# Description : Outil tout-en-un pour gérer la maintenance de la stack.
# =============================================================================
# --- CHEMIN RELATIF (fonctionne en dev et prod) ---
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

# Chemins relatifs au projet
LOG_FILE="$PROJECT_DIR/logs/FastAPI.log"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python"
DOCS_DIR="$PROJECT_DIR/documents"
BACKUP_DIR="$PROJECT_DIR/backups"

# Détection de l'environnement pour le nom du service
if [[ "$PROJECT_DIR" == "/opt/asset-manager" ]]; then
    SERVICE_NAME="asset-manager"
else
    SERVICE_NAME="asset-manager-dev"
fi

# --- CHARGEMENT DU FICHIER .env (méthode robuste) ---
ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key value; do
        # Ignorer les commentaires et les lignes vides
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # Supprimer les guillemets et espaces superflus
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')
        # Exporter la variable
        export "$key=$value"
    done < "$ENV_FILE"
fi

# --- VARIABLES PAR DÉFAUT (si non définies dans .env) ---
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-avea}"
DB_NAME="${DB_NAME:-asset_vuln_manager}"
DB_PASSWORD="${DB_PASSWORD:-}"
MISTRAL_API_KEY="${MISTRAL_API_KEY:-}"
NVD_API_KEY="${NVD_API_KEY:-}"

# --- CATÉGORIES ET COMMANDES ---
declare -A CATEGORIES=(
    ["fastapi"]="Gestion du service FastAPI (start/stop/restart/status)"
    ["logs"]="Affichage des logs (show)"
    ["db"]="Gestion de la base de données (connect, backup, import, schema, size, vacuum, check)"
    ["corr"]="Gestion des corrélations (launch)"
    ["docs"]="Gestion des documents PDF (list, clear, size)"
    ["cve"]="Statistiques et dernières CVE (show)"
    ["sys"]="Informations système (info, ports, services, env, disk, deps, version)"
)

declare -A COMMANDS=(
    # FastAPI
    ["fastapi:start"]="cmd_fastapi_start"
    ["fastapi:stop"]="cmd_fastapi_stop"
    ["fastapi:restart"]="cmd_fastapi_restart"
    ["fastapi:status"]="cmd_fastapi_status"

    # Logs
    ["logs:show"]="cmd_logs"

    # Base de données
    ["db:connect"]="cmd_db_connect"      # <-- "db:connect" au lieu de "db:db-connect"
    ["db:backup"]="cmd_db_backup"
    ["db:import"]="cmd_db_import"
    ["db:import-schema"]="cmd_db_import_schema"
    ["db:schema"]="cmd_db_schema"
    ["db:size"]="cmd_db_size"
    ["db:vacuum"]="cmd_db_vacuum"
    ["db:check"]="cmd_db_check"


    # Corrélations
    ["corr:launch"]="cmd_correlate"
    ["corr:clean"]="cmd_correlate_clean"

    # Documents
    ["docs:list"]="cmd_docs_list"        # <-- "docs:list" au lieu de "docs:docs-list"
    ["docs:clear"]="cmd_docs_clear"       # <-- "docs:clear" au lieu de "docs:docs-clear"
    ["docs:size"]="cmd_docs_size"         # <-- "docs:size" au lieu de "docs:docs-size"

    # CVE
    ["cve:show"]="cmd_cve_show"

    # Système
    ["sys:info"]="cmd_sys_info"           # <-- "sys:info" au lieu de "sys:sys-info"
    ["sys:ports"]="cmd_sys_ports"         # <-- "sys:ports" au lieu de "sys:sys-ports"
    ["sys:services"]="cmd_sys_services"   # <-- "sys:services" au lieu de "sys:sys-services"
    ["sys:check-env"]="cmd_check_env"
    ["sys:check-db"]="cmd_check_db"
    ["sys:check-disk"]="cmd_check_disk"
    ["sys:update-deps"]="cmd_update_deps"
    ["sys:version"]="cmd_version"
)

# --- FONCTIONS UTILITAIRES ---

# Afficher l'aide globale
show_help() {
    clear
    cat <<EOF
╔════════════════════════════════════════════════════════════════════════════╗
║                    ASSET-MANAGER CLI v1.1.0                                ║
║  Outil de maintenance pour AirGappedCVE (Gvte-Kali)                        ║
╚════════════════════════════════════════════════════════════════════════════╝

📌 ENVIRONNEMENT DÉTECTÉ :
   Project Dir : $PROJECT_DIR
   Mode        : $(if [[ "$PROJECT_DIR" == "/opt/asset-manager" ]]; then echo "PROD"; else echo "DEV"; fi)

📌 CATÉGORIES DISPONIBLES :
EOF

    for category in "${!CATEGORIES[@]}"; do
        printf "   %-12s %s\n" "$category" "${CATEGORIES[$category]}"
    done

    cat <<EOF

📌 USAGE :
   $0 <catégorie> [commande|help]

📌 EXEMPLES :
   $0 help                 # Affiche cette aide
   $0 logs help            # Affiche l'aide pour la catégorie "logs"
   $0 logs logs-err        # Filtre les erreurs dans les logs
   $0 db db-backup         # Effectue une sauvegarde de la BDD

📌 ALIAS RECOMMANDÉ :
   Ajoutez ceci à votre ~/.bashrc ou ~/.zshrc :
   alias asset-manager="$SCRIPT_DIR/asset-manager.sh"

EOF
}

# Afficher l'aide pour une catégorie
show_category_help() {
    clear
    local category="$1"
    if [[ -z "${CATEGORIES[$category]+x}" ]]; then
        echo "❌ Catégorie inconnue : '$category'"
        echo "Utilisez '$0 help' pour voir les catégories disponibles."
        exit 1
    fi

    echo "AIDE POUR LA CATÉGORIE \"$category\" :"
    echo "   ${CATEGORIES[$category]}"
    echo ""
    echo "COMMANDES DISPONIBLES :"

    for cmd in "${!COMMANDS[@]}"; do
        if [[ "$cmd" == "$category:"* ]]; then
            local subcmd="${cmd#$category:}"
            local func_name="${COMMANDS[$cmd]}"
            local desc=""
            case "$func_name" in
                "cmd_fastapi_start") desc="Démarre le service FastAPI" ;;
                "cmd_fastapi_stop") desc="Arrête le service FastAPI" ;;
                "cmd_fastapi_restart") desc="Redémarre le service FastAPI" ;;
                "cmd_fastapi_status") desc="Affiche le statut du service FastAPI" ;;
                "cmd_logs") desc="Affiche les logs" ;;
                "cmd_db") desc="Affiche la commande MySQL pour se connecter" ;;
                "cmd_db_connect") desc="Se connecte directement à MariaDB" ;;
                "cmd_db_backup") desc="Effectue un dump complet de la BDD" ;;
                "cmd_db_import") desc="Importe un fichier SQL vers la BDD" ;;
                "cmd_db_import_schema") desc="Importe le schéma SQL par défaut" ;;
                "cmd_db_schema") desc="Génère le schéma SQL de la BDD" ;;
                "cmd_db_size") desc="Affiche la taille des tables en Mo" ;;
                "cmd_db_vacuum") desc="Optimise les tables corrélations et cve" ;;
                "cmd_db_check") desc="Vérifie l'intégrité des tables" ;;
                "cmd_correlate") desc="Lance le pipeline de corrélation + analyse" ;;
                "cmd_correlate_clean") desc="Supprime toutes les corrélations CVEs pour repartir à zéro" ;;
                "cmd_docs_list") desc="Liste les PDFs avec taille et date" ;;
                "cmd_docs_clear") desc="Supprime TOUS les PDFs (avec confirmation)" ;;
                "cmd_docs_size") desc="Affiche la taille totale du dossier documents" ;;
                "cmd_cve_show") desc="Affiche le COUNT des CVE par vendor" ;;
                "cmd_sys_info") desc="Affiche RAM, CPU, température, uptime" ;;
                "cmd_sys_ports") desc="Vérifie les ports 3000 (Grafana) et 8000 (FastAPI)" ;;
                "cmd_sys_services") desc="Affiche le statut de FastAPI, MariaDB, Grafana" ;;
                "cmd_check_env") desc="Vérifie que les variables .env sont présentes" ;;
                "cmd_check_db") desc="Vérifie la connexion à la BDD + COUNT des tables" ;;
                "cmd_check_disk") desc="Affiche l'espace disque (documents + logs)" ;;
                "cmd_update_deps") desc="Met à jour les dépendances Python" ;;
                "cmd_version") desc="Affiche les versions de Python, FastAPI, MariaDB" ;;
            esac
            printf "   %-20s %s\n" "$subcmd" "$desc"
        fi
    done
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
    if ! mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl -e "SELECT 1;" "$DB_NAME" >/dev/null 2>&1; then
        echo "❌ ERREUR : Impossible de se connecter à MariaDB."
        echo "   Vérifiez DB_HOST, DB_PORT, DB_USER, DB_PASSWORD dans .env"
        return 1
    fi
    return 0
}

# Vérifier si systemd est disponible
check_systemd() {
    # Vérifie si systemctl existe ET si systemd est le PID 1 (pour éviter les faux positifs dans Docker)
    if ! command_exists systemctl; then
        return 1
    fi
    if [ "$(ps -p 1 -o comm= 2>/dev/null)" != "systemd" ]; then
        return 1
    fi
    return 0
}

# --- COMMANDES FASTAPI ---

cmd_fastapi_start() {
    clear
    if ! check_systemd; then
        echo "⚠️  systemd non disponible. Utilisation du script de fallback..."
        if [ -f "$PROJECT_DIR/scripts/fastapi/start.sh" ]; then
            bash "$PROJECT_DIR/scripts/fastapi/start.sh"
        else
            echo "❌ Impossible de démarrer FastAPI : ni systemd ni script de fallback trouvé."
            exit 1
        fi
        return
    fi
    echo "🚀 Démarrage du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl start "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_stop() {
    clear
    if ! check_systemd; then
        echo "⚠️  systemd non disponible. Utilisation du script de fallback..."
        if [ -f "$PROJECT_DIR/scripts/fastapi/stop.sh" ]; then
            bash "$PROJECT_DIR/scripts/fastapi/stop.sh"
        else
            echo "❌ Impossible d'arrêter FastAPI : ni systemd ni script de fallback trouvé."
            exit 1
        fi
        return
    fi
    echo "🛑 Arrêt du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl stop "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_restart() {
    clear
    if ! check_systemd; then
        echo "⚠️  systemd non disponible. Utilisation du script de fallback..."
        if [ -f "$PROJECT_DIR/scripts/fastapi/reload.sh" ]; then
            bash "$PROJECT_DIR/scripts/fastapi/reload.sh"
        else
            echo "❌ Impossible de redémarrer FastAPI : ni systemd ni script de fallback trouvé."
            exit 1
        fi
        return
    fi
    echo "🔄 Redémarrage du service FastAPI ($SERVICE_NAME)..."
    sudo systemctl restart "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

cmd_fastapi_status() {
    clear
    if ! check_systemd; then
        echo "⚠️  systemd non disponible. Utilisation du script de fallback..."
        if [ -f "$PROJECT_DIR/scripts/fastapi/status.sh" ]; then
            bash "$PROJECT_DIR/scripts/fastapi/status.sh"
        else
            echo "⚠️  Aucun script de fallback trouvé. Vérification manuelle..."
            if pgrep -f "uvicorn.*main:app" >/dev/null; then
                PID=$(pgrep -f "uvicorn.*main:app")
                PORT=$(grep -oP 'port=\K[0-9]+' "$PROJECT_DIR/main.py" || echo "8000")
                echo "✅ FastAPI est en cours d'exécution (PID: $PID, Port: $PORT)"
            else
                echo "❌ FastAPI n'est pas en cours d'exécution."
            fi
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

# --- COMMANDES LOGS ---

cmd_logs() {
    clear
    if [ ! -f "$LOG_FILE" ]; then
        echo "❌ Fichier de log introuvable : $LOG_FILE"
        echo "   Vérifiez LOG_FILE dans .env ou l'emplacement du projet."
        exit 1
    else
        echo "📜 Affichage de $LOG_FILE :"
        tail -f "$LOG_FILE"
    fi
}


# --- COMMANDES BASE DE DONNÉES ---

cmd_db() {
    clear
    echo "🗃️  Commande MySQL pour se connecter à $DB_NAME :"
    echo "   mysql --skip-ssl --host=$DB_HOST --port=$DB_PORT --user=$DB_USER --password=$DB_PASSWORD --skip-ssl $DB_NAME"
}

cmd_db_connect() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔌 Connexion à MariaDB ($DB_NAME)..."
    mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl "$DB_NAME"
}

cmd_db_backup() {
    clear
    if ! check_mariadb; then
        exit 1
    fi

    local compress=true
    local backup_file
    local temp_file=""
    local timestamp=$(date +"%Y%m%d_%H%M%S")

    # Vérifier si l'utilisateur veut un fichier non compressé
    if [[ "$1" == "--no-compress" || "$1" == "-n" ]]; then
        compress=false
        shift
    fi

    # Définir le nom du fichier de sauvegarde (même format que backup.sh)
    if [ $# -gt 0 ]; then
        # Si un nom personnalisé est fourni, l'utiliser
        backup_file="$1"
    else
        # Sinon, utiliser le format par défaut : backup_<DB_NAME>_YYYYMMDD_HHMMSS.sql
        backup_file="$BACKUP_DIR/backup_${DB_NAME}_${timestamp}.sql"
    fi

    if [ "$compress" = true ]; then
        backup_file="${backup_file}.gz"
        temp_file=$(mktemp)
    fi

    echo "💾 Sauvegarde de $DB_NAME vers $backup_file..."
    mysqldump --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
              --single-transaction --routines --triggers --events "$DB_NAME" > "${temp_file:-$backup_file}"

    if [ $? -ne 0 ]; then
        echo "❌ Échec de la sauvegarde."
        rm -f "$temp_file"
        exit 1
    fi

    if [ "$compress" = true ]; then
        echo "🗜️ Compression du fichier..."
        if gzip -c "$temp_file" > "$backup_file"; then
            echo "✅ Sauvegarde compressée terminée : $backup_file"
            rm -f "$temp_file"
        else
            echo "❌ Échec de la compression."
            rm -f "$temp_file"
            exit 1
        fi
    else
        echo "✅ Sauvegarde terminée : $backup_file"
    fi

    ls -lh "$backup_file"
}

cmd_db_schema() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    local schema_file="$PROJECT_DIR/sql/schema.sql"
    echo "📄 Génération du schéma vers $schema_file..."
    mysqldump --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
              --no-data --routines --triggers "$DB_NAME" > "$schema_file"
    if [ $? -eq 0 ]; then
        echo "✅ Schéma généré : $schema_file"
    else
        echo "❌ Échec de la génération du schéma."
        exit 1
    fi
}

cmd_db_size() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "📏 Taille des tables de $DB_NAME (en Mo) :"
    mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
          -e "SELECT table_name AS 'Table',
                     ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Taille (Mo)'
              FROM information_schema.TABLES
              WHERE table_schema = '$DB_NAME'
              ORDER BY (data_length + index_length) DESC;" "$DB_NAME"
}

cmd_db_vacuum() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "🧹 Optimisation des tables corrélations et cve..."
    mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
          -e "OPTIMIZE TABLE correlations, cve;" "$DB_NAME"
    echo "✅ Optimisation terminée."
}

cmd_db_check() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Vérification de l'intégrité des tables..."
    mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
          -e "CHECK TABLE clients, sites, assets, cve, correlations, equipment_types;" "$DB_NAME"
    echo "✅ Vérification terminée."
}

cmd_db_import() {
    clear
    if [ $# -eq 0 ]; then
        echo "❌ Usage : asset-manager db import <fichier.sql[.gz]>"
        echo "   Exemple : asset-manager db import /chemin/vers/backup.sql"
        echo "   Exemple : asset-manager db import /chemin/vers/backup.sql.gz"
        exit 1
    fi

    local sql_file="$1"
    if [ ! -f "$sql_file" ]; then
        echo "❌ Fichier introuvable : $sql_file"
        exit 1
    fi

    if ! check_mariadb; then
        exit 1
    fi

    local temp_file=""
    if [[ "$sql_file" == *.gz ]]; then
        echo "🔍 Décompression de $sql_file..."
        temp_file=$(mktemp)
        if ! gunzip -c "$sql_file" > "$temp_file"; then
            echo "❌ Échec de la décompression du fichier .gz."
            rm -f "$temp_file"
            exit 1
        fi
        sql_file="$temp_file"
    fi

    echo "📥 Import du fichier $1 vers $DB_NAME..."
    if mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl "$DB_NAME" < "$sql_file"; then
        echo "✅ Import terminé avec succès."
    else
        echo "❌ Échec de l'import. Vérifiez le fichier SQL et les permissions."
        rm -f "$temp_file"
        exit 1
    fi

    rm -f "$temp_file"
}

cmd_db_import_schema() {
    clear
    local schema_file="${1:-$PROJECT_DIR/sql/schema.sql}"

    if [ ! -f "$schema_file" ]; then
        echo "❌ Fichier schema.sql introuvable : $schema_file"
        echo "   Utilisation : asset-manager db import-schema [/chemin/vers/schema.sql]"
        exit 1
    fi

    if ! check_mariadb; then
        exit 1
    fi

    echo "📥 Import du schéma SQL ($schema_file) vers $DB_NAME..."
    cmd_db_import "$schema_file"
}

# --- COMMANDES CORRÉLATIONS ---

cmd_correlate() {
    clear
    echo "🔄 Lancement du pipeline de corrélation + analyse..."
    cd "$PROJECT_DIR" || exit 1
    if [ -f "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" "$PROJECT_DIR/scripts/correlate_and_analyze.py"
    else
        python3 "$PROJECT_DIR/scripts/correlate_and_analyze.py"
    fi
}

cmd_correlate_clean() {
    clear
    echo -e "${RED}${BOLD}⚠️  ATTENTION : Cette opération va SUPPRIMER toutes les corrélations existantes !${NC}"
    echo ""
    echo "Cette action est IRRÉVERSIBLE et va :"
    echo "  - Supprimer toutes les entrées de la table 'correlations'"
    echo "  - Supprimer toutes les entrées de la table 'correlation_rejects'"
    echo "  - Vous devrez relancer une analyse complète après cette opération"
    echo ""

    # Première confirmation
    read -rp "Voulez-vous vraiment supprimer toutes les corrélations ? ([N]on/[O]ui) : " CONFIRM1
    if [[ ! "$CONFIRM1" =~ ^[OoYy]$ ]]; then
        echo -e "${YELLOW}Opération annulée.${NC}"
        return 0
    fi

    # Deuxième confirmation avec le mot exact
    read -rp "Tapez 'SUPPRIMER' pour confirmer définitivement : " CONFIRM2
    if [[ "$CONFIRM2" != "SUPPRIMER" ]]; then
        echo -e "${YELLOW}Opération annulée.${NC}"
        return 0
    fi

    # Vérification de la connexion à la base
    if ! check_mariadb; then
        return 1
    fi

    echo -e "${CYAN}Suppression des corrélations en cours...${NC}"

    # Suppression des corrélations
    if mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" -e "DELETE FROM correlations;" "$DB_NAME" 2>/dev/null; then
        echo -e "${GREEN}✓ Table 'correlations' vidée${NC}"
    else
        echo -e "${RED}✗ Erreur lors de la suppression des corrélations${NC}"
        return 1
    fi

    # Suppression des rejets de corrélation
    if mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" -e "DELETE FROM correlation_rejects;" "$DB_NAME" 2>/dev/null; then
        echo -e "${GREEN}✓ Table 'correlation_rejects' vidée${NC}"
    else
        echo -e "${RED}✗ Erreur lors de la suppression des rejets${NC}"
        return 1
    fi

    # Compter pour vérifier
    COUNT=$(mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" -e "SELECT COUNT(*) as cnt FROM correlations;" "$DB_NAME" 2>/dev/null | awk 'NR==2 {print $1}')

    if [[ "$COUNT" == "0" ]]; then
        echo ""
        echo -e "${GREEN}${BOLD}✅ Toutes les corrélations ont été supprimées avec succès !${NC}"
        echo ""
        echo "Vous pouvez maintenant relancer une analyse complète avec :"
        echo "  asset-manager corr launch"
    else
        echo -e "${RED}✗ Il reste encore $COUNT corrélations${NC}"
        return 1
    fi
}

# --- COMMANDES DOCUMENTS ---

cmd_docs_list() {
    clear
    if [ ! -d "$DOCS_DIR" ]; then
        echo "❌ Dossier documents introuvable : $DOCS_DIR"
        exit 1
    fi
    echo "📄 Liste des documents dans $DOCS_DIR :"
    ls -lh "$DOCS_DIR"/*.pdf 2>/dev/null || echo "   Aucun PDF trouvé."
}

cmd_docs_clear() {
    clear
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
    clear
    if [ ! -d "$DOCS_DIR" ]; then
        echo "❌ Dossier documents introuvable : $DOCS_DIR"
        exit 1
    fi
    local size=$(du -sh "$DOCS_DIR" 2>/dev/null | cut -f1)
    echo "📏 Taille totale de $DOCS_DIR : $size"
}

# --- COMMANDES CVE ---

cmd_cve_show() {
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "📊 Statistiques des CVE par statut :"
    mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
          -e "SELECT
                  s.statut,
                  COUNT(c.id) AS nombre_cve
              FROM (
                  SELECT 'nouveau' AS statut UNION ALL
                  SELECT 'en_analyse' UNION ALL
                  SELECT 'confirme' UNION ALL
                  SELECT 'faux_positif' UNION ALL
                  SELECT 'patche'
              ) s
              LEFT JOIN correlations c ON s.statut = c.statut
              GROUP BY s.statut
              ORDER BY FIELD(s.statut, 'nouveau', 'en_analyse', 'confirme', 'faux_positif', 'patche');" "$DB_NAME" | \
          awk 'NR==1 {print; next} {print $1 ": " $2}'
}


# --- COMMANDES SYSTÈME ---

cmd_sys_info() {
    clear
    echo "💻 Informations système :"
    echo "   --- Mémoire ---"
    free -h
    echo ""
    echo "   --- CPU ---"
    lscpu | grep -E "Model name|CPU\(s\):|Thread\(s\) per core|Core\(s\) per socket"
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
    clear
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
    clear
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
    clear
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
    clear
    if ! check_mariadb; then
        exit 1
    fi
    echo "🔍 Vérification de la base de données :"
    local tables=("clients" "sites" "assets" "cve" "correlations" "equipment_types" "product_vendors")
    for table in "${tables[@]}"; do
        count=$(mysql --skip-ssl --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password="$DB_PASSWORD" --skip-ssl \
                     -e "SELECT COUNT(*) FROM $table;" "$DB_NAME" | tail -n 1)
        echo "   $table : $count entrées"
    done
    echo "✅ Connexion et requêtes réussies."
}

cmd_check_disk() {
    clear
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
    clear
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
    clear
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

# --- DISPATCHER PRINCIPAL ---

if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

# Gestion de l'aide globale
if [[ "$1" == "help" || "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

# Vérifier si le premier argument est une catégorie
if [[ -n "${CATEGORIES[$1]+x}" ]]; then
    CATEGORY="$1"
    shift
    if [ $# -eq 0 ] || [[ "$1" == "help" ]]; then
        show_category_help "$CATEGORY"
        exit 0
    fi
    COMMAND="${CATEGORY}:$1"
    shift
else
    # Si ce n'est pas une catégorie, essayer de trouver une commande directe (pour la rétrocompatibilité)
    COMMAND="$1"
    shift
fi

# Exécuter la commande
if [ -n "${COMMANDS[$COMMAND]}" ]; then
    ${COMMANDS[$COMMAND]} "$@"
else
    echo "❌ Commande ou catégorie inconnue : '$COMMAND'"
    echo "Utilisez '$0 help' ou '$0 <catégorie> help' pour l'aide."
    exit 1
fi