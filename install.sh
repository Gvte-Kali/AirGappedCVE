#!/usr/bin/env bash
# =============================================================================
#  Asset & Vulnerability Manager — Script d'installation
# =============================================================================
set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Variables ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/asset-manager"
SERVICE_USER="pwner"
SERVICE_NAME="asset-manager"
DB_NAME="asset_vuln_manager"
DB_USER="avea"
VENV_PATH="$INSTALL_DIR/venv"

# =============================================================================
# 0. Vérifications préalables
# =============================================================================
info "Vérification des prérequis..."
[[ $EUID -ne 0 ]] && error "Ce script doit être exécuté en root (sudo ./install.sh)"
command -v python3 &>/dev/null || error "python3 introuvable."

# =============================================================================
# 1. Dépendances système
# =============================================================================
info "Installation des dépendances système..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    mariadb-server \
    mariadb-client \
    libmariadb-dev \
    curl \
    git

# =============================================================================
# 2. Création de l'utilisateur système (si absent)
# =============================================================================
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Création de l'utilisateur système '$SERVICE_USER'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    info "Utilisateur '$SERVICE_USER' déjà existant."
fi

# =============================================================================
# 3. Création de l'arborescence du projet
# =============================================================================
info "Création des répertoires..."
mkdir -p "$INSTALL_DIR"/{config,data/nvd/{raw,cwe},infos,logs,routers,scripts,ui/static}

# =============================================================================
# 4. Clonage / copie des fichiers
# =============================================================================
# Décommentez et adaptez si vous clonez depuis GitHub :
#   git clone https://github.com/<votre-compte>/asset-manager "$INSTALL_DIR"
info "Fichiers du projet supposés présents dans $INSTALL_DIR."

# =============================================================================
# 5. Environnement virtuel Python
# =============================================================================
info "Création du virtualenv Python..."
python3 -m venv "$VENV_PATH"
source "$VENV_PATH/bin/activate"

info "Installation des dépendances Python..."
pip install --upgrade pip -q
pip install -r "$INSTALL_DIR/requirements.txt" -q

deactivate

# =============================================================================
# 6. Fichier .env (vierge)
# =============================================================================
info "Création du fichier .env..."
cat > "$INSTALL_DIR/.env" << 'EOF'
# SERVER INFOS
SERVER_IP=

# API Keys
NVD_API_KEY=
MISTRAL_API_KEY=
MISTRAL_MODEL=mistral-large-latest

# Database Infos
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=avea
DB_PASSWORD=
DB_NAME=asset_vuln_manager
EOF

# =============================================================================
# 7. Fichier config/secrets.json (vierge)
# =============================================================================
info "Création du fichier config/secrets.json..."
cat > "$INSTALL_DIR/config/secrets.json" << 'EOF'
{
  "mariadb": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "avea",
    "password": "",
    "database": "asset_vuln_manager"
  },
  "mistral": {
    "api_key": ""
  },
  "nvd": {
    "api_key": ""
  }
}
EOF

# =============================================================================
# 8. Base de données MariaDB
# =============================================================================
info "Démarrage de MariaDB..."
systemctl enable --now mariadb

info "Création de la base de données et de l'utilisateur MariaDB..."
DB_PASSWORD=$(python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(24)))")

mysql -u root << SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1'
    IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

# Injecter le mot de passe dans .env
sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${DB_PASSWORD}/" "$INSTALL_DIR/.env"

# Injecter le mot de passe dans secrets.json
python3 - << PYEOF
import json, pathlib
p = pathlib.Path("$INSTALL_DIR/config/secrets.json")
d = json.loads(p.read_text())
d["mariadb"]["password"] = "$DB_PASSWORD"
p.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PYEOF

info "Mot de passe MariaDB généré et injecté dans .env et config/secrets.json"

# =============================================================================
# 9. Scripts de démarrage
# =============================================================================
info "Création du script de démarrage..."
cat > "$INSTALL_DIR/logs/start.sh" << STARTEOF
#!/bin/bash
PROJECT_DIR="$INSTALL_DIR"
VENV_PATH="\$PROJECT_DIR/venv"

if [ -d "\$VENV_PATH" ]; then
    source "\$VENV_PATH/bin/activate"
fi

cd "\$PROJECT_DIR"

exec uvicorn main:app \\
    --host 0.0.0.0 \\
    --port 8000 \\
    --log-level info
STARTEOF
chmod +x "$INSTALL_DIR/logs/start.sh"

cat > "$INSTALL_DIR/start_fastapi.sh" << 'WRAPEOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/logs/start.sh"
WRAPEOF
chmod +x "$INSTALL_DIR/start_fastapi.sh"

# =============================================================================
# 10. Service systemd
# =============================================================================
info "Création du service systemd '$SERVICE_NAME'..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SVCEOF
[Unit]
Description=Asset & Vulnerability Manager — FastAPI
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/start_fastapi.sh
Restart=on-failure
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/FastAPI.log
StandardError=append:$INSTALL_DIR/logs/FastAPI.log

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# =============================================================================
# 11. Permissions
# =============================================================================
info "Application des permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/.env" "$INSTALL_DIR/config/secrets.json"

# =============================================================================
# 12. Résumé
# =============================================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Installation terminée avec succès !${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Répertoire     : $INSTALL_DIR"
echo "  Service        : $SERVICE_NAME"
echo "  Base de données: $DB_NAME  (user: $DB_USER)"
echo ""
warn "ÉTAPES OBLIGATOIRES avant de démarrer le service :"
echo "  1. Renseignez SERVER_IP      dans : $INSTALL_DIR/.env"
echo "  2. Renseignez NVD_API_KEY    dans : $INSTALL_DIR/.env"
echo "  3. Renseignez MISTRAL_API_KEY dans : $INSTALL_DIR/.env"
echo "     (et dans config/secrets.json)"
echo ""
echo "  Démarrer le service :"
echo "    sudo systemctl start $SERVICE_NAME"
echo ""
echo "  Suivre les logs :"
echo "    sudo journalctl -u $SERVICE_NAME -f"
echo "    tail -f $INSTALL_DIR/logs/FastAPI.log"
echo ""
