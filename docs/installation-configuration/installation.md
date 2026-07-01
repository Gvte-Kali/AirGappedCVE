---
title: Guide d'installation
nav_order: 2
parent: Installation & Configuration
---

# \ud83d\udee0\ufe0f Guide d'installation

**Proc\u00e9dure d'installation \u00e9tape par \u00e9tape avec commandes one-liner**

---

## \u26a0\ufe0f Avant de commencer

1. V\u00e9rifiez les [pr\u00e9requis]({{ site.baseurl }}/installation-configuration/prerequis)
2. Ex\u00e9cutez toutes les commandes en root (`sudo -i` ou `sudo` devant chaque commande)
3. Ne sautez aucune \u00e9tape : Chaque commande d\u00e9pend des pr\u00e9c\u00e9dentes

---

## \ud83d\udccc Etape 0 : Pr\u00e9paration de l'environnement

### 1. Mise \u00e0 jour du syst\u00e8me

```bash
apt-get update && apt-get upgrade -y
```

### 2. Installation des outils de base

```bash
apt-get install -y curl wget git bc iproute2 procps software-properties-common
```

### 3. Installation des d\u00e9pendances Python

```bash
apt-get install -y python3-venv python3-pip python3-dev build-essential
```

---

## \ud83d\udccc Etape 1 : Installation de MariaDB

### 1. Installation de MariaDB

```bash
apt-get install -y mariadb-server mariadb-client
```

### 2. D\u00e9marrage et activation du service

```bash
systemctl enable mariadb && systemctl start mariadb
```

### 3. S\u00e9curisation de MariaDB

```bash
mariadb -u root -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;"
```

### 4. V\u00e9rification

```bash
ss -tunlp | grep 3306
mariadb -u root -e "SELECT 1;"
```

---

## \ud83d\udccc Etape 2 : Clone du d\u00e9p\u00f4t

### 1. Suppression du dossier existant (si n\u00e9cessaire)

```bash
rm -rf /opt/asset-manager
```

### 2. Clone du d\u00e9p\u00f4t GitHub

```bash
mkdir -p /opt/asset-manager && git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
```

### 3. V\u00e9rification du clone

```bash
ls /opt/asset-manager/main.py /opt/asset-manager/requirements.txt /opt/asset-manager/sql/schema.sql
```

---

## \ud83d\udccc Etape 3 : Configuration de l'environnement (.env)

### 1. Cr\u00e9ation du fichier .env

> \u26a0\ufe0f Remplacez `avea_user` par votre nom d'utilisateur MariaDB !

```bash
cat > /opt/asset-manager/.env << 'EOF'
# =============================================================================
# Fichier de configuration - AirGappedCVE
# =============================================================================

# --- SERVER ---
SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
SERVER_PORT=8000

# --- DATABASE ---
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=asset_vuln_manager
DB_USER=avea_user
DB_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)

# --- API KEYS (optionnelles) ---
NVD_API_KEY=
MISTRAL_API_KEY=
MISTRAL_MODEL=mistral-large-latest

# --- LOGGING ---
LOG_LEVEL=info
EOF
```

### 2. S\u00e9curisation du fichier .env

```bash
chmod 600 /opt/asset-manager/.env
```

---

## \ud83d\udccc Etape 4 : Cr\u00e9ation du virtualenv et installation des d\u00e9pendances Python

### 1. Cr\u00e9ation du virtualenv

```bash
python3 -m venv /opt/asset-manager/venv
```

### 2. Mise \u00e0 jour de pip

```bash
/opt/asset-manager/venv/bin/pip install --upgrade pip
```

### 3. Installation des d\u00e9pendances

```bash
/opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt
```

### 4. V\u00e9rification des d\u00e9pendances critiques

```bash
/opt/asset-manager/venv/bin/pip show fastapi pymysql reportlab uvicorn python-dotenv >/dev/null && echo "OK - Toutes les dependances sont installees" || echo "ERREUR - Dependances manquantes"
```

---

## \ud83d\udccc Etape 5 : Configuration de la base de donn\u00e9es

### 1. Cr\u00e9ation de la base et de l'utilisateur

> \u26a0\ufe0f Remplacez `avea_user` et `DB_PASSWORD` par vos valeurs !

```bash
DB_USER=avea_user
DB_PASSWORD=$(grep DB_PASSWORD /opt/asset-manager/.env | cut -d'=' -f2)
mariadb -u root -e "CREATE DATABASE IF NOT EXISTS asset_vuln_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO '$DB_USER'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"
```

### 2. Import du sch\u00e9ma SQL

```bash
mariadb -u avea_user -p"$DB_PASSWORD" asset_vuln_manager < /opt/asset-manager/sql/schema.sql
```

### 3. Test de connexion

```bash
mariadb -u avea_user -p"$DB_PASSWORD" -e "SELECT 1;" && echo "OK - Connexion reussie" || echo "ERREUR - Echec de la connexion"
```

---

## \ud83d\udccc Etape 6 : Configuration du service systemd

### 1. Cr\u00e9ation du fichier de service

```bash
cat > /etc/systemd/system/asset-manager.service << 'EOF'
[Unit]
Description=AirGappedCVE - Asset & Vulnerability Manager
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/asset-manager
EnvironmentFile=/opt/asset-manager/.env
ExecStart=/opt/asset-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
Restart=on-failure
RestartSec=5
StandardOutput=append:/opt/asset-manager/logs/FastAPI.log
StandardError=append:/opt/asset-manager/logs/FastAPI.log

[Install]
WantedBy=multi-user.target
EOF
```

### 2. Rechargement de systemd

```bash
systemctl daemon-reload
```

### 3. Activation et d\u00e9marrage du service

```bash
systemctl enable asset-manager && systemctl start asset-manager
```

### 4. V\u00e9rification du service

```bash
systemctl status asset-manager
journalctl -u asset-manager -n 20
```

---

## \ud83d\udccc Etape 7 : Ajout au PATH

### 1. Cr\u00e9ation du fichier pour /etc/profile.d/

```bash
cat > /etc/profile.d/asset-manager.sh << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF
chmod +x /etc/profile.d/asset-manager.sh
```

### 2. Ajout au .bashrc de l'utilisateur actuel

```bash
if ! grep -q "asset-manager" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Ajoute par install.sh - AirGappedCVE" >> ~/.bashrc
    echo 'export PATH="$PATH:/opt/asset-manager/scripts"' >> ~/.bashrc
fi
```

### 3. Application imm\u00e9diate

```bash
export PATH="$PATH:/opt/asset-manager/scripts"
```

---

## \ud83d\udccc Etape 8 : V\u00e9rifications finales

### 1. Test du health endpoint FastAPI

```bash
curl -sf http://localhost:8000/health && echo "OK - FastAPI est operationnel" || echo "ERREUR - FastAPI ne repond pas"
```

### 2. V\u00e9rification des fichiers critiques

```bash
[ -f /opt/asset-manager/main.py ] && [ -f /opt/asset-manager/.env ] && [ -d /opt/asset-manager/venv ] && echo "OK - Installation complete" || echo "ERREUR - Fichiers manquants"
```

---

## \ud83c\udf89 R\u00e9sum\u00e9 de l'installation

| Element | Chemin | Commande de test |
|---------|--------|-------------------|
| Application | /opt/asset-manager | ls /opt/asset-manager |
| Virtualenv | /opt/asset-manager/venv | ls /opt/asset-manager/venv/bin/python |
| Fichier .env | /opt/asset-manager/.env | cat /opt/asset-manager/.env |
| Service | asset-manager | systemctl status asset-manager |
| API | http://<IP>:8000 | curl -sf http://localhost:8000/health |
| Base de donn\u00e9es | MariaDB (asset_vuln_manager) | mariadb -u avea_user -p -e "SHOW TABLES;" asset_vuln_manager |

---

## \ud83d\udccc D\u00e9pannage

| Probleme | Solution |
|----------|----------|
| Port 8000 occup\u00e9 | ss -tunlp | grep 8000 -> Tuez le processus avec kill -9 <PID> |
| MariaDB ne d\u00e9marre pas | journalctl -u mariadb -n 50 |
| FastAPI ne r\u00e9pond pas | journalctl -u asset-manager -n 50 |
| D\u00e9pendances Python manquantes | /opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt |
| Permission refus\u00e9e | Ex\u00e9cutez les commandes en sudo |

---

## \ud83d\uddd1\ufe0f D\u00e9sinstallation

Si vous devez tout d\u00e9sinstaller, ex\u00e9cutez :

```bash
# Arret du service
systemctl stop asset-manager && systemctl disable asset-manager

# Suppression du service
rm -f /etc/systemd/system/asset-manager.service && systemctl daemon-reload

# Suppression du dossier
rm -rf /opt/asset-manager

# Suppression des entrees PATH
rm -f /etc/profile.d/asset-manager.sh
sed -i '/# Ajoute par install.sh - AirGappedCVE/,/export PATH.*asset-manager/d' ~/.bashrc
```
