---
title: Installation
---

# 🛠️ **Installation - AirGappedCVE**
*Guide étape par étape avec commandes one-liner*

---

## **⚠️ Avant de commencer**

1. **Vérifiez les [prérequis](prerequis.html)**.
2. **Exécutez toutes les commandes en root** (`sudo -i` ou `sudo` devant chaque commande).
3. **Ne sautez aucune étape** : Chaque commande dépend des précédentes.

---

## **📌 Étape 0 : Préparation de l'environnement**

### **1. Mise à jour du système**
```bash
apt-get update && apt-get upgrade -y
```

### **2. Installation des outils de base**
```bash
apt-get install -y curl wget git bc iproute2 procps software-properties-common
```

### **3. Installation des dépendances Python**
```bash
apt-get install -y python3-venv python3-pip python3-dev build-essential
```

---

## **📌 Étape 1 : Installation de MariaDB**

### **1. Installation de MariaDB**
```bash
apt-get install -y mariadb-server mariadb-client
```

### **2. Démarrage et activation du service**
```bash
systemctl enable mariadb && systemctl start mariadb
```

### **3. Sécurisation de MariaDB**
```bash
mariadb -u root -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;"
```

### **4. Vérification**
```bash
ss -tunlp | grep 3306  # Doit afficher MariaDB en écoute
mariadb -u root -e "SELECT 1;"  # Doit retourner 1
```

---

## **📌 Étape 2 : Clone du dépôt**

### **1. Suppression du dossier existant (si nécessaire)**
```bash
rm -rf /opt/asset-manager
```

### **2. Clone du dépôt GitHub**
```bash
mkdir -p /opt/asset-manager && git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
```

### **3. Vérification du clone**
```bash
ls /opt/asset-manager/main.py /opt/asset-manager/requirements.txt /opt/asset-manager/sql/schema.sql
```

---

## **📌 Étape 3 : Configuration de l'environnement (.env)**

### **1. Création du fichier .env**
> **⚠️ Remplacez `avea_user` par votre nom d'utilisateur MariaDB !**

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
DB_USER=avea_user  # ← À personnaliser
DB_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)  # Généré automatiquement

# --- API KEYS (optionnelles) ---
NVD_API_KEY=
MISTRAL_API_KEY=
MISTRAL_MODEL=mistral-large-latest

# --- LOGGING ---
LOG_LEVEL=info
EOF
```

### **2. Sécurisation du fichier .env**
```bash
chmod 600 /opt/asset-manager/.env
```

---

## **📌 Étape 4 : Création du virtualenv et installation des dépendances Python**

### **1. Création du virtualenv**
```bash
python3 -m venv /opt/asset-manager/venv
```

### **2. Mise à jour de pip**
```bash
/opt/asset-manager/venv/bin/pip install --upgrade pip
```

### **3. Installation des dépendances**
```bash
/opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt
```

### **4. Vérification des dépendances critiques**
```bash
/opt/asset-manager/venv/bin/pip show fastapi pymysql reportlab uvicorn python-dotenv >/dev/null && echo "✅ Toutes les dépendances sont installées" || echo "❌ Dépendances manquantes"
```

---

## **📌 Étape 5 : Configuration de la base de données**

### **1. Création de la base et de l'utilisateur**
> **⚠️ Remplacez `avea_user` et `DB_PASSWORD` par vos valeurs !**

```bash
DB_USER=avea_user
DB_PASSWORD=$(grep DB_PASSWORD /opt/asset-manager/.env | cut -d'=' -f2)
mariadb -u root -e "CREATE DATABASE IF NOT EXISTS asset_vuln_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD'; CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD'; GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO '$DB_USER'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"
```

### **2. Import du schéma SQL**
```bash
mariadb -u avea_user -p"$DB_PASSWORD" asset_vuln_manager < /opt/asset-manager/sql/schema.sql
```

### **3. Test de connexion**
```bash
mariadb -u avea_user -p"$DB_PASSWORD" -e "SELECT 1;" && echo "✅ Connexion réussie" || echo "❌ Échec de la connexion"
```

---

## **📌 Étape 6 : Configuration du service systemd**

### **1. Création du fichier de service**
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

### **2. Rechargement de systemd**
```bash
systemctl daemon-reload
```

### **3. Activation et démarrage du service**
```bash
systemctl enable asset-manager && systemctl start asset-manager
```

### **4. Vérification du service**
```bash
systemctl status asset-manager
journalctl -u asset-manager -n 20  # Affiche les derniers logs
```

---

## **📌 Étape 7 : Ajout au PATH**

### **1. Création du fichier pour /etc/profile.d/**
```bash
cat > /etc/profile.d/asset-manager.sh << 'EOF'
#!/bin/bash
export PATH="$PATH:/opt/asset-manager/scripts"
EOF
chmod +x /etc/profile.d/asset-manager.sh
```

### **2. Ajout au .bashrc de l'utilisateur actuel**
```bash
if ! grep -q "asset-manager" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Ajouté par install.sh - AirGappedCVE" >> ~/.bashrc
    echo 'export PATH="$PATH:/opt/asset-manager/scripts"' >> ~/.bashrc
fi
```

### **3. Application immédiate**
```bash
export PATH="$PATH:/opt/asset-manager/scripts"
```

---

## **📌 Étape 8 : Vérifications finales**

### **1. Test du health endpoint FastAPI**
```bash
curl -sf http://localhost:8000/health && echo "✅ FastAPI est opérationnel" || echo "❌ FastAPI ne répond pas"
```

### **2. Vérification des fichiers critiques**
```bash
[ -f /opt/asset-manager/main.py ] && [ -f /opt/asset-manager/.env ] && [ -d /opt/asset-manager/venv ] && echo "✅ Installation complète" || echo "❌ Fichiers manquants"
```

---

## **🎉 Résumé de l'installation**

| Élément | Chemin | Commande de test |
|---------|--------|-------------------|
| **Application** | `/opt/asset-manager` | `ls /opt/asset-manager` |
| **Virtualenv** | `/opt/asset-manager/venv` | `ls /opt/asset-manager/venv/bin/python` |
| **Fichier .env** | `/opt/asset-manager/.env` | `cat /opt/asset-manager/.env` |
| **Service** | `asset-manager` | `systemctl status asset-manager` |
| **API** | `http://<IP>:8000` | `curl -sf http://localhost:8000/health` |
| **Base de données** | MariaDB (`asset_vuln_manager`) | `mariadb -u avea_user -p -e "SHOW TABLES;" asset_vuln_manager` |

---

## **📌 Dépannage**

| Problème | Solution |
|----------|----------|
| **Port 8000 occupé** | `ss -tunlp \| grep 8000` → Tuez le processus avec `kill -9 <PID>` |
| **MariaDB ne démarre pas** | `journalctl -u mariadb -n 50` |
| **FastAPI ne répond pas** | `journalctl -u asset-manager -n 50` |
| **Dépendances Python manquantes** | `/opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt` |
| **Permission refusée** | Exécutez les commandes en `sudo` |

---

## **🗑️ Désinstallation**

Si vous devez tout désinstaller, exécutez :
```bash
# Arrêt du service
systemctl stop asset-manager && systemctl disable asset-manager

# Suppression du service
rm -f /etc/systemd/system/asset-manager.service && systemctl daemon-reload

# Suppression du dossier
rm -rf /opt/asset-manager

# Suppression des entrées PATH
rm -f /etc/profile.d/asset-manager.sh
sed -i '/# Ajouté par install.sh - AirGappedCVE/,/export PATH.*asset-manager/d' ~/.bashrc
```
