---
title: Guide d'installation
nav_order: 2
parent: Installation & Configuration
---

# 🛠️ Guide d'installation

**Procédure d'installation étape par étape avec commandes one-liner**

---

## ⚠️ Avant de commencer

1. Vérifiez les [prérequis]({{ site.baseurl }}/installation-configuration/prerequis)
2. Exécutez toutes les commandes en root (`sudo -i` ou `sudo` devant chaque commande)
3. Ne sautez aucune étape : Chaque commande dépend des précédentes

---

## 📌 Etape 0 : Préparation de l'environnement

### 1. Mise à jour du système

```bash
apt-get update && apt-get upgrade -y
```

### 2. Installation des outils de base

```bash
apt-get install -y curl wget git bc iproute2 procps software-properties-common
```

### 3. Installation des dépendances Python

```bash
apt-get install -y python3-venv python3-pip python3-dev build-essential
```

---

## 📌 Etape 1 : Installation de MariaDB

### 1. Installation de MariaDB

```bash
apt-get install -y mariadb-server mariadb-client
```

### 2. Démarrage et activation du service

```bash
systemctl enable mariadb && systemctl start mariadb
```

### 3. Sécurisation de MariaDB

```bash
mariadb -u root -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;"
```

### 4. Vérification

```bash
sudo systemctl status mariadb
```
Si vous voyez "active" c'est que le service tourne. ( fermer en appuyant sur 'q' )
---

## 📌 Etape 2 : Clone du dépôt

### 1. Suppression du dossier existant (si précédente installation présente sur le système)

```bash
rm -rf /opt/asset-manager
```

### 2. Création du dossier cible pour le projet et attribution des droits pour le user actuel

```bash
sudo mkdir -p /opt/asset-manager && sudo chown $USER:$USER /opt/asset-manager
```

### 3. Clone du projet github

```bash
git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
```

### 4. Vérification du clone

```bash
ls /opt/asset-manager/main.py /opt/asset-manager/requirements.txt /opt/asset-manager/sql/schema.sql
```

---

## 📌 Etape 3 : Configuration de l'environnement (.env)

### 1. Configuration du fichier .env

> ⚠️ Il est important que le fichier .env soit rempli avec toutes ses variables avant la suite de l'installation !

```bash
# SERVER INFOS
SERVER_IP=LAN_ip_of_the_server

# API Keys
NVD_API_KEY=your_nvd_api_key_here
MISTRAL_API_KEY=your_mistral_api_key_here
MISTRAL_MODEL=mistral-large-latest

# Database Infos
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_db_password_here
DB_NAME=asset_vuln_manager

```


### 2. Sécurisation du fichier .env
Donne l'accès au fichier uniquement à l'utilisateur ayant fait l'installation.
```bash
chmod 600 /opt/asset-manager/.env
```

---

## 📌 Etape 4 : Création du virtualenv et installation des dépendances Python

### 1. Création du virtualenv

```bash
python3 -m venv /opt/asset-manager/venv
```

### 2. Mise à jour de pip

```bash
/opt/asset-manager/venv/bin/pip install --upgrade pip
```

### 3. Installation des dépendances

```bash
source /opt/asset-manager/venv/bin/activate && /opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt
```

### 4. Vérification des dépendances critiques

```bash
source /opt/asset-manager/venv/bin/activate && /opt/asset-manager/venv/bin/pip show fastapi pymysql reportlab uvicorn python-dotenv >/dev/null && echo "OK - Toutes les dependances sont installees" || echo "ERREUR - Dependances manquantes"
```

---

## 📌 Etape 5 : Configuration de la base de données

> ⚠️ Si le fichier `.env` n'est pas correctement rempli, allez le remplir maintenant

### 1. Intégrer les variables du .env dans les prochaines commandes
```bash 
source /opt/asset-manager/.env
```

### 2. Setup de la base de données

Un script va gérer le setup de la base de données : 
```bash
sudo python3 /opt/asset-manager/scripts/setup_database.py
```

#### Si le script fonctionne, passer à l'étape 3

#### Si le script échoue, il va falloir manuellement gérer le setup en faisant ceci : 

Se connecter via `sudo mysql`puis taper les commandes suivantes en adaptant les variables par celles notées dans votre fichier `.env` :

```sql
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### 3. Import du schéma SQL

```bash
asset-manager db import-schema /opt/asset-manager/sql/schema.sql
```

### 3. Test de connexion

```bash
mariadb -u $DB_USER -p"$DB_PASSWORD" -e "SELECT 1;" && echo "OK - Connexion reussie" || echo "ERREUR - Echec de la connexion"
```

---

## 📌 Etape 6 : Configuration du service systemd

### 1. Copie du service dans le système de services du serveur

```bash
cp /opt/asset-manager/asset-manager.service /etc/systemd/system/asset-manager.service
```

### 2. Rechargement de systemd

```bash
systemctl daemon-reload
```

### 3. Activation et démarrage du service

```bash
systemctl enable asset-manager && systemctl start asset-manager
```

### 4. Vérification du service

```bash
systemctl status asset-manager
journalctl -u asset-manager -n 20
```

---

## 📌 Etape 7 : Ajout au PATH

### 1. Création d'un lien du script asset-manager vers /usr/local/bin/

```bash
sudo ln -sf /opt/asset-manager/scripts/asset-manager.sh /usr/local/bin/asset-manager && sudo chmod +x /usr/local/bin/asset-manager
```

### 2. Solution de repli en cas de non fonctionnement

Ajouter un alias dans votre fichier ~/.bashrc : 
Il faudra ajouter une ligne à la fin du fichier 
Cette ligne est `alias asset-manager='bash /opt/asset-manager/scripts/asset-manager.sh'`

Pour modifier le fichier : 
`nano ~/.bashrc` 
Pour sortir de l'éditeur et sauvegarder le fichier, faire "CTRL + X" puis "CTRL + Y" ( ou "CTRL + O" pour les configurations françaises)

---

## 📌 Etape 8 : Vérifications finales

### 1. Test du health endpoint FastAPI

```bash
curl -sf http://localhost:8000/health && echo "OK - FastAPI est operationnel" || echo "ERREUR - FastAPI ne repond pas"
```

### 2. Vérification des fichiers critiques

```bash
[ -f /opt/asset-manager/main.py ] && [ -f /opt/asset-manager/.env ] && [ -d /opt/asset-manager/venv ] && echo "OK - Installation complete" || echo "ERREUR - Fichiers manquants"
```

---

## 🎉 Résumé de l'installation

| Element | Chemin | Commande de test |
|---------|--------|-------------------|
| Application | /opt/asset-manager | ls /opt/asset-manager |
| Virtualenv | /opt/asset-manager/venv | ls /opt/asset-manager/venv/bin/python |
| Fichier .env | /opt/asset-manager/.env | cat /opt/asset-manager/.env |
| Service | asset-manager | systemctl status asset-manager |
| API | http://<IP>:8000 | curl -sf http://localhost:8000/health |
| Base de données | MariaDB (asset_vuln_manager) | sudo mysql |

---

## 📌 Dépannage

| Probleme | Solution |
|----------|----------|
| Port 8000 occupé | ss -tunlp | grep 8000 -> Tuez le processus avec kill -9 <PID> |
| MariaDB ne démarre pas, affichage des logs | journalctl -u mariadb -n 50 |
| FastAPI ne répond pas, affichage des logs | journalctl -u asset-manager -n 50 |
| Dépendances Python manquantes | /opt/asset-manager/venv/bin/pip install -r /opt/asset-manager/requirements.txt |
| Permission refusée | Exécutez les commandes en sudo |

---

## 🗑️ Désinstallation

Si vous devez tout désinstaller, exécutez :

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
La suppression de la Base de données n'est pas obligatoire car il est possible qu'il reste un autre composant qui utilise une base de données mariaDB sur le système.

Maintenant, vous pouvez faire la procédure de démarrage : 
- [1️⃣ Première Utilisation]({{ site.baseurl }}/installation-configuration/premiere-utilisation) - Procédure de démarrage