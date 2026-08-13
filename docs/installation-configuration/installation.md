---
title: Guide d'installation
nav_order: 2
parent: Installation & Configuration
---

# 🛠️ Guide d'installation

**Procédure d'installation étape par étape avec commandes one-liner**

Overview des étapes :

1. Préparation de l'environnement
2. Installation de MariaDB
3. Cloner le dépôt
4. Configuration de l'environnement (.env)
5. Création du virtualenv et installation des dépendances Python
6. Configuration de la base de données
7. Configuration du service systemd
8. Ajout au PATH
9. Vérifications finales

---

## ⚠️ Avant de commencer

1. Vérifiez les [prérequis]({{ site.baseurl }}/installation-configuration/prerequis)
2. Exécutez toutes les commandes en root (`sudo -i` ou `sudo` devant chaque commande)
3. Ne sautez aucune étape : Chaque commande dépend des précédentes

---

## 📌 Etape 1 : Préparation de l'environnement

### 1. Mise à jour du système

```bash
sudo apt-get update && apt-get upgrade -y
```

### 2. Installation des outils de base et des dépendances python

```bash
sudo apt-get install -y curl wget git bc iproute2 procps software-properties-common rsync openssh-client gzip cifs-utils python3-venv python3-pip python3-dev build-essential
```
**⚠️ Il est possible que certains paquets ne soient pas dans la bonne version sur des machines ARM.** 

Si c'est le cas, je vous conseille d'installer aptitude, et de l'utiliser à la place de _apt-get_ afin qu'il propose des solutions en cas de conflit de versions.

De ce que j'ai pu tester, la meilleure solution est de downgrade les paquets vers la version correspondante ( répondre 'y' au choix 2 normalement ).


---

## 📌 Etape 2 : Installation de MariaDB

### 1. Installation de MariaDB

```bash
sudo apt-get install -y mariadb-server mariadb-client
```

### 2. Démarrage et activation du service

```bash
sudo systemctl enable --now mariadb
```

### 3. Sécurisation de MariaDB
Suivre les recommendations dans cette commande
```bash
sudo mariadb-secure-installation
```

Pour une installation plutôt sécurisée, je conseille ces choix : 

- Ne pas switcher sur l'authentification unix_socket
- Ne pas changer le mot de passe d'accès root
- Enlever l'utilisateur 'anonymous'
- Enlever le remote login de l'utilisateur root ( accès uniquement en sudo mysql )
- Enlever la base de test
- Recharger la table des privilèges

### 4. Vérification

```bash
sudo systemctl status mariadb
```
Si vous voyez "active" c'est que le service tourne. ( fermer en appuyant sur 'q' )

---

## 📌 Etape 3 : Clone du dépôt

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

### 5. Aller dans le dossier d'installation

```bash
cd /opt/asset-manager
```

---

## 📌 Etape 4 : Configuration de l'environnement (.env)

### 1. Configuration du fichier .env 

> ⚠️ Il est important que le fichier .env soit rempli avec toutes ses variables avant la suite de l'installation !

Il faut déjà renommer le fichier'.env.example' en '.env'
```bash
mv /opt/asset-manager/.env.example /opt/asset-manager/.env
```

Pour modifier le fichier : 
```bash 
nano .env
```
Il faudra modifier toutes les variables suivantes

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
Donne l'accès en lecture et en écriture uniquement au groupe ayant accès à sudo.
Cette étape est optionnelle mais permet principalement de sécuriser les clés API si le serveur est compromis.
```bash
chmod 640 /opt/asset-manager/.env
```

### 3. Création du dossier backups
```bash
cd /opt/asset-manager && mkdir backups
```

---

## 📌 Etape 5 : Création du virtualenv et installation des dépendances Python

### 1. Création du virtualenv

```bash
python3 -m venv /opt/asset-manager/venv
```

### 2. Activation du virtualenv

```bash
source /opt/asset-manager/venv/bin/activate
```

### 3. Mise à jour de pip

```bash
pip install --upgrade pip
```

### 4. Installation des dépendances dans le venv

```bash
pip install -r /opt/asset-manager/requirements.txt
```

### 5. Vérification des dépendances critiques du venv

```bash
pip show fastapi pymysql reportlab uvicorn python-dotenv >/dev/null && echo "OK - Toutes les dependances sont installees" || echo "ERREUR - Dependances manquantes"
```

---

## 📌 Etape 6 : Configuration de la base de données

> ⚠️ Si le fichier `.env` n'est pas correctement rempli, allez le remplir maintenant

### 1. Intégrer les variables du .env dans les prochaines commandes
```bash 
source /opt/asset-manager/.env
```

### 2. Setup de la base de données

Un script va gérer le setup de la base de données avec l'import automatique : 
```bash
sudo /opt/asset-manager/venv/bin/python3 /opt/asset-manager/setup_database.py
```

#### Si le script fonctionne, passer à l'étape 3

#### Si le script échoue, il va falloir manuellement gérer le setup en faisant ceci : 

Se connecter via `sudo mysql`puis taper les commandes suivantes en adaptant les variables (commençant par "$") par celles notées dans votre fichier `.env` :

```sql
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### 3. Test de connexion

```bash
mariadb -u $DB_USER -p"$DB_PASSWORD" -e "SELECT 1;" && echo "OK - Connexion reussie" || echo "ERREUR - Echec de la connexion"
```

---

## 📌 Etape 7 : Configuration du service systemd

### 1. Copie du service dans le système de services du serveur

```bash
sudo cp /opt/asset-manager/asset-manager.service /etc/systemd/system/asset-manager.service
```

### 2. Rechargement de systemd

```bash
sudo systemctl daemon-reload
```

### 3. Activation et démarrage du service

```bash
sudo systemctl enable --now asset-manager
```

### 4. Vérification du service

```bash
sudo systemctl status asset-manager
sudo journalctl -u asset-manager -n 20
```

---

## 📌 Etape 8 : Ajout au PATH

### 1. Identification du shell

```bash
echo $SHELL
```

Sur Ubuntu Server, par défaut, c'est **/bin/bash**.

### 2. Création d'un alias lié au shell

Pour **/bin/bash**, on a deux choix : 
1. Ajouter l'alias au fichier **~/.bash_aliases** ( créer le fichier si celui-ci n'existe pas encore ) --> **Solution la plus propre**
```bash
echo "alias asset-manager='bash /opt/asset-manager/scripts/asset-manager.sh'" >> ~/.bash_aliases
```

2. Ajouter l'alias à la fin du fichier **~/.bashrc** ( moins propre )
```bash
echo "alias asset-manager='bash /opt/asset-manager/scripts/asset-manager.sh'" >> ~/.bashrc
```

---

## 📌 Etape 9 : Vérifications finales


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
