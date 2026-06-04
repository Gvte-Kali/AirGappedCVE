---
title: Prérequis
parent: Installation & Déploiement
nav_order: 1
---

# Prérequis

**Préparation du serveur avant installation**

---

## 🖥️ **Système**

Testé sur **Ubuntu Server 22.04+** (Raspberry Pi 5 recommandé).

```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y
```

---

## 📦 **Paquets requis**

```bash
sudo apt install -y python3 python3-pip python3-venv git curl mariadb-server
```

**Versions recommandées** : Python 3.12+, MariaDB 11.x

---

## 🗃️ **MariaDB**

### 1. Démarrage et sécurisation

```bash
# Démarrer et activer MariaDB
sudo systemctl enable mariadb
sudo systemctl start mariadb

# Sécuriser (mot de passe root, supprimer accès anonymes)
sudo mysql_secure_installation
```

### 2. Création base et utilisateur

```sql
-- Se connecter
sudo mariadb

-- Créer la base
CREATE DATABASE asset_vuln_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Créer utilisateur (remplacer les valeurs)
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'votre_mot_de_passe';
GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

⚠️ **Ne pas utiliser root** - Créez un utilisateur dédié.

### 3. Initialisation du schéma

```bash
# Depuis le dossier du projet
mariadb -u app_user -p asset_vuln_manager < sql/schema.sql
```

---

## 🌐 **Réseau**

- **Port API** : 3000 (par défaut)
- **IP statique** : Recommandée pour le serveur

```bash
# Exemple Netplan (Ubuntu)
sudo nano /etc/netplan/00-installer-config.yaml
# Configurer votre IP statique, puis :
sudo netplan apply
```

---

## 🔑 **Clé API Mistral**

1. Créer un compte sur [console.mistral.ai](https://console.mistral.ai)
2. Générer une clé API
3. La renseigner dans `.env` (voir [Configuration]({{ site.baseurl }}/installation/configuration))

ℹ️ **Note** : Le serveur doit avoir accès à Internet pour Mistral AI, même si les clients sont air-gappés.
