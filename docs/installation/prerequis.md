---
title: Prérequis
parent: Installation & Déploiement
nav_order: 1
---

# Prérequis
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Système d'exploitation

Le système a été testé sur **Ubuntu Server** (Raspberry Pi 5). Il est compatible avec toute distribution Debian/Ubuntu récente.

```bash
# Mettre à jour le système avant toute installation
sudo apt update && sudo apt upgrade -y
```

---

## Paquets système

```bash
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    mariadb-server \
    mariadb-client
```

Versions testées :

| Paquet | Version testée |
|--------|----------------|
| Python | 3.12.x |
| MariaDB | 11.8.x |
| FastAPI | 0.135.x |
| Uvicorn | 0.41.x |

{: .note }
Le projet utilise des fonctionnalités Python standard — toute version ≥ 3.10 devrait fonctionner.

---

## MariaDB

### Démarrage et sécurisation

```bash
# Démarrer MariaDB
sudo systemctl enable mariadb
sudo systemctl start mariadb

# Sécuriser l'installation (définir le mot de passe root, supprimer les accès anonymes)
sudo mysql_secure_installation
```

### Création de la base de données et de l'utilisateur

```sql
-- Se connecter en root
sudo mariadb

-- Créer la base de données
CREATE DATABASE asset_vuln_manager
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- Créer l'utilisateur applicatif
-- Remplacer 'votre_utilisateur' et 'votre_mot_de_passe' par vos valeurs
CREATE USER 'votre_utilisateur'@'localhost' IDENTIFIED BY 'votre_mot_de_passe';

-- Accorder les droits
GRANT ALL PRIVILEGES ON asset_vuln_manager.* TO 'votre_utilisateur'@'localhost';
FLUSH PRIVILEGES;

EXIT;
```

{: .warning }
Ne pas utiliser l'utilisateur `root` MariaDB pour l'application. Créez toujours un utilisateur dédié avec les droits limités à la base `asset_vuln_manager`.

### Initialisation du schéma

```bash
# Importer le schéma initial
mariadb -u votre_utilisateur -p asset_vuln_manager < schema.sql
```

Le fichier `schema.sql` se trouve à la racine du projet.

---

## Réseau

Le service FastAPI écoute sur le **port 3000** par défaut.

Assurez-vous que ce port est accessible depuis les machines qui utiliseront l'interface web. Sur un réseau local isolé (air-gap), aucune règle de pare-feu externe n'est nécessaire.

Pour définir une IP statique sur Ubuntu Server, éditez la configuration Netplan :

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 192.168.X.X/24   # votre IP statique
      routes:
        - to: default
          via: 192.168.X.1  # votre gateway
      nameservers:
        addresses: [8.8.8.8]
```

```bash
sudo netplan apply
```

---

## Clé API Mistral

Le moteur d'analyse nécessite une clé API Mistral AI.

1. Créer un compte sur [console.mistral.ai](https://console.mistral.ai)
2. Générer une clé API
3. La renseigner dans le fichier `.env` (voir [Configuration]({{ site.baseurl }}/installation/configuration))

{: .note }
En environnement air-gap, le **serveur** doit avoir accès à Internet pour appeler l'API Mistral, même si les **clients** sont isolés. Si le serveur est lui-même air-gappé, l'analyse Mistral ne sera pas disponible — la corrélation CVE fonctionnera quand même en mode pré-triage uniquement.
