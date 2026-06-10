# AirGappedCVE — Asset & Vulnerability Manager

Système de gestion d'assets informatiques et de vulnérabilités de sécurité, conçu spécifiquement pour un prestataire IT gérant des environnements **air-gappés** — c'est-à-dire des réseaux physiquement isolés d'Internet.

---

## 📚 Documentation

🔗 **Documentation complète disponible ici :** [https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)

---

## 🚀 Installation

### Installation automatique (recommandée)

Le script d'installation guide l'utilisateur étape par étape et configure tout automatiquement :

```bash
# Télécharger et exécuter le script d'installation
curl -sSL https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/refs/heads/main/install.sh | sudo bash
```

**Le script effectue les étapes suivantes :**

1. **Vérifications préliminaires**
   - Espace disque disponible (≥ 5GB sur `/opt`)
   - Mémoire RAM (≥ 2GB recommandé)
   - Détection de l'architecture (compatible Raspberry Pi)
   - Vérification de la connectivité internet
   - Vérification que les ports 8000 et 3306 sont disponibles
   - Vérification de la version Python (≥ 3.12 recommandé)

2. **Mise à jour système et installation des dépendances**
   - Mise à jour des paquets APT
   - Installation de : curl, wget, git, python3, python3-pip, python3-venv, mariadb-server, mariadb-client, net-tools, netcat

3. **Clone du projet**
   - Clonage du dépôt dans `/opt/asset-manager/`
   - Suppression des fichiers inutiles en production

4. **Configuration interactive**
   - **NVD_API_KEY** : Clé API NVD (optionnelle)
   - **MISTRAL_API_KEY** : Clé API Mistral (optionnelle)
   - **DB_USER** : Nom d'utilisateur MariaDB (obligatoire)
   - **DB_PASSWORD** : Mot de passe généré automatiquement (32 caractères)
   - **SERVER_IP** : Détectée automatiquement
   - **DB_HOST** : 127.0.0.1 (par défaut)
   - **DB_PORT** : 3306 (par défaut)
   - **DB_NAME** : asset_vuln_manager (par défaut)
   - **Affichage d'un résumé** avant confirmation

5. **Installation de la base de données et de l'application**
   - Démarrage et sécurisation de MariaDB
   - Création de la base de données et de l'utilisateur
   - Import du schéma SQL
   - Création de l'environnement virtuel Python
   - Installation des dépendances Python
   - Configuration du service systemd
   - Démarrage du service FastAPI

6. **Finalisation**
   - Ajout de `asset-manager` au PATH
   - Exécution des commandes de vérification :
     - `asset-manager status`
     - `asset-manager sys ports`
     - `asset-manager sys check-db`
     - `asset-manager sys check-env`
     - `asset-manager db check`
   - Création du fichier `INSTALL_INFO.txt` avec toutes les informations
   - Affichage du récapitulatif final

---

### Installation manuelle

Si vous préférez installer manuellement :

```bash
# 1. Cloner le dépôt
git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
cd /opt/asset-manager

# 2. Copier et configurer le .env
cp .env.example .env
nano .env  # Remplir les variables nécessaires

# 3. Installer les dépendances système
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git python3 python3-pip python3-venv mariadb-server mariadb-client bc net-tools netcat

# 4. Configurer MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo mariadb -u root < sql/schema.sql

# 5. Configurer l'application
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 6. Configurer le service systemd
sudo cp asset-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable asset-manager
sudo systemctl start asset-manager

# 7. Ajouter au PATH
sudo cp scripts/asset-manager.sh /usr/local/bin/asset-manager
sudo chmod +x /usr/local/bin/asset-manager
```

---

## 📋 Prérequis

| Élément | Exigence | Description |
|---------|----------|-------------|
| **Système** | Ubuntu Server 22.04/24.04 LTS | Testé et recommandé |
| **Architecture** | x86_64, ARM (Raspberry Pi) | Compatible |
| **Espace disque** | ≥ 5GB sur `/opt` | Pour l'application et les données |
| **Mémoire** | ≥ 2GB RAM | Recommandé pour Mistral AI |
| **Python** | ≥ 3.12 | Recommandé (fonctionne avec 3.10+) |
| **Ports** | 8000, 3306 | FastAPI et MariaDB |

---

## 🔑 Clés API nécessaires

Deux clés API sont nécessaires pour le fonctionnement complet :

### 1. Clé API NVD (gratuite)
- **Obtenir** : [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- **Utilité** : Synchronisation des CVE depuis la base NVD
- **Limite sans clé** : 5 requêtes/30s (au lieu de 50)

### 2. Clé API Mistral AI (payante)
- **Obtenir** : [https://console.mistral.ai/api-keys](https://console.mistral.ai/api-keys)
- **Utilité** : Analyse IA des corrélations CVE/asset
- **Modèle recommandé** : `mistral-large-latest`
- **Coût** : Quelques centimes par analyse
- **Crédits gratuits** : Offerts à la création du compte

> ⚠️ **Important** : Ces clés sont demandées pendant l'installation automatique ou à placer dans le fichier `.env`.
> **Ne jamais commiter le fichier `.env`** (il est dans le `.gitignore`).

---

## 📊 Architecture

Le système tourne sur une seule machine avec les composants suivants :

| Composant | Rôle | Port |
|-----------|------|------|
| **MariaDB** | Base de données centrale | 3306 |
| **FastAPI** | API REST (toutes les opérations CRUD) | 8000 |
| **Mistral AI** | Analyse IA des corrélations (API externe) | — |
| **NVD API** | Source des données CVE (API externe) | — |
| **systemd** | Gestion du service FastAPI | — |
| **CLI** | Interface en ligne de commande | — |

---

## 🎯 Fonctionnalités clés

- ✅ **Centralisation** : Tous les assets (serveurs, PCs, switches, caméras, NAS...) de tous les clients dans une base unique
- ✅ **Synchronisation** : Mise à jour automatique des CVE depuis le NVD
- ✅ **Corrélation** : Détection automatique des CVE concernant vos assets
- ✅ **Analyse IA** : Évaluation du risque réel avec Mistral AI (contexte air-gap pris en compte)
- ✅ **Pondération** : Score de risque adapté aux environnements isolés
- ✅ **API REST** : Interface programmatique complète (FastAPI + Swagger)
- ✅ **CLI** : Interface en ligne de commande pour les opérations quotidiennes

---

## 📁 Structure du projet

```
/opt/asset-manager/
├── main.py                    # Point d'entrée FastAPI
├── database.py                # Connexion MariaDB
├── requirements.txt           # Dépendances Python
├── install.sh                # Script d'installation automatique
├── backup.sh                 # Script de sauvegarde
├── .env.example               # Template de configuration
│
├── routers/                   # Endpoints FastAPI
│   ├── clients.py
│   ├── sites.py
│   ├── assets.py
│   └── correlations.py
│
├── scripts/                   # Moteur logique
│   ├── sync_nvd.py            # Synchronisation CVE/CWE
│   └── correlate_and_analyze.py # Corrélation + analyse Mistral
│
├── ui/                        # CLI Typer
│   └── main.py
│
├── sql/
│   └── schema.sql             # Schéma de la base de données
│
├── logs/                      # Logs (non commité)
│   └── FastAPI.log
│
├── data/                      # Données temporaires (non commité)
├── documents/                 # Documents générés (non commité)
└── venv/                      # Virtualenv Python (non commité)
```

---

## 🔧 Gestion quotidienne

### Vérifier le service

```bash
# État du service FastAPI
systemctl status asset-manager

# Logs en temps réel
journalctl -u asset-manager -f

# Logs FastAPI
tail -f /opt/asset-manager/logs/FastAPI.log
```

### Redémarrer le service

```bash
sudo systemctl restart asset-manager
```

### Accéder à la base de données

```bash
# En tant que root (unix socket, sans mot de passe)
sudo mariadb

# En tant qu'utilisateur applicatif
mariadb -u <DB_USER> -p asset_vuln_manager
```

### Documentation API interactive

Ouvrir dans un navigateur :
```
http://<IP_SERVEUR>:8000/docs
```

### Sauvegarde

```bash
sudo bash /opt/asset-manager/backup.sh
```

Crée un dossier `backups_YYYYMMDD_HHMMSS/` avec le projet, le dump SQL, le service systemd et le `.env`.

---

## 📖 Documentation complète

Pour plus de détails, consultez la documentation complète :

🔗 **[https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)**

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Ouvrez une issue ou une pull request sur GitHub.

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
