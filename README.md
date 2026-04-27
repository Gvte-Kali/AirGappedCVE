# AirGappedCVE — Asset & Vulnerability Manager

Système de gestion d'assets informatiques et de vulnérabilités de sécurité, conçu pour un prestataire IT gérant des environnements **air-gappés** (physiquement isolés d'Internet).

## Contexte

- Aucun agent déployé chez les clients
- Toutes les données sont saisies manuellement ou importées lors des interventions
- La criticité des vulnérabilités est pondérée selon le contexte air-gap (une CVE exploitable uniquement via Internet est moins critique en réseau isolé)

## Stack technique

| Composant | Rôle |
|---|---|
| **FastAPI** | API REST — toutes les opérations CRUD |
| **MariaDB** | Base de données centrale |
| **Mistral AI** | Corrélation CVE/asset et analyse de risque |
| **Grafana** | Dashboards de visualisation *(à venir)* |
| **Typer CLI** | Interface en ligne de commande |
| **systemd** | Gestion du service FastAPI |

## Installation

> Prérequis : Ubuntu Server 24.04 LTS, accès Internet pour le téléchargement initial

```bash
curl -sSL "https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/refs/heads/main/install.sh?token=GHSAT0AAAAAAD26DA3377CKQZIBBJDLVIYE2PPHAUQ" | sudo bash
```

Le script installe et configure automatiquement :
- Les dépendances système
- MariaDB (base, utilisateur, schéma)
- Le virtualenv Python et les dépendances
- Le service systemd
- Le fichier `.env` (renseigné interactivement)
- L'IP statique (optionnel)

### Informations demandées lors de l'installation

| Paramètre | Défaut |
|---|---|
| Adresse IP du serveur | `10.100.0.20` |
| Clé API NVD | *(obligatoire)* |
| Clé API Mistral | *(obligatoire)* |
| Modèle Mistral | `mistral-large-latest` |
| Nom d'utilisateur MariaDB | `avea` |
| Mot de passe MariaDB | *(obligatoire)* |
| Nom de la base de données | `asset_vuln_manager` |

## Structure du projet

```
/opt/asset-manager/
├── main.py                  # Point d'entrée FastAPI
├── database.py              # Connexion MariaDB
├── requirements.txt         # Dépendances Python
├── .env                     # Variables d'environnement (non commité)
├── .env.example             # Template .env
├── routers/                 # Routes FastAPI
├── scripts/                 # Scripts d'analyse et corrélation
├── sql/
│   └── schema.sql           # Schéma de la base de données
├── config/
│   ├── secrets.json         # Credentials (non commité)
│   └── secrets.json.example # Template secrets
├── ui/                      # Interface CLI (Typer)
├── logs/                    # Logs applicatifs
└── data/                    # Données temporaires
```

## Gestion du service

```bash
# Statut
systemctl status asset-manager

# Logs en temps réel
journalctl -u asset-manager -f

# Redémarrer
sudo systemctl restart asset-manager
```

## Base de données

```bash
# Connexion root
sudo mariadb

# Connexion avec l'utilisateur applicatif
mariadb -u avea -p asset_vuln_manager
```

## Variables d'environnement

Copier `.env.example` en `.env` et remplir les valeurs :

```bash
cp .env.example .env
nano .env
```

| Variable | Description |
|---|---|
| `SERVER_IP` | IP du serveur |
| `NVD_API_KEY` | Clé API National Vulnerability Database |
| `MISTRAL_API_KEY` | Clé API Mistral AI |
| `MISTRAL_MODEL` | Modèle Mistral utilisé |
| `DB_HOST` | Hôte MariaDB |
| `DB_PORT` | Port MariaDB |
| `DB_USER` | Utilisateur MariaDB |
| `DB_PASSWORD` | Mot de passe MariaDB |
| `DB_NAME` | Nom de la base de données |

## Sécurité

- Le fichier `.env` et `config/secrets.json` ne sont **jamais commités** (`.gitignore`)
- Les environnements clients étant air-gappés, l'analyse de risque tient compte de l'exploitabilité réseau réelle
- L'accès root MariaDB se fait uniquement via `sudo mariadb` (unix socket, sans mot de passe)
