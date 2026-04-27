# AirGappedCVE — Asset & Vulnerability Manager

Système de gestion d'assets informatiques et de vulnérabilités de sécurité, conçu spécifiquement pour un prestataire IT gérant des environnements **air-gappés** — c'est-à-dire des réseaux physiquement isolés d'Internet.

---

## Sommaire

1. [Contexte et philosophie](#1-contexte-et-philosophie)
2. [Architecture générale](#2-architecture-générale)
3. [Schéma de la stack](#3-schéma-de-la-stack)
4. [Composants détaillés](#4-composants-détaillés)
5. [Base de données — schéma et relations](#5-base-de-données--schéma-et-relations)
6. [Flux de données — de la CVE à la décision](#6-flux-de-données--de-la-cve-à-la-décision)
7. [Moteur de corrélation et analyse Mistral](#7-moteur-de-corrélation-et-analyse-mistral)
8. [Structure du projet](#8-structure-du-projet)
9. [Installation](#9-installation)
10. [Configuration](#10-configuration)
11. [Gestion quotidienne](#11-gestion-quotidienne)
12. [Sécurité](#12-sécurité)

---

## 1. Contexte et philosophie

### Le problème

Un prestataire IT gère les équipements informatiques de plusieurs clients. Ces clients opèrent dans des **environnements air-gappés** : leurs réseaux sont physiquement coupés d'Internet. Chaque jour, de nouvelles vulnérabilités (CVE) sont publiées par le NVD (National Vulnerability Database). La question est : **lesquelles concernent réellement les assets des clients ?**

Sans outil dédié, répondre à cette question est manuel, chronophage, et sujet aux oublis.

### Ce que fait ce système

- **Centralise** tous les assets (serveurs, PCs, switches, caméras, NAS...) de tous les clients dans une base unique
- **Synchronise** automatiquement les CVE depuis le NVD via son API
- **Corrèle** chaque CVE avec les assets potentiellement concernés, en comparant fabricant, produit et version
- **Analyse** chaque corrélation avec Mistral AI pour affiner la pertinence et évaluer le risque réel
- **Pondère** la criticité selon le contexte air-gap : une CVE exploitable uniquement via Internet est beaucoup moins critique qu'une CVE exploitable en réseau local ou physiquement
- **Expose** toutes ces données via une API REST et des dashboards Grafana

### Ce que ce système ne fait PAS

- Pas d'agent déployé chez les clients — tout est saisi manuellement
- Pas de scan réseau — les données sont collectées lors des interventions sur site
- Pas d'interface web custom — Grafana sert de tableau de bord, l'API FastAPI est l'interface programmatique

---

## 2. Architecture générale

Le système tourne intégralement sur **une seule machine** (VM Ubuntu Server sur Proxmox, ou Raspberry Pi 5) avec les composants suivants :

| Composant | Rôle | Port |
|---|---|---|
| **MariaDB** | Base de données centrale — cœur du système | 3306 |
| **FastAPI** | API REST — toutes les opérations CRUD et déclenchement des scripts | 8000 |
| **Mistral AI** | Analyse IA des corrélations CVE/asset (API externe) | — |
| **NVD API** | Source des données CVE (API externe) | — |
| **Grafana** | Dashboards de visualisation *(à venir)* | 3000 |
| **systemd** | Gestion du cycle de vie du service FastAPI | — |
| **CLI Typer** | Interface en ligne de commande pour les opérations courantes | — |

---

## 3. Schéma de la stack

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SOURCES EXTERNES                             │
│                                                                     │
│   ┌─────────────────┐              ┌──────────────────┐            │
│   │   NVD API        │              │   Mistral AI API  │            │
│   │ (nvd.nist.gov)   │              │ (api.mistral.ai)  │            │
│   └────────┬────────┘              └────────┬─────────┘            │
└────────────│───────────────────────────────│─────────────────────── ┘
             │ sync CVE/CWE                  │ analyse corrélations
             ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     SERVEUR UBUNTU (VM / RPi5)                      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    SCRIPTS PYTHON                             │  │
│  │                                                              │  │
│  │  sync_nvd.py          correlate_and_analyze.py              │  │
│  │  (sync CVE/CWE)       (corrélation + analyse Mistral)       │  │
│  └──────────────────────────────┬───────────────────────────────┘  │
│                                 │ lecture/écriture                  │
│                                 ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      MARIADB                                 │   │
│  │              (base : asset_vuln_manager)                     │   │
│  │                                                              │   │
│  │  clients  sites  assets  cve  cwe  correlations             │   │
│  │  product_vendors  product_models  utilisateurs              │   │
│  │  historique_analyses  asset_software                        │   │
│  └──────────┬──────────────────────────────────────────────────┘   │
│             │ lecture/écriture           │ lecture directe          │
│             ▼                            ▼                          │
│  ┌──────────────────┐        ┌─────────────────────┐              │
│  │    FASTAPI        │        │      GRAFANA          │              │
│  │  (port 8000)      │        │    (port 3000)        │              │
│  │                  │        │  (dashboards/vues)    │              │
│  └────────┬─────────┘        └─────────────────────┘              │
│           │                                                         │
└───────────│─────────────────────────────────────────────────────── ┘
            │ HTTP REST
            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENTS DE L'API                            │
│                                                                     │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐      │
│   │  CLI Typer   │     │ curl / HTTP  │     │   Grafana    │      │
│   │  (dev/ops)   │     │  (scripts)   │     │  (API calls) │      │
│   └──────────────┘     └──────────────┘     └──────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Composants détaillés

### FastAPI — L'API REST

FastAPI est le point d'entrée programmatique du système. Il expose des endpoints REST pour toutes les opérations :

- **CRUD** sur les clients, sites, assets, vendors, modèles
- **Déclenchement** des scripts de synchronisation et corrélation
- **Consultation** des CVE, corrélations, et historiques d'analyse
- **Override manuel** des décisions de corrélation par l'opérateur

Le service est géré par **systemd** et démarre automatiquement au boot. Les logs sont écrits dans `/opt/asset-manager/logs/FastAPI.log`.

```
GET/POST/PUT/DELETE /clients
GET/POST/PUT/DELETE /sites
GET/POST/PUT/DELETE /assets
GET/POST/PUT/DELETE /correlations
PATCH               /correlations/{id}/override
GET                 /cve
GET                 /docs   ← documentation interactive Swagger
```

### MariaDB — La base de données

C'est le cœur du système. Toutes les données y sont stockées et toutes les interactions passent par elle (directement via les scripts Python, ou via l'API FastAPI). Grafana s'y connecte aussi directement en lecture pour alimenter les dashboards.

L'accès root se fait via `sudo mariadb` (authentification unix socket, sans mot de passe). Un utilisateur applicatif dédié (par défaut `avea`) est créé avec des droits limités à la base `asset_vuln_manager`.

### Scripts Python — Le moteur logique

Deux scripts principaux constituent le moteur du système :

**`sync_nvd.py`** — Synchronisation CVE/CWE
- Interroge l'API NVD pour récupérer les nouvelles CVE et les mettre à jour
- Récupère aussi les CWE (Common Weakness Enumeration) associés
- Stocke tout dans les tables `cve`, `cwe`, et `cve_cwe`
- Enregistre chaque exécution dans `historique_analyses`

**`correlate_and_analyze.py`** — Corrélation et analyse Mistral
- Pour chaque asset actif, compare ses informations (vendor, produit, version) avec les CVE connues
- Calcule un `type_correlation` : `affirme` si la version est explicitement dans le range vulnérable, `informatif` si c'est potentiel mais non confirmé
- Envoie chaque corrélation à Mistral AI pour analyse approfondie
- Mistral évalue : l'asset est-il vraiment concerné ? La CVE est-elle exploitable en contexte air-gap ?
- Met à jour le `statut`, `priorite`, `score_contextuel`, `exploitable_air_gap`, et `risque_reel`

### CLI Typer — L'interface opérateur

Interface en ligne de commande construite avec la bibliothèque Python Typer. Elle permet d'interagir avec le système sans passer par un client HTTP, idéal pour les opérations quotidiennes et le développement.

### Grafana — Les dashboards *(à venir)*

Grafana se connecte directement à MariaDB via le plugin MySQL/MariaDB. Il consomme des **vues SQL** précalculées (notamment `v_vulnerabilites_tableau`) pour afficher les tableaux de bord. Cette approche évite d'exposer la complexité des jointures à Grafana.

---

## 5. Base de données — schéma et relations

```
clients (1) ──────────< sites (1) ──────────< assets
                                                  │
                                          ┌───────┴────────┐
                                          │                │
                                    asset_software    correlations
                                                           │
                                                    ┌──────┴──────┐
                                                    │             │
                                                   cve ──────< cve_cwe >──── cwe
                                                    │
                                             product_vendors
                                             product_models
```

**Tables principales :**

| Table | Description |
|---|---|
| `clients` | Les entreprises clientes du prestataire |
| `sites` | Les sites physiques de chaque client |
| `assets` | Les équipements inventoriés (serveurs, switches, caméras...) |
| `asset_software` | Les logiciels installés sur chaque asset |
| `product_vendors` | Les fabricants référencés (Microsoft, Synology, Axis...) |
| `product_models` | Les produits référencés avec leur identifiant NVD |
| `cve` | Les vulnérabilités récupérées depuis le NVD |
| `cwe` | Les faiblesses associées aux CVE |
| `cve_cwe` | Table de liaison CVE ↔ CWE |
| `correlations` | Les associations CVE/asset détectées et analysées |
| `historique_analyses` | Journal des exécutions des scripts |
| `utilisateurs` | Les opérateurs du système |

**La table `correlations` en détail :**

C'est la table centrale du système. Elle stocke chaque association détectée entre un asset et une CVE, et porte toute la logique de qualification :

| Colonne | Description |
|---|---|
| `type_correlation` | `affirme` = version explicitement vulnérable / `informatif` = potentiellement vulnérable |
| `override_utilisateur` | Décision manuelle de l'opérateur (`a_patcher`, `informatif`, `faux_positif`) |
| `statut` | Cycle de vie : `nouveau` → `en_analyse` → `confirme` / `faux_positif` / `mitige` / `patche` |
| `priorite` | `critique`, `haute`, `moyenne`, `basse` — calculée par Mistral |
| `exploitable_air_gap` | `true/false` — la CVE est-elle exploitable dans un réseau isolé ? |
| `score_contextuel` | Score de risque pondéré selon le contexte (0.0 à 10.0) |
| `analyse_mistral` | Justification textuelle de Mistral |
| `risque_reel` | Évaluation du risque réel pour cet asset spécifique |

**La vue `v_vulnerabilites_tableau` :**

Vue SQL utilisée par Grafana pour afficher le tableau principal. Elle joint toutes les tables et expose la colonne `decision_patch` qui applique la logique suivante :

```sql
COALESCE(override_utilisateur, type_correlation) AS decision_patch
```

Si l'opérateur a saisi un override → on affiche l'override. Sinon → on affiche la décision automatique.

---

## 6. Flux de données — de la CVE à la décision

```
1. SYNCHRONISATION (sync_nvd.py)
   ─────────────────────────────
   NVD API ──► table cve (CVE-2024-XXXX, score CVSS, versions affectées, CPE...)
             ──► table cwe (faiblesses associées)

2. CORRÉLATION (correlate_and_analyze.py — phase 1)
   ─────────────────────────────────────────────────
   Pour chaque asset actif :
     └── Cherche les CVE correspondant au même vendor/produit
           └── Compare la version de l'asset avec les versions vulnérables
                 ├── Version dans le range → type_correlation = 'affirme'
                 └── Version inconnue ou hors range → type_correlation = 'informatif'
                       └── INSERT dans correlations (statut = 'nouveau')

3. ANALYSE MISTRAL (correlate_and_analyze.py — phase 2)
   ─────────────────────────────────────────────────────
   Pour chaque corrélation 'nouveau' :
     └── Envoie à Mistral : infos CVE + infos asset + contexte air-gap
           └── Mistral répond (JSON) :
                 ├── asset_concerne : true/false
                 ├── confirmation_version : true/false
                 ├── exploitable_air_gap : true/false
                 ├── priorite : critique/haute/moyenne/basse
                 ├── score_contextuel : 0.0-10.0
                 └── justification : texte
           └── UPDATE correlations :
                 ├── statut = 'confirme' ou 'faux_positif'
                 ├── type_correlation affiné selon confirmation_version
                 └── tous les champs d'analyse renseignés

4. DÉCISION OPÉRATEUR (via API / CLI)
   ────────────────────────────────────
   L'opérateur consulte les corrélations confirmées et peut :
     ├── Valider → override_utilisateur = 'a_patcher'
     ├── Minimiser → override_utilisateur = 'informatif'
     └── Rejeter → override_utilisateur = 'faux_positif'

5. VISUALISATION (Grafana / API)
   ──────────────────────────────
   v_vulnerabilites_tableau :
     └── decision_patch = COALESCE(override_utilisateur, type_correlation)
```

---

## 7. Moteur de corrélation et analyse Mistral

### Pourquoi deux phases ?

La corrélation seule (phase 1) est rapide et automatique mais produit des faux positifs : un asset sous Windows 11 sera corrélé avec toutes les CVE Windows 11, même celles qui ne concernent que des fonctionnalités non présentes. Mistral (phase 2) affine cette liste en comprenant le contexte.

### Le rôle du contexte air-gap

Mistral reçoit explicitement l'information que les environnements clients sont air-gappés. Il peut ainsi décider qu'une CVE nécessitant un accès Internet pour être exploitée (`exploitable_air_gap = false`) est moins prioritaire, même si elle a un score CVSS élevé. Le `score_contextuel` reflète cette pondération.

### La distinction `affirme` / `informatif`

| Valeur | Signification | Exemple |
|---|---|---|
| `affirme` | La version de l'asset est **explicitement** dans le range vulnérable de la CVE | Asset sous Windows 11 22H2, CVE affecte Windows 11 versions ≤ 22H2 |
| `informatif` | La CVE concerne potentiellement l'asset, mais sans confirmation de version | Version de l'asset inconnue, ou CVE sans plage de versions précise |

### Override opérateur

L'opérateur a toujours le dernier mot via `override_utilisateur`. Ce champ écrase la décision automatique dans tous les affichages. Cela permet de gérer les cas où Mistral se trompe ou où le contexte client impose une décision différente.

---

## 8. Structure du projet

```
/opt/asset-manager/
│
├── main.py                        # Point d'entrée FastAPI
├── database.py                    # Connexion et sessions MariaDB
├── requirements.txt               # Dépendances Python
│
├── routers/                       # Endpoints FastAPI (un fichier par ressource)
│   ├── clients.py
│   ├── sites.py
│   ├── assets.py
│   ├── correlations.py
│   └── ...
│
├── scripts/                       # Moteur logique
│   ├── sync_nvd.py                # Synchronisation CVE/CWE depuis NVD
│   └── correlate_and_analyze.py   # Corrélation assets/CVE + analyse Mistral
│
├── ui/                            # CLI Typer
│   └── main.py
│
├── sql/
│   └── schema.sql                 # Schéma complet de la base de données
│
│
├── logs/
│   └── FastAPI.log                # Logs du service (non commité)
│
├── data/                          # Données temporaires (non commité)
├── documents/                     # Documents générés (non commité)
│
├── .env                           # Variables d'environnement (non commité)
├── .env.example                   # Template .env
├── install.sh                     # Script d'installation automatique
├── backup.sh                      # Script de sauvegarde
└── venv/                          # Virtualenv Python (non commité)
```

---

## 9. Installation

> **Prérequis :** Ubuntu Server 22.04 ou 24.04 LTS, accès Internet pour le téléchargement initial.

### Installation automatique (recommandée)

```bash
curl -sSL https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/main/install.sh | sudo bash
```

Le script installe et configure tout de manière interactive :

1. Mise à jour système et installation des dépendances
2. Clonage du repo dans `/opt/asset-manager`
3. Configuration guidée du `.env` (IP, clés API, credentials BDD)
4. Création du virtualenv Python et installation des dépendances
5. Configuration MariaDB (base, utilisateur, schéma, vue)
6. Création et activation du service systemd
7. Configuration IP statique (optionnelle)

### Informations demandées lors de l'installation

| Paramètre | Défaut | Description |
|---|---|---|
| IP du serveur | `10.100.0.20` | IP de la machine hôte |
| Clé API NVD | — | Obtenir sur [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| Clé API Mistral | — | Obtenir sur [console.mistral.ai](https://console.mistral.ai/api-keys) |
| Modèle Mistral | `mistral-large-latest` | Modèle utilisé pour l'analyse |
| Utilisateur MariaDB | `avea` | Nom du compte applicatif |
| Mot de passe MariaDB | — | Confirmé deux fois |
| Nom de la base | `asset_vuln_manager` | Nom de la base de données |

---

## 10. Configuration

### Fichier `.env`

```ini
# SERVER INFOS
SERVER_IP=10.100.0.20

# API Keys
NVD_API_KEY=your_nvd_api_key_here
MISTRAL_API_KEY=your_mistral_api_key_here
MISTRAL_MODEL=mistral-large-latest

# Database
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=avea
DB_PASSWORD=your_password_here
DB_NAME=asset_vuln_manager
```



---

## 11. Gestion quotidienne

### Vérifier le service FastAPI

```bash
systemctl status asset-manager
journalctl -u asset-manager -f        # logs en temps réel
tail -f /opt/asset-manager/logs/FastAPI.log
```

### Redémarrer le service

```bash
sudo systemctl restart asset-manager
```

### Accéder à la base de données

```bash
sudo mariadb                           # root (unix socket, sans mot de passe)
mariadb -u avea -p asset_vuln_manager  # utilisateur applicatif
```

### Documentation API interactive

```
http://<IP_SERVEUR>:8000/docs
```

### Sauvegarde

```bash
sudo bash /opt/asset-manager/backup.sh
```

Crée un dossier `backups_YYYYMMDD_HHMMSS/` dans le home de l'utilisateur avec le projet, le dump SQL, le service systemd, et le `.env`.

---

## 12. Sécurité

- **`.env`** n'est jamais commité (`.gitignore`) — c'est la seule source de vérité pour les credentials
- **Root MariaDB** accessible uniquement via `sudo mariadb` (unix socket)
- **Contexte air-gap** pris en compte dans toutes les analyses de risque
- **Override opérateur** permet de corriger toute décision automatique erronée
- **Clés API** à régénérer régulièrement (NVD, Mistral)
