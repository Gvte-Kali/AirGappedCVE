---
title: Installation
parent: Installation & Déploiement
nav_order: 2
---

# Installation
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Cloner le projet

```bash
# Cloner le dépôt
git clone https://github.com/votre-utilisateur/votre-repo.git /opt/asset-manager

# Se positionner dans le répertoire
cd /opt/asset-manager
```

---

## 2. Créer l'environnement virtuel Python

```bash
# Créer le venv
python3 -m venv venv

# Activer le venv
source venv/bin/activate
```

---

## 3. Installer les dépendances Python

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Les dépendances principales incluent :

| Paquet | Usage |
|--------|-------|
| `fastapi` | Framework API REST |
| `uvicorn` | Serveur ASGI |
| `pymysql` | Connecteur MariaDB |
| `python-dotenv` | Chargement du `.env` |
| `mistralai` | Client API Mistral |
| `typer` | CLI pour les scripts |
| `pyyaml` | Lecture de `config.yml` |
| `reportlab` | Génération de PDF |

---

## 4. Initialiser la base de données

```bash
# Depuis le répertoire du projet, avec le venv activé
mariadb -u votre_utilisateur -p asset_vuln_manager < schema.sql
```

Vérifier que les tables ont bien été créées :

```sql
mariadb -u votre_utilisateur -p asset_vuln_manager
SHOW TABLES;
```

Vous devriez voir une vingtaine de tables dont `assets`, `clients`, `cve`, `correlations`, etc.

---

## 5. Configurer l'application

Copier le fichier d'exemple et le compléter :

```bash
cp .env.example .env
nano .env
```

Voir la page [Configuration]({{ site.baseurl }}/installation/configuration) pour le détail de chaque variable.

---

## 6. Tester le démarrage

```bash
# Depuis le répertoire du projet, venv activé
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 3000 --reload
```

Ouvrir un navigateur sur `http://IP_DU_SERVEUR:3000` — la page d'accueil doit s'afficher.

L'API Swagger est accessible sur `http://IP_DU_SERVEUR:3000/docs`.

{: .note }
Le flag `--reload` est utile en développement (redémarrage automatique à chaque modification). En production, utiliser le service systemd sans ce flag.

---

## 7. Scripts de gestion

Le projet inclut des scripts shell pour gérer le service FastAPI manuellement :

```bash
# Démarrer FastAPI
bash .devcontainer/start.sh

# Arrêter FastAPI
bash .devcontainer/stop.sh

# Redémarrer FastAPI
bash .devcontainer/reload.sh

# Consulter les logs
tail -f logs/FastAPI.log
```

En production sur votre machine, le service est géré par systemd (voir [Déploiement systemd]({{ site.baseurl }}/installation/deploiement)).

---

## Structure du répertoire après installation

```
/opt/asset-manager/
├── main.py                  # Point d'entrée FastAPI
├── database.py              # Connexion MariaDB
├── schema.sql               # Schéma de la base de données
├── requirements.txt         # Dépendances Python
├── .env                     # Variables d'environnement (non versionné)
├── venv/                    # Environnement virtuel Python
├── routers/                 # Routes FastAPI
│   ├── assets.py
│   ├── clients.py
│   ├── correlations.py
│   └── ...
├── scripts/                 # Scripts Python (corrélation, analyse)
│   ├── correlate_and_analyze.py
│   ├── config.yml
│   └── vuln_types.yml
├── ui/                      # Interface web (HTML/JS)
│   ├── index.html
│   ├── assets.html
│   ├── vulns.html
│   └── static/
├── logs/                    # Logs FastAPI
└── documents/               # Documents générés (PDF)
```
