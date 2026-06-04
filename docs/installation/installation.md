---
title: Installation
parent: Installation & Déploiement
nav_order: 2
---

# Installation

**Clone du projet et dépendances Python**

---

## 1️⃣ **Cloner le projet**

```bash
git clone https://github.com/Gvte-Kali/AirGappedCVE.git /opt/asset-manager
cd /opt/asset-manager
```

---

## 2️⃣ **Environnement Python**

```bash
# Créer et activer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt
```

**Paquets clés** : FastAPI, Uvicorn, PyMySQL, mistralai, reportlab, typer, PyYAML

---

## 3️⃣ **Initialiser la base**

```bash
# Importer le schéma
mariadb -u app_user -p asset_vuln_manager < sql/schema.sql

# Vérifier
mariadb -u app_user -p asset_vuln_manager -e "SHOW TABLES;"
```

---

## 4️⃣ **Configurer l'application**

```bash
cp .env.example .env
nano .env
```

Voir [Configuration]({{ site.baseurl }}/installation/configuration) pour les variables.

---

## 5️⃣ **Tester le démarrage**

```bash
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 3000 --reload
```

- **Interface** : `http://IP_DU_SERVEUR:3000`
- **API Swagger** : `http://IP_DU_SERVEUR:3000/docs`

⚠️ `--reload` = développement uniquement. En production, utiliser systemd.

---

## 📁 **Structure du projet**

```
/opt/asset-manager/
├── main.py              # FastAPI
├── database.py          # Connexion MariaDB
├── .env                 # Configuration
├── venv/                # Python virtuel
├── routers/             # Routes API
├── scripts/             # Corrélation, analyse
├── ui/                  # Interface web
├── logs/                # Logs
└── documents/           # PDF générés
```
