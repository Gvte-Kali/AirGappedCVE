# AirGappedCVE — Asset & Vulnerability Manager

Système de gestion d'assets informatiques et de vulnérabilités de sécurité, conçu spécifiquement pour un prestataire IT gérant des environnements **air-gappés** — c'est-à-dire des réseaux physiquement isolés d'Internet.

---

## 📚 Documentation

🔗 [https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)

---

## 🚀 Installation

https://gvte-kali.github.io/AirGappedCVE/installation-configuration/

---

## 🔑 Clés API nécessaires

Deux clés API sont nécessaires pour le fonctionnement complet :

### 1. Clé API NVD (gratuite)
- **Obtenir** : [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- **Utilité** : Synchronisation des CVE depuis la base NVD
- **Limite sans clé** : 5 requêtes/30s (au lieu de 50)

### 2. Clé API Mistral AI (gratuite)
- **Obtenir** : [https://console.mistral.ai/api-keys](https://console.mistral.ai/api-keys)
- **Utilité** : Analyse IA des corrélations CVE/asset

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
- ✅ **Analyse IA** : Évaluation du risque réel avec Mistral AI sur un prompt personnalisable
- ✅ **Pondération** : Score de risque adapté aux environnements isolés
- ✅ **API CRUD** : Interface web qui interagit avec une API personnalisée
- ✅ **CLI** : Interface en ligne de commande pour les opérations quotidiennes et la maintenance

---

## 📁 Structure du projet

```
📁/opt/asset-manager/
├──📁 backups/        # Backups de la base de donnée
│
├──📁 data/           # Toutes les données NVD
│
├──📁 docs/           # La documentation de l'application (https://gvte-kali.github.io/AirGappedCVE/)
│
├──📁 documents/      # Les documents générés par l'application et accessibles via la page /documents
│
├──📁 grafana/        # Fonctionnalité à venir
│
├──📁 logs/           # Les différents fichiers de log
│
├──📁 routers/        # Les endpoints de FastAPI
│
├──📁 scripts/        # Les scripts lancés par l'app web et par le cron job
│
├──📁 sql/            # Le dossier contenant le schema.sql, et autres au besoin
│
├──📁 ui/             # Le dossier contenant toutes les pages web
│
├──📁 venv/           # Le virtual environment de Python créé lors du setup
│
├──📄 asset-manager.service     # Fichier de service créé pour lancer l'app au lancement de l'OS
├──📄 database.py               # Script de connexion à MariaDB, utilisé par l'API et les pages web
├──📄 main.py                   # Point d'entrée FastAPI
├──📄 README.md                 # Ce fichier
├──📄 requirements.txt          # Dépendances Python
├──📄 setup_database.py         # Script de mise en place de la base de données
├──📄 suivi.txt                 # Avancement du développement, fonctionnalités en cours de développement, bugs connus,...
├──📄 uninstall.sh              # Script de désinstallation de tout le système
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Ouvrez une issue ou une pull request sur GitHub.

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
