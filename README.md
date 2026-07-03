# AirGappedCVE — Asset & Vulnerability Manager

Système de gestion d'assets informatiques et de vulnérabilités de sécurité, conçu spécifiquement pour un prestataire IT gérant des environnements **air-gappés** — c'est-à-dire des réseaux physiquement isolés d'Internet.

---

## 📚 Documentation

🔗 **Documentation complète disponible ici :** [https://gvte-kali.github.io/AirGappedCVE/](https://gvte-kali.github.io/AirGappedCVE/)

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

### 2. Clé API Mistral AI (payante)
- **Obtenir** : [https://console.mistral.ai/api-keys](https://console.mistral.ai/api-keys)
- **Utilité** : Analyse IA des corrélations CVE/asset
- **Modèle recommandé** : `mistral-large-latest`
- **Coût** : Gratuit avec clé API gratuite
- **Crédits gratuits** : Offerts à la création du compte

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
asset-manager status

# Logs FastAPI
asset-manager logs show
```

### Redémarrer le service

```bash
asset-manager fastapi restart
```

### Accéder à la base de données

```bash
# En tant que root (unix socket, sans mot de passe)
asset-manager db connect

```

### Documentation API interactive

Ouvrir dans un navigateur :
```
http://<IP_SERVEUR>:8000/docs
```

### Sauvegarde

```bash
asset-manager db backup
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
