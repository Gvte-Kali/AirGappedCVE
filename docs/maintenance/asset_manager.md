---
title: Utilitaire asset-manager
nav_order: 1
parent : Maintenance
---

# **asset-manager** — CLI de maintenance

Outil **Bash** (version **1.1.0**) tout-en-un pour gérer la maintenance de la stack **AirGappedCVE**.  
Il centralise l'exécution des scripts Python et Bash, et propose une interface unifiée pour les opérations courantes.

---

## **Aperçu général**

- **Chargement automatique** des variables depuis `.env` (priorité aux variables déjà exportées).
- **Détection de l'environnement** : Distingue automatiquement **PROD** (`/opt/asset-manager`) et **DEV** (autre chemin).
- **Gestion des erreurs** : Vérifie les prérequis (ex: `mysqldump`, `mysql`, `gzip`) avant chaque opération.
- **Logging** : Chaque commande affiche son statut en console. Les logs détaillés sont gérés par les scripts individuels.

---

## **Utilisation de base**

### **Afficher l'aide globale**

```bash
asset-manager help
```
ou
```bash
asset-manager
```

### **Afficher l'aide pour une catégorie**

```bash
asset-manager <catégorie> help
```
ou
```bash
asset-manager <catégorie>
```

### **Exécuter une commande**

```bash
asset-manager <catégorie> <commande> [options]
```

---

## **Catégories et commandes disponibles**

### **Catégories**


| Catégorie | Description                                                                          |
| --------- | ------------------------------------------------------------------------------------ |
| `fastapi` | Gestion du service FastAPI (start/stop/restart/status)                               |
| `logs`    | Affichage des logs (show)                                                            |
| `db`      | Gestion de la base de données (connect, backup, import, schema, size, vacuum, check) |
| `corr`    | Gestion des corrélations (launch, clean)                                             |
| `docs`    | Gestion des documents PDF (list, clear, size)                                        |
| `cve`     | Statistiques et dernières CVE (show)                                                 |
| `sys`     | Informations système (info, ports, services, env, disk, deps, version)               |


---

### **Toutes les commandes disponibles**


| Catégorie           | Commande                       | Description                                                 |
| ------------------- | ------------------------------ | ----------------------------------------------------------- |
| **FastAPI**         | _fastapi start_                | Démarre le service FastAPI                                  |
| **FastAPI**         | _fastapi stop_                 | Arrête le service FastAPI                                   |
| **FastAPI**         | _fastapi restart_              | Redémarre le service FastAPI                                |
| **FastAPI**         | _fastapi status_               | Affiche le statut du service FastAPI                        |
| **Logs**            | _logs show_                    | Affiche les logs (FastAPI.log) en temps réel                |
| **Base de données** | _db connect_                   | Se connecte directement à MariaDB                           |
| **Base de données** | _db backup <chemin/vers/fichier.sql>_ | Effectue un dump complet de la BDD (compressé en .gz)       |
| **Base de données** | _db backup --no-compress_      | Effectue un dump non compressé                              |
| **Base de données** | _db import <fichier.sql[.gz]>_ | Importe un fichier SQL vers la BDD                          |
| **Base de données** | _db import-schema_             | Importe le schéma SQL par défaut                            |
| **Base de données** | _db schema_                    | Génère le schéma SQL de la BDD                              |
| **Base de données** | _db size_                      | Affiche la taille des tables en Mo                          |
| **Base de données** | _db vacuum_                    | Optimise les tables `correlations` et `cve`                 |
| **Base de données** | _db check_                     | Vérifie l'intégrité des tables                              |
| **Corrélations**    | _corr launch_                  | Lance le pipeline de corrélation + analyse (Mistral)        |
| **Corrélations**    | _corr clean_                   | Supprime toutes les corrélations (avec double confirmation) |
| **Documents**       | _docs list_                    | Liste les PDFs avec taille et date                          |
| **Documents**       | _docs clear_                   | Supprime TOUS les PDFs (avec confirmation)                  |
| **Documents**       | _docs size_                    | Affiche la taille totale du dossier documents               |
| **CVE**             | _cve show_                     | Affiche le COUNT des CVE par statut                         |
| **Système**         | _sys info_                     | Affiche RAM, CPU, température, uptime                       |
| **Système**         | _sys ports_                    | Vérifie les ports 3000 (Grafana) et 8000 (FastAPI)          |
| **Système**         | _sys services_                 | Affiche le statut des services (FastAPI, MariaDB, Grafana)  |
| **Système**         | _sys check-env_                | Vérifie que les variables `.env` sont présentes             |
| **Système**         | _sys check-db_                 | Vérifie la connexion à la BDD + COUNT des tables            |
| **Système**         | _sys check-disk_               | Affiche l'espace disque (documents + logs)                  |
| **Système**         | _sys update-deps_              | Met à jour les dépendances Python (`requirements.txt`)      |
| **Système**         | _sys version_                  | Affiche les versions de Python, FastAPI, MariaDB            |


---

## **Chemins par défaut**


| Variable      | Chemin                                          | Description                       |
| ------------- | ----------------------------------------------- | --------------------------------- |
| `SCRIPT_DIR`  | `$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)` | Répertoire du script              |
| `PROJECT_DIR` | `$(dirname "$SCRIPT_DIR")`                      | Répertoire racine du projet       |
| `LOG_FILE`    | `$PROJECT_DIR/logs/FastAPI.log`                 | Fichier de log FastAPI            |
| `VENV_PYTHON` | `$PROJECT_DIR/venv/bin/python`                  | Python de l'environnement virtuel |
| `DOCS_DIR`    | `$PROJECT_DIR/documents`                        | Dossier des documents PDF         |
| `BACKUP_DIR`  | `$PROJECT_DIR/backups`                          | Dossier des sauvegardes           |


---

## **Alias recommandé**

Pour faciliter l'utilisation, on a 2 choix : 

1. Ajouter au PATH via un lien (symlink) de __/opt/asset-manager/scripts/asset-manager.sh__ vers __/usr/local/bin/asset-manager__.
```bash
sudo ln -sf /opt/asset-manager/scripts/asset-manager.sh /usr/local/bin/asset-manager && sudo chmod +x /usr/local/bin/asset-manager
```

2. Ajoutez=r cet alias à votre `~/.bashrc` ou `~/.zshrc` :

```bash
alias asset-manager="bash /opt/asset-manager/scripts/asset-manager.sh"
```

---

## **Comportements spécifiques**

### **Gestion de systemd**

- Si **systemd** est disponible, les commandes `fastapi:start/stop/restart/status` utilisent `systemctl`.
- Sinon, le script bascule automatiquement sur les scripts de fallback (`scripts/fastapi/start.sh`, etc.).

### **Double confirmation pour les actions destructives**

- `corr:clean` et `docs:clear` demandent **deux confirmations** avant d'exécuter.
- Exemple pour `corr:clean` :
  1. Confirmer avec `O` ou `Y`.
  2. Taper `SUPPRIMER` pour valider définitivement.

### **Gestion des erreurs MariaDB**

- Toutes les commandes de base de données vérifient la connexion avec `check_mariadb()` avant d'agir.
- Si la connexion échoue, le script affiche une erreur et s'arrête.

---

## **Fichiers liés**

- **Emplacement** : `/opt/asset-manager/scripts/asset-manager.sh`
- **Logs** : Voir les fichiers individuels dans `/opt/asset-manager/logs/` (ex: `FastAPI.log`, `backup.log`).