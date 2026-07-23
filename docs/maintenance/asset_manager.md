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

### **Afficher l'aide pour une catégorie**

```bash
asset-manager <catégorie> help
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
| **FastAPI**         | `fastapi:start`                | Démarre le service FastAPI                                  |
| **FastAPI**         | `fastapi:stop`                 | Arrête le service FastAPI                                   |
| **FastAPI**         | `fastapi:restart`              | Redémarre le service FastAPI                                |
| **FastAPI**         | `fastapi:status`               | Affiche le statut du service FastAPI                        |
| **Logs**            | `logs:show`                    | Affiche les logs (FastAPI.log) en temps réel                |
| **Base de données** | `db:connect`                   | Se connecte directement à MariaDB                           |
| **Base de données** | `db:backup`                    | Effectue un dump complet de la BDD (compressé en .gz)       |
| **Base de données** | `db:backup --no-compress`      | Effectue un dump non compressé                              |
| **Base de données** | `db:import <fichier.sql[.gz]>` | Importe un fichier SQL vers la BDD                          |
| **Base de données** | `db:import-schema`             | Importe le schéma SQL par défaut                            |
| **Base de données** | `db:schema`                    | Génère le schéma SQL de la BDD                              |
| **Base de données** | `db:size`                      | Affiche la taille des tables en Mo                          |
| **Base de données** | `db:vacuum`                    | Optimise les tables `correlations` et `cve`                 |
| **Base de données** | `db:check`                     | Vérifie l'intégrité des tables                              |
| **Corrélations**    | `corr:launch`                  | Lance le pipeline de corrélation + analyse (Mistral)        |
| **Corrélations**    | `corr:clean`                   | Supprime toutes les corrélations (avec double confirmation) |
| **Documents**       | `docs:list`                    | Liste les PDFs avec taille et date                          |
| **Documents**       | `docs:clear`                   | Supprime TOUS les PDFs (avec confirmation)                  |
| **Documents**       | `docs:size`                    | Affiche la taille totale du dossier documents               |
| **CVE**             | `cve:show`                     | Affiche le COUNT des CVE par statut                         |
| **Système**         | `sys:info`                     | Affiche RAM, CPU, température, uptime                       |
| **Système**         | `sys:ports`                    | Vérifie les ports 3000 (Grafana) et 8000 (FastAPI)          |
| **Système**         | `sys:services`                 | Affiche le statut des services (FastAPI, MariaDB, Grafana)  |
| **Système**         | `sys:check-env`                | Vérifie que les variables `.env` sont présentes             |
| **Système**         | `sys:check-db`                 | Vérifie la connexion à la BDD + COUNT des tables            |
| **Système**         | `sys:check-disk`               | Affiche l'espace disque (documents + logs)                  |
| **Système**         | `sys:update-deps`              | Met à jour les dépendances Python (`requirements.txt`)      |
| **Système**         | `sys:version`                  | Affiche les versions de Python, FastAPI, MariaDB            |


---

## **Exemples d'utilisation**

### **Gestion de FastAPI**

```bash
# Démarrer le service
asset-manager fastapi start

# Vérifier le statut
asset-manager fastapi status

# Redémarrer
asset-manager fastapi restart
```

### **Gestion de la base de données**

```bash
# Sauvegarder la BDD (compressé)
asset-manager db backup

# Sauvegarder sans compression
asset-manager db backup --no-compress

# Importer un backup
asset-manager db import /chemin/vers/backup.sql.gz

# Vérifier l'intégrité
asset-manager db check
```

### **Corrélation et analyse**

```bash
# Lancer le pipeline complet
asset-manager corr launch

# Nettoyer les corrélations (ATTENTION : irréversible)
asset-manager corr clean
```

### **Vérifications système**

```bash
# Vérifier les variables d'environnement
asset-manager sys check-env

# Vérifier l'espace disque
asset-manager sys check-disk

# Afficher les versions
asset-manager sys version
```

---

## **Configuration**

### **Variables d'environnement**

Toutes les variables sont chargées depuis `.env` (à la racine du projet).
Ce fichier est normalement rempli lors de l'installation.


| Variable          | Description                        | Requis ?             |
| ----------------- | ---------------------------------- | -------------------- |
| `DB_HOST`         | Hôte de la base de données         | *(requis)*           |
| `DB_PORT`         | Port de la base de données         | *(requis)*           |
| `DB_USER`         | Utilisateur de la base de données  | *(requis)*           |
| `DB_NAME`         | Nom de la base de données          | *(requis)*           |
| `DB_PASSWORD`     | Mot de passe de la base de données | *(requis)*           |
| `NVD_API_KEY`     | Clé API pour le NVD                | *(optionnel)*        |
| `MISTRAL_API_KEY` | Clé API pour Mistral               | *(optionnel)*        |
| `SERVER_IP`       | IP du serveur                      | *(requis)*           |
| `MISTRAL_MODEL`   | Modèle Mistral à utiliser          | *(optionnel)*        |


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