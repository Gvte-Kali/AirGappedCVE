---
title: Backup
nav_order: 3
parent: Scripts
---

# Résumé du script `backup.sh`

**⚠️ Ce script n'a pas été testé sur les backup à distance, si vous voulez vous assurer que les backups fonctionnent correctement, montez un dossier directement via votre système de backup.**
_Voir la section **Fallback** en pied de page_

## **Aperçu général**

Le script `backup.sh` (version 5.1.0) automatise la sauvegarde de la base de données **MariaDB/MySQL** pour le projet **AirGappedCVE**. Il permet de :

- Créer un **dump SQL compressé** (`gzip`) de la base de données.
- Stocker une **copie locale** dans un dossier configurable.
- Copier le backup vers un **NAS** (optionnel) via **SMB, SSH/SCP, RSYNC ou un dossier local monté**.
- Gérer la **rotation automatique** des sauvegardes (conserve uniquement les 5 backups les plus récents par destination).
- Vérifier l'**intégrité** des fichiers de backup.
- Afficher un **récapitulatif détaillé** à la fin de l'exécution.

**Usage** : `bash scripts/backup.sh`

---

## **Configuration**

Toutes les configurations sont **chargées depuis le fichier `.env`** situé à la racine du projet. **Ne modifiez pas le script** : éditez uniquement `.env`.

### **Variables obligatoires (base de données)**


| Variable           | Description                         | Défaut               |
| ------------------ | ----------------------------------- | -------------------- |
| `DB_NAME`          | Nom de la base de données           | `asset_vuln_manager` |
| `DB_USER`          | Utilisateur de la base              | `avea`               |
| `DB_PASSWORD`      | Mot de passe de la base             | *(requis)*           |
| `DB_HOST`          | Hôte de la base                     | `127.0.0.1`          |
| `DB_PORT`          | Port de la base                     | `3306`               |
| `LOCAL_BACKUP_DIR` | Dossier de sauvegarde locale        | `backups`            |
| `MAX_BACKUPS`      | Nombre maximal de backups conservés | `5`                  |


---

### **Variables optionnelles (NAS)**

Pour activer la sauvegarde sur NAS, définissez dans `.env` :

```ini
ENABLE_NAS_BACKUP=true
NAS_PROTOCOL=smb  # ou ssh, rsync, local
```

#### **Protocoles supportés**

1. **SMB** (partage Windows/NAS)
  - Variables : `NAS_SMB_SERVER`, `NAS_SMB_SHARE`, `NAS_SMB_USER`, `NAS_SMB_PASSWORD`, `NAS_SMB_DIR`, `NAS_SMB_MOUNT`
  - Prérequis : `sudo apt install cifs-utils`
2. **SSH/SCP**
  - Variables : `NAS_SSH_SERVER`, `NAS_SSH_USER`, `NAS_SSH_PASSWORD`, `NAS_SSH_PORT`, `NAS_SSH_DIR`
  - Prérequis : `openssh-client`
3. **RSYNC**
  - Variables : `NAS_RSYNC_SERVER`, `NAS_RSYNC_USER`, `NAS_RSYNC_DIR`
  - Prérequis : `rsync`
4. **Dossier local monté**
  - Variable : `NAS_LOCAL_MOUNT`

---

## **Fonctionnalités principales**

### **1. Détection automatique et chargement de `.env`**

- Détecte le répertoire du projet et charge les variables depuis `.env`.
- Priorité aux variables déjà exportées dans l'environnement.

### **2. Vérification des prérequis**

- Vérifie la présence de `mysqldump` et `gzip`.
- Vérifie que `DB_PASSWORD` est défini.
- Si NAS activé, vérifie les outils spécifiques au protocole choisi (ex: `mount.cifs` pour SMB, `scp` pour SSH).

### **3. Création du dossier de backup**

- Crée le dossier local s'il n'existe pas (`LOCAL_BACKUP_DIR`).

### **4. Rotation des backups**

- Supprime le backup le plus ancien si le nombre maximal (`MAX_BACKUPS`) est atteint.

### **5. Dump de la base de données**

- Utilise `mysqldump` avec les options :
  - `--single-transaction` (pour éviter les verrous).
  - `--routines`, `--triggers`, `--events` (pour inclure tous les objets).
  - `--skip-ssl` (désactive SSL pour les environnements locaux).
- Compresse le dump avec `gzip`.

### **6. Vérification de l'intégrité**

- Utilise `gzip -t` pour vérifier que le fichier de backup n'est pas corrompu.

### **7. Sauvegarde sur NAS**

- **SMB** : Monte le partage, copie le backup, puis démonte.
- **SSH/SCP** : Copie via `scp` et gère la rotation à distance.
- **RSYNC** : Copie via `rsync` et gère la rotation à distance.
- **Local** : Copie directement vers le dossier monté.

### **8. Affichage du récapitulatif**

- Affiche un résumé complet :
  - Date et heure.
  - Détails de la base de données.
  - Chemin et taille du backup local.
  - Détails de la sauvegarde NAS (si activée).

---

## **Gestion des logs**

- **Fichier de log** : `$PROJECT_DIR/logs/backup.log`
- **Niveaux de log** :
  - `log()` : Succès (vert, `[✓]`).
  - `error()` : Erreur critique (rouge, `[✗]`). Arrête le script.
  - `warn()` : Avertissement (jaune, `[⚠]`).
  - `info()` : Information (bleu, `[~]`).
  - `title()` : Titre (violet, `===`).

---

## **Comportement en cas d'erreur**

- Le script s'arrête immédiatement en cas d'erreur critique (ex: `mysqldump` introuvable, `DB_PASSWORD` manquant).
- Les avertissements n'arrêtent pas l'exécution (ex: impossibilité de démonter un partage SMB).
- Les logs détaillés sont écrits dans `backup.log` et affichés en console.

---

## **Fallback sauvegarde sur dossier distant en cas de non fonctionnement de backup.sh**

Une fois le dossier distant monté, on va faire la sauvegarde dedans.
Les sauvegardes peuvent s'effectuer depuis l'utilitaire **'asset-manager'** : 

```bash
asset-manager db backup /path/to/file/file_name
```

Il est possible de mettre cette commande en cron job ou dans un script "maison" afin d'automatiser la sauvegarde dans le cas où **backup.sh** ne fonctionne pas sur l'enregistrement sur dossier distant.

---