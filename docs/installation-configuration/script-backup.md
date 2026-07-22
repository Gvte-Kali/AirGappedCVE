--- 
title: Script de backup de base de données
nav_order: 5
parent: Installation & Configuration
---

# ⚙️ Script de Backup

---

## **📌 Aperçu général**
Ce script **automatise la sauvegarde de la base de données MariaDB/MySQL** du projet **AirGappedCVE** en :
1. **Créant un dump SQL compressé** (`gzip`) de la base de données.
2. **Stockant une copie locale** (dans `/data/backups/` par défaut).
3. **Copiant le backup vers un NAS** (optionnel) via **SMB, SSH/SCP, RSYNC ou un dossier local monté**.
4. **Gérant la rotation** : conserve **uniquement les 5 backups les plus récents** (configurable) par destination.

---

## **⚙️ Configuration**

### **1. Fichier `.env` (obligatoire)**
Toutes les configurations sont **chargées depuis le fichier `.env`** situé à la racine du projet.
**Ne modifiez pas le script `backup.sh`** : éditez uniquement `.env`.

---

### **2. Configuration du NAS (optionnelle)**
Pour activer la sauvegarde sur un NAS, dans le fichier **.env**, définissez :
```ini
ENABLE_NAS_BACKUP=true
NAS_PROTOCOL=smb  # ou ssh, rsync, local
```

#### **🔹 Protocole SMB (partage Windows/NAS)**

| Variable | Description | Exemple |
|----------|-------------|---------|
| `NAS_SMB_SERVER` | Adresse IP ou nom du serveur SMB | 192.168.1.100 |
| `NAS_SMB_SHARE` | Nom du partage SMB | backup |
| `NAS_SMB_USER` | Utilisateur SMB | admin |
| `NAS_SMB_PASSWORD` | Mot de passe SMB | votre_mdp |
| `NAS_SMB_DIR` | Dossier de destination sur le NAS | AirGappedCVE |
| `NAS_SMB_MOUNT` | Point de montage local temporaire | /mnt/nas_backup |

**Prérequis** :
```bash
sudo apt install cifs-utils  # Pour mount.cifs
```

---

#### **🔹 Protocole SSH/SCP**

| Variable | Description | Exemple |
|----------|-------------|---------|
| `NAS_SSH_SERVER` | Adresse IP ou nom du serveur SSH | 192.168.1.100 |
| `NAS_SSH_USER` | Utilisateur SSH | backup_user |
| `NAS_SSH_PASSWORD` | Mot de passe SSH (optionnel) | votre_mdp |
| `NAS_SSH_PORT` | Port SSH | 22 |
| `NAS_SSH_DIR` | Chemin de destination sur le NAS | /backup/AirGappedCVE |

> ⚠️ **Pour éviter de stocker le mot de passe en clair** :
> Utilisez une **clé SSH** (recommandé) :
> ```bash
> ssh-copy-id NAS_SSH_USER@NAS_SSH_SERVER
> ```
> Puis laissez `NAS_SSH_PASSWORD` vide.

**Prérequis** :
```bash
sudo apt install openssh-client
```

---

#### **🔹 Protocole RSYNC**

| Variable | Description | Exemple |
|----------|-------------|---------|
| `NAS_RSYNC_SERVER` | Adresse IP ou nom du serveur RSYNC | 192.168.1.100 |
| `NAS_RSYNC_USER` | Utilisateur RSYNC | backup_user |
| `NAS_RSYNC_DIR` | Chemin de destination (module RSYNC) | backup/AirGappedCVE |

**Prérequis** :
```bash
sudo apt install rsync
```

---

#### **🔹 Dossier local monté (NAS monté via NFS/FUSE)**

| Variable | Description | Exemple |
|----------|-------------|---------|
| `NAS_LOCAL_MOUNT` | Chemin du dossier monté localement | /mnt/nas/backup/AirGappedCVE |

**Prérequis** :
Montez manuellement le NAS avant d'exécuter le script :
```bash
sudo mount -t nfs NAS_SERVER:/chemin/partage /mnt/nas
```

---

### **3. Autres options**

| Variable | Description | Exemple | Défaut |
|----------|-------------|---------|--------|
| `MAX_BACKUPS` | Nombre max de backups conservés | 10 | 5 |

---

## **✅ Prérequis système**
Installez les outils nécessaires selon votre protocole :
```bash
# Pour tous les backups (local + NAS)
sudo apt install mariadb-client gzip

# Pour SMB
sudo apt install cifs-utils

# Pour SSH/SCP
sudo apt install openssh-client

# Pour RSYNC
sudo apt install rsync
```

---

## **🔄 Exécution**
```bash
# Depuis le dossier du projet
bash scripts/backup.sh
```
**Sortie** :
- Affichage coloré dans le terminal.
- Logs détaillés dans `logs/backup.log`.
- Récapitulatif final avec taille du backup et destination(s).
