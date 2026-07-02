---
title: Prérequis
nav_order: 1
parent: Installation & Configuration
---

# 📋 Prérequis

**Configuration système requise avant l'installation**

---

## Exigences matérielles et logicielles

### Système d'exploitation

- **OS** : Ubuntu Server 22.04 LTS (ou supérieur) / Debian 11+ (Tests uniquement sur Ubuntu 24.04 LTS)
- **Architecture** : x86_64 (AMD64) ou ARM64
- **Utilisateur** : Root (ou `sudo`) obligatoire

### Ressources minimales

| Ressource | Minimum | Recommandé |
|----------|---------|------------|
| Espace disque | 20 Go | 500 Go |
| Mémoire RAM | 4 Go | 8 Go |
| CPU | 2 cœurs | 4 cœurs |

### Ports réseau

| Port | Service | Utilisation |
|------|---------|-------------|
| 3306 | MariaDB | Base de données locale |
| 8000 | FastAPI | API REST du gestionnaire |

---

## Dépendances système

### Outils requis

Les outils suivants doivent être installés avant de lancer l'installation :

- `curl` - Téléchargement de fichiers
- `wget` - Téléchargement alternatif
- `git` - Clone du dépôt GitHub
- `bc` - Calculs arithmétiques
- `ss` / `ip` - Vérification des ports et gestion réseau (paquet `iproute2`)
- `pgrep` - Gestion des processus (paquet `procps`)
- `add-apt-repository` - Ajout de dépôts APT (paquet `software-properties-common`)

### Dépendances Python

Python 3.10 ou supérieur est requis. Les dépendances Python sont installées automatiquement via `pip` dans un virtualenv.
Le virtualenv est utilisé pour isoler le projet et ne pas casser python sur le système en cas de souci sur l'installation des paquets.

---


### Accès MariaDB

- Dans le fichier de configuration `.env`, on configurera les variables nécessaires à la configuration de mariadb.
- Mot de passe root MariaDB : Non modifié par défaut (utilise celui du système car connexion en `sudo mysql`)

---

## Connexion Internet

### Requis pour l'installation

Une connexion Internet active est nécessaire pour :
- Télécharger les dépendances (`apt-get`, `pip`)
- Cloner le dépôt GitHub
- Télécharger les fichiers NVD (si `NVD_API_KEY` est configurée)

### Vérification

Avant de lancer l'installation, vérifiez que :

```bash
ping -c 1 github.com
curl -sSf https://github.com >/dev/null && echo "OK" || echo "KO"
```
