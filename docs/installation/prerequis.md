---
title: Prrequis
nav_order: 1
parent: Installation
---

# \ud83d\udccb Pr\u00e9requis

**Configuration syst\u00e8me requise avant l'installation**

---

## Exigences mat\u00e9rielles et logicielles

### Syst\u00e8me d'exploitation

- **OS** : Ubuntu Server 22.04 LTS (ou sup\u00e9rieur) / Debian 11+
- **Architecture** : x86_64 (AMD64) ou ARM64
- **Utilisateur** : **Root** (ou `sudo`) **obligatoire**

### Ressources minimales

| Ressource | Minimum | Recommand\u00e9 |
|----------|---------|------------|
| Espace disque | 5 Go | 10 Go (pour les logs et bases de donn\u00e9es) |
| M\u00e9moire RAM | 2 Go | 4 Go |
| CPU | 2 c\u0153urs | 4 c\u0153urs |

### Ports r\u00e9seau

| Port | Service | Utilisation |
|------|---------|-------------|
| **3306** | MariaDB | Base de donn\u00e9es locale |
| **8000** | FastAPI | API REST du gestionnaire |

---

## D\u00e9pendances syst\u00e8me

### Outils requis

Les outils suivants doivent \u00eatre install\u00e9s **avant** de lancer l'installation :

- `curl` - T\u00e9l\u00e9chargement de fichiers
- `wget` - T\u00e9l\u00e9chargement alternatif
- `git` - Clone du d\u00e9p\u00f4t GitHub
- `bc` - Calculs arithm\u00e9tiques
- `ss` / `ip` - V\u00e9rification des ports et gestion r\u00e9seau (paquet `iproute2`)
- `pgrep` - Gestion des processus (paquet `procps`)
- `add-apt-repository` - Ajout de d\u00e9p\u00f4ts APT (paquet `software-properties-common`)

### D\u00e9pendances Python

Python **3.10 ou sup\u00e9rieur** est requis. Les d\u00e9pendances Python sont install\u00e9es automatiquement via `pip` dans un *virtualenv*.

---

## Acc\u00e8s et permissions

### Acc\u00e8s root

Le script d'installation **doit \u00eatre ex\u00e9cut\u00e9 en root** :

```bash
sudo bash install.sh
```

### Acc\u00e8s MariaDB

- Le script configure automatiquement un utilisateur MariaDB d\u00e9di\u00e9.
- **Mot de passe root MariaDB** : Non modifi\u00e9 par d\u00e9faut (utilise celui du syst\u00e8me).

---

## Connexion Internet

### Requis pour l'installation

Une **connexion Internet active** est n\u00e9cessaire pour :
- T\u00e9l\u00e9charger les d\u00e9pendances (`apt-get`, `pip`).
- Cloner le d\u00e9p\u00f4t GitHub.
- T\u00e9l\u00e9charger les fichiers NVD (si `NVD_API_KEY` est configur\u00e9e).

### V\u00e9rification

Avant de lancer l'installation, v\u00e9rifiez que :

```bash
ping -c 1 github.com  # Test de connectivit\u00e9
curl -sSf https://github.com >/dev/null && echo "OK" || echo "KO"  # Test HTTPS
```
