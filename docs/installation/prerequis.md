---
title: Prérequis
---

# 📋 **Prérequis - AirGappedCVE**
*Configuration système requise avant l'installation*

---

## **🔧 Exigences matérielles et logicielles**

### **Système d'exploitation**
   Exigence | Détail |
 |----------|--------|
 | **OS** | Ubuntu Server 22.04 LTS (ou supérieur) / Debian 11+ |
 | **Architecture** | x86_64 (AMD64) ou ARM64 |
 | **Utilisateur** | **Root** (ou `sudo`) **obligatoire** |

### **Ressources minimales**
 | Ressource | Minimum | Recommandé |
 |----------|---------|------------|
 | **Espace disque** | 5 Go | 10 Go (pour les logs et bases de données) |
 | **Mémoire RAM** | 2 Go | 4 Go |
 | **CPU** | 2 cœurs | 4 cœurs |

### **Ports réseau**
 | Port | Service | Utilisation |
 |------|---------|-------------|
 | **3306** | MariaDB | Base de données locale |
 | **8000** | FastAPI | API REST du gestionnaire |

---

## **📦 Dépendances système**

### **Outils requis**
Les outils suivants doivent être installés **avant** de lancer l'installation :
 | Outil | Commande d'installation | Description |
 |-------|--------------------------|-------------|
 | `curl` | `apt-get install -y curl` | Téléchargement de fichiers |
 | `wget` | `apt-get install -y wget` | Téléchargement alternatif |
 | `git` | `apt-get install -y git` | Clone du dépôt GitHub |
 | `bc` | `apt-get install -y bc` | Calculs arithmétiques |
 | `ss` | `apt-get install -y iproute2` | Vérification des ports |
 | `pgrep` | `apt-get install -y procps` | Gestion des processus |
 | `add-apt-repository` | `apt-get install -y software-properties-common` | Ajout de dépôts APT |
 | `ip` | `apt-get install -y iproute2` | Gestion réseau |

### **Dépendances Python**
Python **3.10 ou supérieur** est requis. Les dépendances Python sont installées automatiquement via `pip` dans un *virtualenv*.

---

## **🔐 Accès et permissions**

### **Accès root**
Le script d'installation **doit être exécuté en root** :
```bash
sudo bash install.sh
