---
title: Configurer un type d'équipement
parent: Guides opérationnels
nav_order: 3
---

# ⚙️ Configurer un type d'équipement

**Choisir les bons paramètres dans `/ui/equipment-types`**

---

## ❓ **2 Questions fondamentales**

### 1️⃣ **Quelle est la source du vendor NVD ?**

| Source | `vendor_source` | Exemples |
|--------|-----------------|----------|
| **OS** | `os_fk` | PC, serveurs, laptops |
| **Firmware** | `fw_fk` | Switches, routeurs |
| **Matériel** | `materiel` | NAS, caméras, lecteurs biométriques |
| **Auto** | `detection_auto` | Essaie os_fk → fw_fk → OS textuel → vendor matériel |

### 2️⃣ **Quel champ de version utiliser ?**

| Champ | Option | Exemples |
|-------|--------|----------|
| OS normalisé FK | `use_os_version = 1` | Ubuntu 22.04, DSM 7.2 |
| Version OS texte libre | `use_version_os = 1` | "Windows Server 2019" |
| Firmware FK | `use_version_firmware = 1` | Firmware switch |
| BIOS FK | `use_version_bios = 1` | BIOS UEFI |

---

## 🌳 **Arbre de décision**

```
L'équipement a un OS installé (Windows, Linux, DSM…) ?
│
├── OUI
│     ├── L'OS est la source principale de CVE ?
│     │     ├── OUI → vendor_source = "os_fk"
│     │     │         use_os_version = 1
│     │     │         use_version_os = 1 (sauf Windows Server)
│     │     └── NON → vendor_source = "materiel"
│     │               use_os_version = 1
│     │
│     └── Ex: serveur Windows → os_fk, os=1, version_os=0
│           NAS Synology → materiel, os=1, version_os=1
│
└── NON (équipement réseau, caméra, lecteur…)
      ├── A un firmware versionné ?
      │     ├── OUI → vendor_source = "fw_fk" ou "materiel"
      │     │         use_version_firmware = 1
      │     └── NON → vendor_source = "materiel"
      │               aucun champ version à activer
      │
      └── Ex: switch → materiel, firmware=1
            caméra → materiel, firmware=1
```

---

## 📋 **Configurations types**

### Serveur Windows / Linux

```yaml
vendor_source: os_fk
use_os_version: 1
use_version_os: 0  # builds Windows non comparables
use_version_firmware: 0
use_version_bios: 0
```

### NAS Synology / QNAP

```yaml
vendor_source: materiel
use_os_version: 1
use_version_os: 1
use_version_firmware: 0
use_version_bios: 0
```

### Switch / Routeur

```yaml
vendor_source: fw_fk  # ou materiel
use_os_version: 0
use_version_os: 0
use_version_firmware: 1
use_version_bios: 0
```

### Caméra IP / Lecteur biométrique

```yaml
vendor_source: materiel
use_os_version: 0
use_version_os: 0
use_version_firmware: 1
use_version_bios: 0
```

---

## 🎯 **Options avancées**

| Option | Description | Défaut |
|--------|-------------|--------|
| `correlation_enabled` | Activer la corrélation pour ce type | 1 |
| `auto_correlate` | Lancer automatiquement la corrélation | 1 |
| `default_criticite` | Criticité par défaut | moyen |
| `default_statut` | Statut par défaut | actif |
