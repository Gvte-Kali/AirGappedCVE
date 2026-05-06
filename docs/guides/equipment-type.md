---
title: Configurer un type d'équipement
parent: Guides opérationnels
nav_order: 3
---

# Configurer un type d'équipement
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Ce guide aide à choisir les bons paramètres lors de la création ou modification d'un type d'équipement dans `/ui/equipment-types`.

---

## Les deux questions fondamentales

Avant de configurer un type, répondre à deux questions :

**1. Quelle est la source du vendor NVD pour cet équipement ?**
- L'OS définit le vendor → `os_fk` (PC, serveurs, laptops)
- Le firmware définit le vendor → `fw_fk` (switches, routeurs)
- Le fabricant matériel définit le vendor → `materiel` (NAS, caméras, lecteurs)

**2. Quel champ de version utiliser pour comparer avec les CVE ?**
- OS normalisé FK → `use_os_version = 1`
- Version texte libre → `use_version_os = 1`
- Firmware FK → `use_version_firmware = 1`
- BIOS FK → `use_version_bios = 1`

---

## Arbre de décision

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
            lecteur biométrique → materiel, firmware=1
```

---

## Configurations types par catégorie

### Serveur Windows / Linux

```
OS (FK)      : ✅
Version OS   : ❌  (builds Windows non comparables)
Firmware     : ❌
BIOS         : ❌
Vendor source: os_fk
```

Pourquoi `Version OS = ❌` pour Windows ? Les CVE Windows utilisent des builds `10.0.14393.xxxx` que `normalize_version("2022")` ne peut pas comparer correctement. Le filtre produit (`windows_server_2022`) est suffisant.

### NAS (Synology, QNAP…)

```
OS (FK)      : ✅
Version OS   : ✅  (DSM 7.x.x-XXXXX comparables avec NVD)
Firmware     : ❌
BIOS         : ❌
Vendor source: materiel
```

### PC / Laptop

```
OS (FK)      : ✅
Version OS   : ✅
Firmware     : ❌
BIOS         : ❌
Vendor source: os_fk
```

### Switch / Routeur / Pare-feu

```
OS (FK)      : ❌
Version OS   : ❌
Firmware     : ✅
BIOS         : ❌
Vendor source: fw_fk  (si firmware normalisé dans os_versions)
              ou materiel (si vendor matériel = éditeur CVE)
```

### Caméra IP (Axis, Hikvision…)

```
OS (FK)      : ❌
Version OS   : ❌
Firmware     : ✅
BIOS         : ❌
Vendor source: materiel
```

### Lecteur biométrique / Lecteur de cartes

```
OS (FK)      : ❌
Version OS   : ❌
Firmware     : ✅
BIOS         : ❌
Vendor source: materiel
```

### Raspberry Pi

```
OS (FK)      : ✅
Version OS   : ✅
Firmware     : ❌
BIOS         : ❌
Vendor source: os_fk
```

---

## Erreurs fréquentes

### Trop de faux positifs

**Symptôme :** Des CVE remontent pour des produits qui ne concernent pas l'équipement.

**Cause probable :** `vendor_source = detection_auto` trop permissif, ou `use_version_os = 1` sur un équipement dont les versions ne sont pas comparables (Windows Server).

**Solution :** Passer à `vendor_source = os_fk` ou `materiel` selon le type, et désactiver `use_version_os` si les formats de version ne sont pas comparables.

### Aucune corrélation détectée

**Symptôme :** 0 CVE trouvée pour un équipement alors que des CVE existent.

**Cause probable :** `vendor_source` incorrect — le moteur cherche dans le mauvais vendor NVD.

**Solution :**
1. Vérifier le `nvd_vendor` du fabricant de l'asset
2. Vérifier que des CVE existent en base pour ce vendor : `SELECT COUNT(*) FROM cve WHERE fabricant = 'nvd_vendor'`
3. Vérifier que `vendor_source` correspond à la source correcte pour ce type

### Corrélations en mode `informatif` au lieu d`affirme`

**Symptôme :** Toutes les corrélations sont `informatif`.

**Cause probable :** `use_os_version = 0` (OS FK non activé) ou `os_version_id` non renseigné sur les assets.

**Solution :** Activer `use_os_version = 1` dans le type ET renseigner l'OS normalisé sur les assets.
