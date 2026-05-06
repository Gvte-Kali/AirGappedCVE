---
title: Types d'équipements
parent: Référentiels métier
nav_order: 6
---

# Types d'équipements
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Rôle

Les types d'équipements (`equipment_types`) configurent le comportement du moteur de corrélation pour chaque catégorie d'équipement. C'est ici qu'on définit **quelles sources de version utiliser** et **comment déterminer le vendor NVD**.

Chaque asset est lié à un type via `equipment_type_id`. Le moteur lit la configuration de ce type pour adapter sa stratégie de corrélation.

---

## Champs

| Champ | Description |
|-------|-------------|
| Code | Identifiant technique unique (ex: `serveur`, `nas`, `camera_axis`) |
| Label | Nom affiché dans l'interface (ex: `Serveur`, `NAS`, `Caméra Axis`) |
| OS (FK) | Utiliser `os_version_id` pour la corrélation |
| Version OS | Utiliser `version_os` texte libre pour affiner la comparaison de version |
| Firmware | Utiliser `fw_version_id` pour la corrélation |
| BIOS | Utiliser `bios_version_id` pour la corrélation |
| Source vendor | Comment déterminer le vendor NVD (voir ci-dessous) |

---

## Colonnes de version — Explication détaillée

### OS (FK) — `use_os_version`

Quand activé, le moteur utilise `os_version_id` de l'asset (FK vers `os_versions`) pour identifier le produit NVD exact. C'est le matching le plus précis.

**Activer pour :** PC, serveurs, laptops, NAS, Raspberry Pi — tout équipement dont l'OS est dans le référentiel `os_versions`.

### Version OS — `use_version_os`

Quand activé, le moteur utilise le champ `version_os` texte libre de l'asset pour affiner la comparaison de version par matching flou.

**Désactiver pour :** Windows Server — les builds NVD (`10.0.14393.xxxx`) ne sont pas comparables avec l'année de version (`2022`). La corrélation produit suffit.

**Activer pour :** Synology DSM, FortiOS — les numéros de version sont directement comparables avec les plages NVD.

### Firmware — `use_version_firmware`

Quand activé, le moteur utilise `fw_version_id` de l'asset. À utiliser pour les équipements réseau dont le firmware est le produit principal à corréler.

**Activer pour :** Switches, routeurs, pare-feux, caméras.

### BIOS — `use_version_bios`

Quand activé, le moteur utilise `bios_version_id`. Rarement nécessaire sauf pour des CVE BIOS/UEFI spécifiques.

---

## Source vendor — `vendor_source`

Détermine quelle source est utilisée pour trouver le vendor NVD cible lors de la recherche de CVE.

### `os_fk`

Utilise le `nvd_vendor` de l'OS normalisé (`os_versions`).

```
asset.os_version_id → os_versions.nvd_vendor → vendor CVE
```

Fallback si `os_version_id` est NULL : détection depuis `systeme_exploitation` / `version_os` via `os_vendor_map` dans `config.yml`.

**Pour :** PC, serveurs, laptops, Raspberry Pi — l'OS définit le vendor (Microsoft pour Windows, Synology pour DSM…).

### `fw_fk`

Utilise le `nvd_vendor` du firmware normalisé.

```
asset.fw_version_id → os_versions.nvd_vendor → vendor CVE
```

Fallback : vendor matériel de l'asset.

**Pour :** Équipements réseau avec firmware distinct du matériel.

### `materiel`

Utilise directement le `nvd_vendor` du fabricant matériel de l'asset.

```
asset.vendor_id → product_vendors.nvd_vendor → vendor CVE
```

Bonus : si `fw_version_id` est défini, utilise son `nvd_vendor` en priorité.

**Pour :** NAS Synology, caméras, lecteurs biométriques — le fabricant matériel est le même que l'éditeur des CVE.

### `detection_auto`

Essaie dans l'ordre : `os_fk` → `fw_fk` → OS textuel → vendor matériel.

**Pour :** Types génériques ou incertains. Moins prévisible que les autres options.

---

## Configuration recommandée par type

| Type | OS (FK) | Version OS | Firmware | BIOS | Source vendor |
|------|---------|-----------|----------|------|---------------|
| Serveur | ✅ | ❌ | ❌ | ❌ | `os_fk` |
| PC | ✅ | ✅ | ❌ | ❌ | `os_fk` |
| Laptop | ✅ | ✅ | ❌ | ❌ | `os_fk` |
| NAS | ✅ | ✅ | ❌ | ❌ | `materiel` |
| Switch | ❌ | ❌ | ✅ | ❌ | `fw_fk` |
| Routeur | ❌ | ❌ | ✅ | ❌ | `fw_fk` |
| Pare-feu | ❌ | ❌ | ✅ | ❌ | `fw_fk` |
| Caméra Axis | ❌ | ❌ | ✅ | ❌ | `materiel` |
| Caméra Hikvision | ❌ | ❌ | ✅ | ❌ | `materiel` |
| Lecteur biométrique | ❌ | ❌ | ✅ | ❌ | `materiel` |
| Raspberry Pi | ✅ | ✅ | ❌ | ❌ | `os_fk` |
| Imprimante | ❌ | ❌ | ✅ | ❌ | `materiel` |

{: .note }
**Pourquoi `use_version_os = false` pour les serveurs ?** Les CVE Windows utilisent des builds NVD (`10.0.14393.xxxx`) que `normalize_version("2022")` ne peut pas comparer correctement. La corrélation par produit NVD (`windows_server_2022`) suffit et est plus fiable.

---

## Gestion depuis l'interface

La page `/ui/equipment-types` permet d'éditer chaque type directement dans le tableau (clic sur une ligne). Les modifications prennent effet au **prochain lancement de la corrélation**.

Un type utilisé par des assets ne peut pas être supprimé (la colonne Assets indique le nombre d'assets associés).
