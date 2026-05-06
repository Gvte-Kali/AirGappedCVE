---
title: Schéma & Relations
parent: Base de données
nav_order: 1
---

# Schéma & Relations
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Diagramme des relations

```
product_vendors ──────────────────────────────┐
      │                                        │
      │ 1:N                                    │
      ▼                                        │
product_models                                 │
      │                                        │
      │ 1:N (FK model_id)                      │ 1:N (FK vendor_id)
      ▼                                        ▼
clients                                      assets ◄──────────────────┐
   │                                           │                        │
   │ 1:N                                       │ FK os_version_id       │
   ▼                                           │ FK fw_version_id       │
 sites                                         │ FK bios_version_id     │
   │                                           ▼                        │
   │ 1:N (FK site_id)                    os_versions                    │
   └──────────────────────────────────►        │                        │
                                               │                        │
                                      equipment_types                   │
                                        (FK equipment_type_id)          │
                                                                        │
                                      asset_software                    │
                                        (FK asset_id → assets) ─────────┘
                                                                        
correlations ◄──────── assets (FK asset_id)
      │   └──────────── cve   (FK cve_id)
      │
correlation_rejects (asset_id, cve_id)

cve ◄──── cve_cwe ────► cwe
```

---

## Hiérarchie métier

La hiérarchie principale du système est :

```
clients
  └── sites
        └── assets
              ├── asset_software
              └── correlations
                    └── correlation_rejects (debug)
```

La suppression en cascade est configurée sur toute la chaîne :
- Supprimer un **client** supprime ses sites, leurs assets, et toutes les corrélations associées
- Supprimer un **site** supprime ses assets et leurs corrélations
- Supprimer un **asset** supprime ses corrélations et ses logiciels installés

---

## Clés étrangères principales

| Table | Colonne | Référence | On Delete |
|-------|---------|-----------|-----------|
| `sites` | `client_id` | `clients.id` | CASCADE |
| `assets` | `site_id` | `sites.id` | CASCADE |
| `assets` | `vendor_id` | `product_vendors.id` | SET NULL |
| `assets` | `model_id` | `product_models.id` | SET NULL |
| `assets` | `os_version_id` | `os_versions.id` | SET NULL |
| `assets` | `fw_version_id` | `os_versions.id` | SET NULL |
| `assets` | `bios_version_id` | `os_versions.id` | SET NULL |
| `assets` | `equipment_type_id` | `equipment_types.id` | SET NULL |
| `asset_software` | `asset_id` | `assets.id` | CASCADE |
| `correlations` | `asset_id` | `assets.id` | CASCADE |
| `correlations` | `cve_id` | `cve.cve_id` | CASCADE |
| `product_models` | `vendor_id` | `product_vendors.id` | — |

{: .note }
Les FK vers `os_versions` (OS, firmware, BIOS) utilisent `ON DELETE SET NULL` — supprimer une entrée du référentiel OS ne supprime pas les assets qui l'utilisaient, mais les déréférence.

---

## Contrainte d'unicité notable

La table `correlations` a une contrainte `UNIQUE KEY unique_asset_cve (asset_id, cve_id)` — une même CVE ne peut être corrélée qu'une seule fois par asset. Le moteur de corrélation est idempotent grâce à cette contrainte.
