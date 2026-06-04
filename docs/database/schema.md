---
title: Schéma & Relations
parent: Base de données
nav_order: 1
---

# 🔗 Schéma & Relations

**Diagramme simplifié des dépendances entre tables**

---

## 📊 **Diagramme**

```
clients
  └── sites (1:N)
        └── assets (1:N)
              ├── asset_software (1:N)
              └── correlations (1:N)
                    └── cve (N:1)
                    └── cwe (via cve_cwe)

product_vendors
  └── product_models (1:N)
        └── assets (via vendor_id, model_id)

os_versions
  └── assets (via os_version_id, fw_version_id, bios_version_id)

equipment_types
  └── assets (via equipment_type_id)
```

---

## 🔄 **Hiérarchie & Cascades**

```
clients → sites → assets → correlations
                  assets → asset_software
```

**Suppression en cascade** :
- ❌ Client → supprime ses sites, assets et corrélations
- ❌ Site → supprime ses assets et corrélations
- ❌ Asset → supprime ses corrélations et logiciels

**SET NULL** (pas de cascade) :
- Vendor/Model/OS → déréférencé mais asset conservé

---

## 🔑 **Clés étrangères principales**

| Table | FK | Référence | On Delete |
|-------|----|-----------|-----------|
| sites | client_id | clients.id | CASCADE |
| assets | site_id | sites.id | CASCADE |
| assets | vendor_id | product_vendors.id | SET NULL |
| assets | model_id | product_models.id | SET NULL |
| assets | os_version_id | os_versions.id | SET NULL |
| correlations | asset_id | assets.id | CASCADE |
| correlations | cve_id | cve.cve_id | CASCADE |

---

## 🎯 **Contrainte importante**

`correlations` a une **clé unique** sur `(asset_id, cve_id)` → Une CVE ne peut être corrélée qu'une fois par asset. Le moteur est **idempotent**.
