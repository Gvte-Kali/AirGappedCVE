---
title: Page OS & Versions
parent: Interface utilisateur
nav_order: 9
---

# 📊 Page OS & Versions

**Référentiel des versions OS/Firmware/BIOS normalisées NVD**

**URL** : `/ui/os-versions` (menu **Référentiels → 📊 OS & Versions**)

---

## 📋 **Tableau des versions**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom affiché |
| **Fabricant** | Fabricant |
| **nvd_vendor** | Vendor NVD |
| **nvd_product** | Produit NVD |
| **Version** | Version exacte |
| **Type OS** | os/firmware/bios |
| **Assets** | Nombre d'assets utilisant cette version |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Fabricant** | Typeahead | ✅ | Fabricant |
| **Nom** | Texte | ✅ | Nom affiché (ex: DSM 7.2.2) |
| **nvd_vendor** | Texte | ✅ | Vendor NVD (ex: synology) |
| **nvd_product** | Texte | ✅ | Produit NVD (ex: diskstation_manager) |
| **Version** | Texte | ✅ | Version exacte (ex: 7.2.2-72806) |
| **Type OS** | Select | ✅ | os/firmware/bios |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer la version (avec confirmation) |
| ➕ **Nouvelle version** | Créer une nouvelle version |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Clé de corrélation** : Le triplet (nvd_vendor, nvd_product, version) doit être exact
- **Type OS** : Détermine comment la version est utilisée (OS, firmware, BIOS)
- **SET NULL** : Supprimer une version ne supprime pas les assets qui l'utilisent (déréférencement)

---

## 💡 **Astuces**

- ✅ **Utiliser les versions complètes** (inclure les numéros de build)
- ✅ **Vérifier sur NVD** avant de créer
- ✅ **Respecter le format du fabricant**
- ❌ **Ne pas modifier une version** déjà utilisée par des assets
- ❌ **Ne pas supprimer une version** sans vérifier les dépendances

---

## 🔍 **Vérification**

Vérifier que la version est utilisée :

```sql
SELECT COUNT(*) as nb_assets
FROM assets
WHERE os_version_id = X OR fw_version_id = X OR bios_version_id = X;
```

Vérifier les CVE disponibles :

```sql
SELECT COUNT(*) as nb_cve
FROM cve
WHERE fabricant = 'nvd_vendor' AND produit = 'nvd_product';
```
