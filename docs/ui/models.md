---
title: Page Modèles
parent: Interface utilisateur
nav_order: 8
---

# 🏷️ Page Modèles

**Référentiel des modèles de produits NVD**

**URL** : `/ui/models` (menu **Référentiels → 🏷️ Modèles**)

---

## 📋 **Tableau des modèles**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom affiché |
| **Fabricant** | Fabricant parent |
| **nvd_product** | Produit NVD |
| **cpe_part** | Partie CPE |
| **Type de produit** | Type |
| **Assets** | Nombre d'assets utilisant ce modèle |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Fabricant** | Typeahead | ✅ | Fabricant parent |
| **Nom** | Texte | ✅ | Nom affiché (ex: DS220+) |
| **nvd_product** | Texte | ✅ | Produit NVD (ex: diskstation_manager) |
| **cpe_part** | Select | ❌ | Partie CPE (o=OS, a=application, h=hardware) |
| **Type de produit** | Texte | ❌ | Type de produit |
| **CPE base** | Texte | ❌ | CPE base complet |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer le modèle (avec confirmation) |
| ➕ **Nouveau modèle** | Créer un nouveau modèle |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Lié au fabricant** : Un modèle doit avoir un fabricant parent
- **nvd_product** : Doit correspondre au format NVD
- **cpe_part** : o (OS), a (application), h (hardware)

---

## 💡 **Astuces**

- ✅ **Vérifier sur NVD** avant de créer
- ✅ **Utiliser des noms descriptifs**
- ✅ **Renseigner le cpe_part** pour une meilleure corrélation
- ❌ **Ne pas supprimer un modèle** s'il est utilisé par des assets

---

## 🔍 **Vérification**

Vérifier que le modèle est utilisé :

```sql
SELECT COUNT(*) as nb_assets
FROM assets
WHERE model_id = X;
```
