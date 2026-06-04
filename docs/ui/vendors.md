---
title: Page Fabricants
parent: Interface utilisateur
nav_order: 7
---

# 🏭 Page Fabricants

**Référentiel des fabricants NVD**

**URL** : `/ui/vendors` (menu **Référentiels → 🏭 Fabricants**)

---

## 📋 **Tableau des fabricants**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom affiché |
| **nvd_vendor** | Identifiant NVD |
| **Modèles** | Nombre de modèles |
| **OS** | Nombre de versions OS |
| **Assets** | Nombre d'assets utilisant ce fabricant |
| **CVE** | Nombre de CVE disponibles |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Nom** | Texte | ✅ | Nom affiché (ex: Synology) |
| **nvd_vendor** | Texte | ✅ | Identifiant NVD exact (ex: synology) |
| **Description** | Texte long | ❌ | Description |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer le fabricant (avec confirmation) |
| ➕ **Nouveau fabricant** | Créer un nouveau fabricant |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Clé primaire de corrélation** : Le `nvd_vendor` doit être **exact**
- **Vérifier sur NVD** : [nvd.nist.gov](https://nvd.nist.gov) avant de créer
- **Format** : Tout en minuscules, pas d'espaces
- **Exemples** : `microsoft`, `synology`, `fortinet`, `zkteco`

---

## 💡 **Astuces**

- ✅ **Vérifier l'orthographe** du `nvd_vendor`
- ✅ **Tester avec une CVE connue** après création
- ✅ **Utiliser des noms courts et clairs**
- ❌ **Ne pas inventer de nvd_vendor**
- ❌ **Ne pas supprimer un fabricant** s'il est utilisé par des assets

---

## 🔍 **Vérification**

Après création, vérifier que des CVE existent :

```sql
SELECT COUNT(*) as nb_cve
FROM cve
WHERE fabricant = 'votre_nvd_vendor';
```

Si `nb_cve = 0` : Synchroniser le référentiel NVD.
