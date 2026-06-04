---
title: Page Sites
parent: Interface utilisateur
nav_order: 4
---

# 📍 Page Sites

**Gestion des localisations physiques**

**URL** : `/ui/sites` (menu **Référentiels → 📍 Sites**)

---

## 📋 **Tableau des sites**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom du site |
| **Client** | Client propriétaire |
| **Ville** | Ville |
| **Code postal** | Code postal |
| **Pays** | Pays |
| **Assets** | Nombre d'assets |
| **Vulnérabilités** | Nombre de corrélations |
| **Actif** | Statut (✅/❌) |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Client** | Typeahead | ✅ | Client propriétaire |
| **Nom** | Texte | ✅ | Nom du site |
| **Adresse** | Texte | ❌ | Adresse postale |
| **Ville** | Texte | ❌ | Ville |
| **Code postal** | Texte | ❌ | Code postal |
| **Pays** | Texte | ❌ | Pays (défaut: France) |
| **Contact local nom** | Texte | ❌ | Contact sur site |
| **Contact local email** | Email | ❌ | Email contact local |
| **Contact local téléphone** | Téléphone | ❌ | Téléphone contact local |
| **Notes** | Texte long | ❌ | Notes libres |
| **Actif** | Booléen | ✅ | 1 = actif, 0 = archivé |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer le site (avec confirmation) |
| ➕ **Nouveau site** | Créer un nouveau site |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Suppression en cascade** : Supprimer un site supprime **tous ses assets et corrélations**
- **Archivage recommandé** : Utiliser le statut `Actif = ❌` plutôt que de supprimer
- **Vérifier les dépendances** avant de supprimer

---

## 💡 **Astuces**

- ✅ **Utiliser des noms descriptifs** (ex: "Siège Paris", "MA-Metz")
- ✅ **Renseigner les contacts locaux** pour les interventions sur site
- ✅ **Archiver plutôt que supprimer** pour conserver l'historique
- ❌ **Ne pas supprimer un site** s'il a des assets actifs
