---
title: Page Clients
parent: Interface utilisateur
nav_order: 3
---

# 🏢 Page Clients

**Gestion des organisations clients**

**URL** : `/ui/clients` (menu **Référentiels → 🏢 Clients**)

---

## 📋 **Tableau des clients**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom de l'organisation |
| **Contact** | Contact principal |
| **Email** | Email du contact |
| **Téléphone** | Téléphone du contact |
| **Sites** | Nombre de sites |
| **Assets** | Nombre d'assets |
| **Vulnérabilités** | Nombre de corrélations |
| **Actif** | Statut (✅/❌) |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Nom** | Texte | ✅ | Nom de l'organisation |
| **Contact nom** | Texte | ❌ | Nom du contact principal |
| **Contact email** | Email | ❌ | Email du contact |
| **Contact téléphone** | Téléphone | ❌ | Téléphone du contact |
| **Adresse** | Texte | ❌ | Adresse postale |
| **Notes** | Texte long | ❌ | Notes libres |
| **Actif** | Booléen | ✅ | 1 = actif, 0 = archivé |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer le client (avec confirmation) |
| ➕ **Nouveau client** | Créer un nouveau client |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Suppression en cascade** : Supprimer un client supprime **tous ses sites, assets et corrélations**
- **Archivage recommandé** : Utiliser le statut `Actif = ❌` plutôt que de supprimer
- **Vérifier les dépendances** avant de supprimer

---

## 💡 **Astuces**

- ✅ **Utiliser des noms uniques** pour éviter les confusions
- ✅ **Renseigner les contacts** pour faciliter la communication
- ✅ **Archiver plutôt que supprimer** pour conserver l'historique
- ❌ **Ne pas supprimer un client** s'il a des assets actifs
