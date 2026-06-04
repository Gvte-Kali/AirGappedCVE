---
title: Page Assets
parent: Interface utilisateur
nav_order: 2
---

# 💻 Page Assets

**Inventaire des équipements** - Gestion complète des assets.

**URL** : `/ui/assets` (menu **Référentiels → 💻 Assets**)

---

## 🔍 **Filtres**

3 filtres en haut de la liste :

| Filtre | Type | Description |
|--------|------|-------------|
| **Client** | Typeahead | Active le filtre Site |
| **Site** | Typeahead | Dépend du client sélectionné |
| **Type** | Select | Filtre par type d'équipement |

**Actions** : 🔍 Appliquer, ✖ Réinitialiser

---

## 📋 **Tableau des assets**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom interne de l'asset |
| **Client** | Client propriétaire |
| **Site** | Site de localisation |
| **Type** | Type d'équipement |
| **Fabricant** | Fabricant NVD |
| **Modèle** | Modèle |
| **IP** | Adresse IP |
| **OS** | Système d'exploitation |
| **Criticité** | Niveau de criticité |
| **Statut** | Statut opérationnel |
| **Actions** | Voir/Modifier/Supprimer |

**Note** : La colonne OS affiche :
- Si `os_version_id` renseigné : `os_version_nom + os_version_ver` (FK)
- Sinon : `systeme_exploitation + version_os` (texte libre)

---

## ✏️ **Modal de création / édition**

### Sections du formulaire

**📍 Localisation**
- Client (typeahead) → débloque Site
- Site (typeahead, dépend du client)

**🏷️ Identification**
- Nom interne (obligatoire)
- Type d'équipement (select dynamique depuis `/api/equipment-types`)

**🏭 Fabricant & Modèle**
- Fabricant (typeahead) → débloque Modèle
- Modèle (typeahead, dépend du fabricant — création inline possible)

**🌐 Réseau**
- Numéro de série
- Adresse IP
- Adresse MAC
- Hostname

**💻 OS & Versions**
- Système d'exploitation (typeahead niveau 1 — noms OS distincts)
- Version OS (typeahead niveau 2 — versions filtrées par nom OS)
- Version exacte (champ libre — apparaît si aucune version normalisée)
- Firmware (typeahead — type_produit = firmware)
- BIOS/UEFI (typeahead — type_produit = bios)

**📅 Dates**
- Date d'installation
- Date de fin de garantie

**⚙️ Métadonnées**
- Niveau de criticité : faible/moyen/élevé/critique
- Statut opérationnel : actif/inactif/maintenance/hors_service
- Notes

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer l'asset (avec confirmation) |
| ➕ **Nouvel asset** | Créer un nouvel asset |
| 📥 **Importer** | Importer depuis Excel |
| 📤 **Exporter** | Exporter en CSV |

---

## 💡 **Astuces**

- ✅ **Utiliser les typeaheads** pour une saisie rapide et sans erreur
- ✅ **Créer les fabricants/modèles/OS** avant de créer les assets
- ✅ **Saisir les versions complètes** (inclure les numéros de build)
- ❌ **Ne pas supprimer un asset** s'il a des corrélations (utiliser le statut `hors_service`)
- ❌ **Ne pas modifier le type d'équipement** après corrélation (recalculer la corrélation)
