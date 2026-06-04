---
title: Page Types d'équipements
parent: Interface utilisateur
nav_order: 10
---

# ⚙️ Page Types d'équipements

**Configuration du moteur de corrélation par type**

**URL** : `/ui/equipment-types` (menu **Référentiels → ⚙️ Types d'équipements**)

---

## 📋 **Tableau des types**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **Nom** | Nom du type |
| **Description** | Description |
| **Vendor Source** | Source du vendor NVD |
| **Assets** | Nombre d'assets de ce type |
| **Actions** | Voir/Modifier/Supprimer |

---

## ✏️ **Modal de création / édition**

### Champs principaux

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| **Nom** | Texte | ✅ | Nom du type (ex: Serveur, NAS, Caméra IP) |
| **Description** | Texte long | ❌ | Description |

### Configuration corrélation

| Champ | Type | Obligatoire | Description | Valeurs |
|-------|------|-------------|-------------|---------|
| **vendor_source** | Select | ✅ | Source du vendor NVD | os_fk/fw_fk/materiel/detection_auto |
| **use_os_version** | Booléen | ❌ | Utiliser OS normalisé | 0/1 |
| **use_version_os** | Booléen | ❌ | Utiliser version OS texte libre | 0/1 |
| **use_version_firmware** | Booléen | ❌ | Utiliser firmware | 0/1 |
| **use_version_bios** | Booléen | ❌ | Utiliser BIOS | 0/1 |

### Options avancées

| Champ | Type | Obligatoire | Description | Défaut |
|-------|------|-------------|-------------|--------|
| **correlation_enabled** | Booléen | ❌ | Activer la corrélation | 1 |
| **auto_correlate** | Booléen | ❌ | Lancer automatiquement | 1 |
| **default_criticite** | Select | ❌ | Criticité par défaut | moyen |
| **default_statut** | Select | ❌ | Statut par défaut | actif |

---

## 🎯 **Actions**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir en lecture seule |
| ✏️ **Modifier** | Ouvrir en édition |
| 🗑️ **Supprimer** | Supprimer le type (avec confirmation) |
| ➕ **Nouveau type** | Créer un nouveau type |
| 📤 **Exporter** | Exporter en CSV |

---

## ⚠️ **Attention**

- **Impact sur la corrélation** : Modifier un type peut affecter les assets existants
- **Vendor source** : Détermine comment le vendor NVD est déterminé
- **Champs de version** : Déterminent quels champs sont utilisés pour la comparaison

---

## 💡 **Astuces**

- ✅ **Tester avec un asset** avant de déployer un nouveau type
- ✅ **Utiliser des noms clairs** (ex: "Serveur Windows", "NAS Synology")
- ✅ **Configurer correctement vendor_source** pour chaque type
- ❌ **Ne pas modifier un type** déjà utilisé par des assets (créer un nouveau type)
- ❌ **Ne pas supprimer un type** sans vérifier les dépendances

---

## 📖 **Exemples de configuration**

| Type | vendor_source | use_os_version | use_version_os | use_version_firmware |
|------|---------------|----------------|----------------|---------------------|
| Serveur Windows | os_fk | 1 | 0 | 0 |
| Serveur Linux | os_fk | 1 | 1 | 0 |
| NAS Synology | materiel | 1 | 1 | 0 |
| Switch Cisco | fw_fk | 0 | 0 | 1 |
| Caméra IP | materiel | 0 | 0 | 1 |
