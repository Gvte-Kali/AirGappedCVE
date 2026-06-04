---
title: Page Vulnérabilités
parent: Interface utilisateur
nav_order: 1
---

# 🔍 Page Vulnérabilités

**Page centrale du système** - Liste toutes les corrélations CVE détectées.

**URL** : `/ui/vulns` (lien **Vulnérabilités** dans la navbar)

---

## 📊 **Cartes de statistiques**

4 cartes en haut de page :

| Carte | Description |
|-------|-------------|
| 📈 **Total Détectées** | Nombre total de corrélations en base |
| 🔴 **Critiques** | Corrélations avec `priorite = critique` |
| 🟠 **Impact Haut** | Corrélations avec `priorite = haute` |
| 📚 **Référentiel** | Toujours `CVE` |

---

## ⚡ **Boutons de pipeline**

3 boutons en haut à droite :

| Bouton | Action | Commande |
|--------|--------|----------|
| 🔄 **Corrélation** | Phase 1+2 uniquement | `correlate` |
| 🤖 **Analyse Mistral** | Phase 3 uniquement | `analyze` |
| ⚡ **Tout exécuter** | Pipeline complet | `run-all` |

⚠️ **Confirmation demandée** avant chaque lancement. Barre de progression avec logs en temps réel.

---

## 🔍 **Panneau de filtres**

**Repliable** - Cliquer sur `🔍 CRITÈRES DE RECHERCHE` pour ouvrir/fermer.

### Filtres disponibles

| Filtre | Type | Description |
|--------|------|-------------|
| **Client** | Typeahead | Recherche dynamique |
| **Site** | Typeahead | Indépendant du client |
| **Type d'équipement** | Typeahead | NAS, serveur, PC… |
| **Fabricant** | Typeahead | Fabricant NVD |
| **Modèle** | Typeahead | Affiné si fabricant sélectionné |
| **Système d'exploitation** | Typeahead | Nom OS |
| **Version OS** | Typeahead + texte | Version |
| **Firmware** | Typeahead | Version firmware |
| **Nom d'asset** | Texte libre | Nom d'inventaire |
| **Identifiant CVE** | Texte libre | Ex: `CVE-2024-` |
| **Statut** | Multi-select | nouveau/en_analyse/confirme/mitige/faux_positif/patche |
| **Priorité** | Multi-select | critique/haute/moyenne/basse |

**Défauts** :
- Statuts : `nouveau`, `en_analyse`, `confirme`
- Priorités : toutes

---

## 📋 **Tableau des vulnérabilités**

### Colonnes

| Colonne | Description |
|---------|-------------|
| **CVE** | Identifiant CVE (cliquable pour détail) |
| **Score** | Score final (après ajustement Mistral) |
| **Priorité** | critique/élevée/moyenne/basse |
| **Asset** | Nom de l'asset |
| **Client** | Nom du client |
| **Site** | Nom du site |
| **OS** | Système d'exploitation |
| **Version** | Version OS |
| **Fabricant** | Fabricant NVD |
| **Type** | Type de corrélation (Affirmé/Informatif) |
| **Statut** | Statut actuel |
| **Verdict** | Verdict Mistral |
| **Date** | Date de détection |

### Tri

Cliquer sur l'en-tête d'une colonne pour trier (ascendant/descendant).

**Tri par défaut** : Score DESC, Date DESC

---

## 🎯 **Actions rapides**

| Bouton | Action |
|--------|--------|
| 🔍 | Ouvrir le détail de la corrélation |
| ❌ | Marquer comme faux positif |
| ✅ | Marquer comme confirmé |
| 📝 | Ouvrir les notes |
| 📥 | Exporter en CSV |

---

## 📤 **Export**

- **CSV** : Bouton en haut à droite
- **PDF** : Via le menu Actions → Générer rapport PDF
- **JSON** : Via l'API `/api/correlations/export`

---

## 💡 **Astuces**

- ✅ Utiliser les filtres pour cibler les corrélations à traiter
- ✅ Trier par **Score DESC** pour voir les plus critiques en premier
- ✅ Utiliser la **recherche globale** pour trouver rapidement une CVE ou un asset
- ✅ **Rafraîchir** le tableau après une corrélation pour voir les nouvelles détections
- ❌ Ne pas laisser trop de corrélations en statut `nouveau` (lancer Mistral régulièrement)
