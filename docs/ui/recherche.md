---
title: Recherche globale
parent: Interface utilisateur
nav_order: 6
---

# 🔎 Recherche globale

**Rechercher rapidement un client, site ou asset** depuis n'importe quelle page.

**URL** : `/ui/recherche` (ou barre de recherche en haut à droite)

---

## 🎯 **Fonctionnement**

- **Barre de recherche** en haut à droite de toutes les pages
- **Page dédiée** accessible via `/ui/recherche`
- **Recherche en temps réel** (debounce 300ms)

---

## 📝 **Champ de recherche**

- **Texte libre** : Saisir un nom, une IP, un numéro de série, etc.
- **Recherche multi-champs** : Cherche dans :
  - Noms des clients
  - Noms des sites
  - Noms des assets
  - Adresses IP
  - Adresses MAC
  - Numéros de série
  - Hostnames

---

## 📊 **Résultats**

### Format

| Type | Nom | Détails | Actions |
|------|-----|---------|--------|
| 🏢 Client | Nom du client | Nombre de sites/assets | Voir |
| 📍 Site | Nom du site | Client parent | Voir |
| 💻 Asset | Nom de l'asset | Client/Site/Type | Voir |

### Tri

- **Par défaut** : Pertinence DESC
- **Cliquer sur l'en-tête** pour changer le tri

---

## 🎯 **Actions sur les résultats**

| Bouton | Action |
|--------|--------|
| 👁️ **Voir** | Ouvrir la fiche détaillée |
| 🔗 **Lien direct** | Aller directement à la page correspondante |

---

## 💡 **Astuces**

- ✅ **Saisir au moins 3 caractères** pour déclencher la recherche
- ✅ **Utiliser des termes précis** (nom exact, IP complète)
- ✅ **Rechercher par numéro de série** pour trouver un asset spécifique
- ❌ **Éviter les termes trop génériques** (ex: "serveur", "nas")
