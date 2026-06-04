---
title: Interface utilisateur
nav_order: 7
has_children: true
---

# 🖥️ Interface utilisateur

**Application HTML/JS/Bootstrap 5 servie par FastAPI** - Pas de framework frontend nécessaire.

---

## 🧭 **Navigation**

**Navbar présente sur toutes les pages** :
- 🏠 Accueil
- 🔍 Vulnérabilités (page principale)
- **Référentiels** (menu déroulant) : Clients, Sites, Assets, Fabricants, Modèles, OS, Types...
- 📚 API Swagger (`/docs`)
- 🎯 Console scripts

---

## 🔍 **Barre de recherche globale**

En haut à droite → Rechercher rapidement un **client**, **site** ou **asset** depuis n'importe quelle page.

---

## ❓ **Aide contextuelle**

Chaque page a un bouton **?** à côté du titre → Ouvre un panneau d'aide expliquant le rôle de la page et de chaque champ.

---

## 📄 **Pages principales**

| Page | Description | URL |
|------|-------------|-----|
| [🔍 Vulnérabilités]({{ site.baseurl }}/ui/vulns) | Tableau principal, filtres, actions rapides | `/ui/vulns` |
| [💻 Assets]({{ site.baseurl }}/ui/assets) | Inventaire, création, édition | `/ui/assets` |
| [🏢 Clients]({{ site.baseurl }}/ui/clients) | Gestion des clients | `/ui/clients` |
| [📍 Sites]({{ site.baseurl }}/ui/sites) | Gestion des sites | `/ui/sites` |
| [🏭 Fabricants]({{ site.baseurl }}/ui/vendors) | Référentiel fabricants NVD | `/ui/vendors` |
| [🏷️ Modèles]({{ site.baseurl }}/ui/models) | Référentiel modèles | `/ui/models` |
| [📊 OS & Versions]({{ site.baseurl }}/ui/os-versions) | Référentiel normalisé NVD | `/ui/os-versions` |
| [⚙️ Types d'équipements]({{ site.baseurl }}/ui/equipment-types) | Configuration moteur corrélation | `/ui/equipment-types` |
| [🎯 Console]({{ site.baseurl }}/ui/console) | Lancement manuel du pipeline | `/ui/console` |
| [🔎 Recherche]({{ site.baseurl }}/ui/recherche) | Recherche cross-pages | `/ui/recherche` |
