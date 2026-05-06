---
title: Interface utilisateur
nav_order: 7
has_children: true
---

# Interface utilisateur

L'interface web est une application HTML/JS/Bootstrap 5 servie directement par FastAPI. Elle ne nécessite aucun framework frontend — tout est en vanilla JS avec des appels API REST.

## Navigation

La navbar est présente sur toutes les pages avec :
- Un lien vers l'accueil
- Un lien vers la page Vulnérabilités
- Un menu déroulant **Référentiels** regroupant toutes les pages de gestion
- Un lien vers la documentation API Swagger (`/docs`)
- Un lien vers la Console scripts

## Barre de recherche globale

La barre de recherche en haut à droite permet de retrouver rapidement un client, un site ou un asset depuis n'importe quelle page.

## Boutons d'aide contextuelle

Chaque page dispose d'un bouton **?** à côté du titre principal. Il ouvre un panneau d'aide contextuel qui explique le rôle de la page et de chaque champ. Le panneau reste ouvert tant qu'on ne clique pas en dehors (`data-bs-auto-close="outside"`).

## Pages

- [Vulnérabilités]({{ site.baseurl }}/ui/vulns) — tableau principal, filtres, actions rapides
- [Assets]({{ site.baseurl }}/ui/assets) — inventaire, création, édition, version OS
- [Types d'équipements]({{ site.baseurl }}/ui/equipment-types) — configuration moteur corrélation
- [OS & Versions]({{ site.baseurl }}/ui/os-versions) — référentiel normalisé NVD
- [Console Scripts]({{ site.baseurl }}/ui/console) — lancement manuel du pipeline
- [Recherche globale]({{ site.baseurl }}/ui/recherche) — barre de recherche cross-pages
