---
title: Recherche globale
parent: Interface utilisateur
nav_order: 6
---

# Recherche globale
{: .no_toc }

---

## Présentation

La barre de recherche en haut à droite de la navbar permet de retrouver rapidement un **client**, un **site** ou un **asset** depuis n'importe quelle page.

## Comportement

- La recherche s'active à partir de **2 caractères** saisis
- Les résultats sont affichés dans un menu déroulant sous le champ
- Les résultats sont groupés par type (Clients, Sites, Assets)
- Un clic sur un résultat navigue vers la page correspondante

## Implémentation

La recherche globale est implémentée dans `ui/static/app-search.js` et consomme les endpoints API avec le paramètre `search`.

## Pages concernées

La barre de recherche est présente sur toutes les pages de l'interface — elle est incluse dans la navbar commune.
