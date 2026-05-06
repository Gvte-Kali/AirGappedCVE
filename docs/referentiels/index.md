---
title: Référentiels métier
nav_order: 4
has_children: true
---

# Référentiels métier

Les référentiels métier sont les données de base du système. Ils doivent être renseignés avant de pouvoir utiliser le moteur de corrélation CVE.

## Ordre de saisie recommandé

L'ordre de saisie suit les dépendances entre tables :

```
1. Fabricants (product_vendors)
        │
        ▼
2. Modèles (product_models)
        │
        ▼
3. OS & Versions (os_versions)
        │
        ▼
4. Types d'équipements (equipment_types)
        │
        ▼
5. Clients
        │
        ▼
6. Sites
        │
        ▼
7. Assets
```

## Pages

- [Clients & Sites]({{ site.baseurl }}/referentiels/clients-sites) — hiérarchie, contacts, cascade
- [Assets]({{ site.baseurl }}/referentiels/assets) — champs, versions OS, criticité, corrélation
- [Fabricants]({{ site.baseurl }}/referentiels/fabricants) — nomenclature NVD, identifier le bon vendor
- [Modèles]({{ site.baseurl }}/referentiels/modeles) — nvd_product, cpe_part, types produit
- [OS & Versions]({{ site.baseurl }}/referentiels/os-versions) — référentiel normalisé, formats
- [Types d'équipements]({{ site.baseurl }}/referentiels/equipment-types) — configuration du moteur de corrélation
