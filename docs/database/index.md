---
title: Base de données
nav_order: 3
has_children: true
---

# Base de données

La base de données **MariaDB** est le cœur du système. Elle centralise les assets, les CVE, les corrélations et tous les référentiels métier.

## Vue d'ensemble

```
asset_vuln_manager
│
├── Référentiels métier
│   ├── clients
│   ├── sites
│   ├── assets
│   ├── asset_software
│   ├── product_vendors
│   ├── product_models
│   ├── os_versions
│   └── equipment_types
│
├── Référentiels CVE/CWE (NVD)
│   ├── cve
│   ├── cwe
│   └── cve_cwe
│
├── Moteur de corrélation
│   ├── correlations
│   ├── correlation_rejects
│   └── historique_analyses
│
├── Divers
│   └── utilisateurs
│
└── Vues
    ├── v_assets
    ├── v_clients
    ├── v_sites
    ├── v_fabricants
    ├── v_modeles
    └── v_vulnerabilites_tableau
```

## Pages

- [Schéma & Relations]({{ site.baseurl }}/database/schema) — diagramme des dépendances entre tables
- [Tables]({{ site.baseurl }}/database/tables) — description détaillée de chaque table et colonne
- [Vues]({{ site.baseurl }}/database/vues) — vues SQL et leur usage
