---
title: Base de données
nav_order: 3
has_children: true
---

# 🗃️ Base de données

**MariaDB** - Cœur du système : assets, CVE, corrélations et référentiels.

---

## 📊 **Structure globale**

```
asset_vuln_manager
├── Référentiels métier
│   ├── clients, sites
│   ├── assets (équipements)
│   ├── product_vendors, product_models
│   ├── os_versions, equipment_types
│   └── asset_software
│
├── Référentiels NVD
│   ├── cve, cwe, cve_cwe
│   └── ...
│
├── Moteur de corrélation
│   ├── correlations
│   ├── correlation_rejects
│   └── historique_analyses
│
└── Vues
    ├── v_assets, v_clients, v_sites
    ├── v_fabricants, v_modeles
    └── v_vulnerabilites_tableau
```

---

## 📖 **Documentation**

- [🔗 Schéma & Relations]({{ site.baseurl }}/database/schema) — Diagramme des tables
- [📋 Tables]({{ site.baseurl }}/database/tables) — Description des colonnes
- [👁️ Vues]({{ site.baseurl }}/database/vues) — Vues SQL utiles
