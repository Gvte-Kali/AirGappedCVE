---
title: Scripts
nav_order: 5
has_children: true
---
## 📋 **Scripts d'exécution**
Cette page reprend tous les scripts utilisés : 
1. Les scripts de Synchronisation NVD et d'insertion en BDD
2. Le script de corrélation assets <--> cve
3. Le script de backup de la BDD


## 📋 Documentation

- [ Synchronisation NVD ]({{ site.baseurl }}/scripts/nvd_sync) — Toute la logique de synchronisation NVD
    1. [ Download NVD ]({{ site.baseurl }}/scripts/download_nvd) — Téléchargement NVD
    2. [ Import Vendors/Models ]({{ site.baseurl }}/scripts/import_vendors_models) — Import en BDD des Fabricants/Modèles
    3. [ CVE Sync ]({{ site.baseurl }}/scripts/cve_sync) — Import en BDD des CVE
    4. [ Extraction OS/Versions ]({{ site.baseurl }}/scripts/cve_sync) — Import en BDD des OS et Versions
- [ Corrélation ]({{ site.baseurl }}/scripts/correlate_and_analyze) — Toute la logique de corrélation
- [ Backup ]({{ site.baseurl }}/scripts/backup) — Toute la logique de backup^

---

