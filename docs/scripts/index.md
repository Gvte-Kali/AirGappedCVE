---
title: Scripts
nav_order: 4
has_children: true
---
# 📋 **Scripts d'exécution**
Cette page reprend tous les scripts utilisés :

1. Les scripts de Synchronisation NVD et d'insertion en BDD : 
**[ Synchronisation NVD ]({{ site.baseurl }}/scripts/nvd_sync) — Toute la logique de synchronisation NVD**
- [ Download NVD ]({{ site.baseurl }}/scripts/download_nvd) — Téléchargement NVD
- [ Import Vendors/Models ]({{ site.baseurl }}/scripts/import_vendors_models) — Import en BDD des Fabricants/Modèles
- [ CVE Sync ]({{ site.baseurl }}/scripts/cve_sync) — Import en BDD des CVE
- [ Extraction OS/Versions ]({{ site.baseurl }}/scripts/cve_sync) — Import en BDD des OS et Versions

2. Le script de corrélation assets <--> cve
**[ Corrélation ]({{ site.baseurl }}/scripts/correlate_and_analyze) — Toute la logique de corrélation**

3. Le script de backup de la BDD
**[ Backup ]({{ site.baseurl }}/scripts/backup) — Toute la logique de backup**

4. Le script d'automatisation Cron
**[ Run Scheduled Tasks ]({{ site.baseurl }}/scripts/run_scheduled_tasks) — Le script de cronjob quotidien**