---
title: Fichiers de log
nav_order: 2
parent : Maintenance
---

# Fichiers de logs des fonctions principales

Les scripts qui font tourner toute la stack écrivent des fichiers de log pour la plupart.
Les scripts les plus importants ont une page dédiée.

Voici un tableau des fichiers se trouvant dans le dossier /opt/asset-manager/logs : 

| Fichier | Script correspondant | Fonction du script | Documentation si existante | 
| ------- | -------------------- | ------------------ | -------------------------- |
| backup.log | /opt/asset-manager/scripts/backup.sh | Fonction de backup de la base de données | Aucune |
| cve_sync.log | /opt/asset-manager/scripts/cve_sync.py | Fonction d'importation des CVE dans la base de données | [ Lien ]({{ site.baseurl }}/scripts/cve_sync) |
| download_nvd.log | /opt/asset-manager/scripts/download_nvd.py | Fonction de téléchargement des CVE via la base NVD | [ Lien ]({{ site.baseurl }}/scripts/download_nvd) |
| extract_os_versions.log | /opt/asset-manager/scripts/extract_os_versions.py | Fonction d'importation des OS/Versions dans la base de données | [ Lien ]({{ site.baseurl }}/scripts/extract_os_versions) |
| FastAPI.log | Plusieurs : asset-manager.sh et service systemd | Logs du service FastAPI ( uvicorn ) | Aucune |
| FastAPI.pid | Plusieurs : asset-manager.sh et service systemd | Numéro du processus système ( peut servir pour plusieurs utilisations ) | Aucune |
| grafana.log.log | Fonctionnalité à venir | - | - |
| import_vendors_models.log | /opt/asset-manager/scripts/import_vendors_models.py | Fonction d'importation des Fabricant/Modèles dans la base de données | [ Lien ]({{ site.baseurl }}/scripts/import_vendors_models) |
| scheduled_tasks.log | /opt/asset-manager/scripts/run_scheduled_tasks.sh | Cronjob | [ Lien ]({{ site.baseurl }}/scripts/run_scheduled_tasks) |

---