---
title: Première Utilisation
nav_order: 3
parent: Installation & Configuration
---

# 1️⃣ Première Utilisation

## ⚠️ Avant de commencer quoi que ce soit, il faut que les clés API dans le fichier .env soient fonctionnelles

## 📌 Etape 1 : Lancement des scripts de setup

En une seule commande : 
```bash
bash /opt/asset-manager/scripts/run_all.sh
```

Pour résumer, ce script exécute dans l'ordre : 

1. Téléchargement de la base NVD
    `/opt/asset-manager/scripts/download_nvd.py`
2. Importer les fabriquants NVD et les modèles : 
    `/opt/asset-manager/scripts/import_vendors_models.py`
3. Parser et Importer les CVE correspondant aux frabricant/modèles 
    `/opt/asset-manager/scripts/cve_sync.py`
4. Importer les OS et les versions d'OS
    `/opt/asset-manager/scripts/extract_os_versions.py`

---

## 📌 Etape 2 : Lancement de la première corrélation ( uniquement si vous avez des assets )

Le script de corrélation se trouve à cet emplacement `/opt/asset-manager/scripts/correlate_and_analyze.py`.
Il peut se lancer de manière simple avec l'outil **asset-manager** : 
`asset-manager corr launch`

---

## 📌 Etape 3 : Création du Cron job 
Il faut ajouter un cron job du script `/opt/asset-manager/scripts/run_scheduled_tasks.sh` quotidien.
Cela va lancer les scripts de téléchargement tous les jours et lancer la corr"lation automatique.
Pour ajouter le cronjob `sudo crotab -e`et ajouter cette ligne :  
```bash 
0 2 * * * /bin/bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
```
Ce cronjob s'exécute tous les jours à 2H00 du matin ( heure du serveur ). 
Si l'heure ne vous convient pas, vous pouvez toujours la changer avant de sauvegarder.

---

