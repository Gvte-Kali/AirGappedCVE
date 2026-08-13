---
title: Première Utilisation
nav_order: 3
parent: Installation & Configuration
---

# 1️⃣ Première Utilisation

## ⚠️ Avant de commencer quoi que ce soit, il faut que les clés API dans le fichier .env soient fonctionnelles

## 📌 Etape 1 : Lancement des scripts de synchronisation de la base NVD et import en BDD

Aller dans le répertoire du projet

```bash
cd /opt/asset-manager
```

Lancer ces scripts dans l'ordre : 

```bash
source /opt/asset-manager/venv/bin/activate && python3 /opt/asset-manager/scripts/download_nvd.py
```
```bash
source /opt/asset-manager/venv/bin/activate && python3 /opt/asset-manager/scripts/import_vendors_models.py
```
```bash
source /opt/asset-manager/venv/bin/activate && python3 /opt/asset-manager/scripts/cve_sync.py
```
```bash
source /opt/asset-manager/venv/bin/activate && python3 /opt/asset-manager/scripts/extract_os_versions.py
```

Ces scripts sont détaillés en profondeur sur [ cette page ]({{ site.baseurl }}/scripts/nvd_sync).

---

## 📌 Etape 2 : Import de vos assets

**⚠️ Avant de continuer, créez les types d'équipement**

Pour cela, se référer à la page [Paramètres corrélation]({{ site.baseurl }}/guides/parametres), dans la catégorie **⚙️ Types d’équipements** qui reprend toute la logique.

Si aucun type d'équipement n'est créé, **vous ne pourrez pas importer d'asset car les assets ne seront pas associés à un type d'équipement.**

Il est impératif d'importer vos assets avant que l'on puisse continuer sur la suite.

Si vous n'avez pas d'assets à importer, vous pouvez continuer.

Pour cela, voir [ cette page ]({{ site.baseurl }}/installation-configuration/import).

---

## 📌 Etape 3 : Création du cronjob

**⚠️ Avant de continuer, il faut que l'import de vos assets ait eu lieu**

Il faut ajouter un cron job du script `/opt/asset-manager/scripts/run_scheduled_tasks.sh` quotidien.

Cela va lancer les scripts de téléchargement tous les jours et lancer la corrélation automatique.

Pour ajouter le cronjob : 
```bash
sudo crontab -e
```
et ajouter cette ligne :  

```bash 
0 2 * * * /bin/bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
```
Ce cronjob s'exécute tous les jours à 2H00 du matin ( heure du serveur ). 

Si l'heure ne vous convient pas, vous pouvez toujours la changer avant de sauvegarder.

---

