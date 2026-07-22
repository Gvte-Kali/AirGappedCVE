---
title: Première Utilisation
nav_order: 3
parent: Installation & Configuration
---

# 1️⃣ Première Utilisation

## ⚠️ Avant de commencer quoi que ce soit, il faut que les clés API dans le fichier .env soient fonctionnelles

## 📌 Etape 1 : Lancement du script de setup

```bash
sudo bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
```

Ce script fais ces étapes : 
1. Lancement de tous les scripts de téléchargement des bases nvd et import des cve, fabricant, modèles et autres dans la abse de données.
2. Lancement du script de corrélation
3. Création d'un dump de la base de données

```bash
sudo bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
```


---

## 📌 Etape 2 : Création du Cron job 
Il faut ajouter un cron job du script `/opt/asset-manager/scripts/run_scheduled_tasks.sh` quotidien.
Cela va lancer les scripts de téléchargement tous les jours et lancer la corrélation automatique.
Pour ajouter le cronjob : 
```bash
sudo crotab -e
```
et ajouter cette ligne :  

```bash 
0 2 * * * /bin/bash /opt/asset-manager/scripts/run_scheduled_tasks.sh
```
Ce cronjob s'exécute tous les jours à 2H00 du matin ( heure du serveur ). 
Si l'heure ne vous convient pas, vous pouvez toujours la changer avant de sauvegarder.

---

