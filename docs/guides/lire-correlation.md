---
title: Gérer les CVEs
parent: Guides d'utilisation
nav_order: 4
---

# 📝 Workflow Page Vulnérabilités

## 1. Filtrer les CVE

Par défaut, lors du chargement de la page 'Vulnérabilités', toutes les CVE sont chargées, y compris les CVE qui sont en faux-positifs.

La première chose à faire est donc de filtrer.
En cliquant sur 'Critères de recherche' vous pouvez filtrer l'affichage de la page web.

## 2. Modification des status des CVE

Les CVE sont classées en 5 catégories, dont 4 catégories appliquées après la corrélation de Mistral AI : 
1. __Mistral AI__ **Nouveau** : La CVE vient d'être assignée mais n'a pas encore été traitée par Mistral AI
2. __Mistral AI__ **En analyse** : Mistral AI est en train d'analyser la CVE afin de la classer
3. __Mistral AI__ **Confirmé** : La CVE a été confirmée par Mistral AI, l'asset est donc à patcher
4. __Mistral AI__ **Faux-Positif** : La CVE a été classée en faux-positif par Mistral AI
5. __utilisateur__ **Patché** : La CVE a été patchée car l'asset a été mis à jour

Il est possible de changer le statut de la CVE, l'état n'est pas figé.

L'utilisateur peut donc choisir de changer l'état de chaque CVE de deux manières : 
1. Cliquer sur la loupe 🔍, changer le statut dans la pop-up, et ensuite sauvegarder.
2. Sélectionner plusieurs assets via les cases à cocher, choisir un état sur le menu en haut de la page, et appliquer.

## 3. Imprimer un rapport des vulnérabilités

En haut de la page, sur la droite, vous avez un bouton 'Générer PDF'
Le rapport de vulnérabilités est affecté par les critères de recherche.

En effet, les vulnérabilités qui seront concernées par le pdf sont celles qui sont affichées sur votre page web, donc cellex qui ont été recherchées.
Rappel  par défaut, aucun filtre n'est appliqué et toutes les CVE sont affichées.

Une fois le filtre appliqué, lorsque vous cliquez sur le bouton 'Générer PDF', vous aurez plusieurs champs à remplir : 
- Les champs à inclure dans le PDF, sous forme de cases à cocher
- Le type de rapport
- Le nom du fichier