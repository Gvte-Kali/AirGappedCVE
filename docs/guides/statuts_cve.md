---
title: Modification des status des CVE
parent: Page Vulnérabilités
nav_order: 1
---

# Page Vulnérabilités

## Modifier le statut d'une CVE

Les CVE sont classées en 5 catégories, dont 4 catégories appliquées après la corrélation de Mistral AI : 
1. __Mistral AI__ **Nouveau** : La CVE vient d'être assignée mais n'a pas encore été traitée par Mistral AI
2. __Mistral AI__ **En analyse** : Mistral AI est en train d'analyser la CVE afin de la classer
3. __Mistral AI__ **Confirmé** : La CVE a été confirmée par Mistral AI, l'asset est donc à patcher
4. __Mistral AI__ **Faux-Positif** : La CVE a été classée en faux-positif par Mistral AI
5. __utilisateur__ **Patché** : La CVE a été patchée car l'asset a été mis à jour

Il est possible de changer le statut de la CVE, l'état n'est pas figé.

L'utilisateur peut donc choisir de changer l'état de chaque CVE de deux manières : 

1. Cliquer sur la loupe 🔍, changer le statut dans la pop-up, et ensuite sauvegarder.

![Changer statut unique](https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/refs/heads/main/docs/images/Vulns_changement_statut_unique.png)


2. Sélectionner plusieurs assets via les cases à cocher, choisir un état sur le menu en haut de la page, et appliquer : 

![Changer statut](https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/refs/heads/main/docs/images/Vulns_changement_statut.png)