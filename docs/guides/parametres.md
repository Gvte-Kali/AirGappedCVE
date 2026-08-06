---
title: Page Parametres
parent: Guides d'utilisation
nav_order: 5
---

# 🔧 Paramètres corrélation

La page des paramètres va gérer l'ensemble des paramètres pris en compte lors de la corrélation entre les CVEs et les Assets.

Cette page comprend plusieurs catégories : 
- 🔍 Corrélation CVE 
- 🤖 Analyse Mistral AI
- 🏷️ Types de vulnérabilités
- ⚙️ Types d'équipements
- 🗺️ Mapping OS textuel → Vendor NVD

![Page Paramètres](https://raw.githubusercontent.com/Gvte-Kali/AirGappedCVE/refs/heads/main/docs/images/Parametres.png)

---

## 🔍 Corrélation CVE 

Cette catégorie vous permet de choisir la granularité de la corrélation au niveau des CVEs.

En effet, vous pouvez choisir d'adapter certains paramètres afin d'ajuster la souplesse que vous voulez donner. 

La corrélation prendra en compte : 

- Le score CVSS minimum des CVEs
- Le score CVSS minimum des CVEs de type réseau
- La date à partir desquelles les CVEs seront étudiées
- Une limite du nombre de CVE par fabricant

---

## 🤖 Analyse Mistral AI

Ici, vous pourrez changer les paramètres liés aux appels à l'API Mistral AI : 

- Le modèle
- Le délai entre les appels
- Le nombre de tentatives maximum en cas d'échec
- Le nombre d'analyses total pour le script en cours
- Le nombre maximum de tokens en sortie
- Le mode _force_ qui ré-analyse toutes les corrélations déjà traitées
- Le prompt envoyé à Mistral AI pour chaque Asset <--> CVE

---

## 🏷️ Types de vulnérabilités

Dans cette catégories, vous pourrez modifier le scoring et la priorité des types de vulnérabilités.

Les vulnérabilités ont chacune un **type** qui les catégorise. Chaque type de vulnérabilité est associé à une priorité.

Chaque type de vulnérabilité est associé à un identifiant **CWE** qui est en fait un identifiant officiel du type de vulnérabilité.

---

## ⚙️ Type d'équipements

Ici vous avez un menu qui va vous permettre de gérer tous les types d'équipements des assets de votre inventaire.
Vous pouvez ajouter un nouveau type d'équipement via le bouton "+ nouveau type".

Les champs renseignés ici sont très importants car ils vont permettre de gérer une grosse partie de la corrélation.
Les champs qui sont cochés sont les champs qui seront analysés par le moteur de corrélation.

Explication des champs à renseigner : 

| Nom du champ | Explication | Commentaire |
| ------------ | ----------- | -------- |
| Code | Le nom en base de données | C'est plus propre si vous mettez des **underscores _** au lieu de mettre des espaces |
| Label | Le nom qui sera affiché au niveau de tous les menus déroulants | Choisir un nom compréhensible et simple |
| OS (normalisé NVD) | OS déjà existant dans les référentiels NVD | Vérifier l'existence dans `http://URL/ui/os-versions` avant de cocher|
| Version OS | Vérification de la version de l'OS, qu'il soit normé ou non.  | Si vous avez coché OS, il est pertinent de cocher Version OS aussi |
| Firmware | Vérification de la version du firmware renseignée | A cocher pour tout ce qui va être IoT, equipements réseaux,... |
| BIOS | Vérification de la version du BIOS renseignée | A voir au cas par cas |

---

## 🗺️ Mapping OS textuel → Vendor NVD

Quand un Asset n'a pas d'OS existant en base de données, donc un OS rentré à la main, on peut choisir de mapper manuellement un **fabricant** (et donc TOUTES les CVEs associées) à un **mot-clé**. 

Toutes les CVEs du fabricant seront donc assignées à l'OS.

Attention, n'utiliser cette fonctionnalité que si l'OS n'existe pas.