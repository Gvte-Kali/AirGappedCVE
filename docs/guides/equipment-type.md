---
title: Configurer un type d'équipement
parent: Guides opérationnels
nav_order: 3
---

# ⚙️ Configurer un type d'équipement

**Choisir les bons paramètres dans `/ui/equipment-types`**

---

# Worflow

Pour configurer un type d'équipement, naviguez dans outils > Paramètres corrélation ( __http://URL/ui/parametres__ )

Dépliez le menu déroulant "Types d'équipements"

Ici vous avez un menu qui va vous permettre de gérer tous les types d'équipements des assets de votre inventaire.
Vous pouvez ajouter un nouveau type d'équipement via le bouton "+ nouveau type".

Les champs renseignés ici sont très importants car ils vont permettre de gérer une grosse partie de la corrélation.
Les champs qui sont cochés sont les champs qui seront analysés par le moteur de corrélation.

Explication des champs à renseigner : 

| Nom du champ | Explication | Commentaire |
| ------------ | ----------- | -------- |
| Code | Le nom en base de données | C'est plus sympa si vous mettez des underscores `_`au lieu de mettre des espaces |
| Label | Le nom qui sera affiché au niveau de tous les menus déroulants | Choisir un nom compréhensible et simple |
| OS (normalisé NVD) | OS déjà existant dans les référentiels NVD | Vérifier l'existence dans `http://URL/ui/os-versions` avant de cocher|
| Version OS | Vérification de la version de l'OS, qu'il soit normé ou non.  | Si vous avez coché OS, il est pertinent de cocher Version OS aussi |
| Firmware | Vérification de la version du firmware renseignée | A cocher pour tout ce qui va être IoT, equipements réseaux,... |
| BIOS | Vérification de la version du BIOS renseignée | A voir au cas par cas |
