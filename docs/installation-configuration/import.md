---
title: Import
nav_order: 4
parent: Installation & Configuration
---

# 📥 Import des informations depuis votre logiciel de gestion

## ⚠️ Cette étape prend beaucoup de temps et demande beaucoup de rigueur !

## 📌 Etape 1 : Télécharger le template d'import

Pour télécharger le template d'import, naviguez jusqu'à l'url de la page d'import : 
```html
http://URL/ui/import
```

Vous allez avoir un fichier xlsx qu'il faudra remplir avec les informations de tous les clients,sites,assets,...

Afin d'y voir plus clair, ci-dessous vous avez un tableau des informations qu'il est possible de renseigner dans le fichier : 

## Tableau des catégories

| Element | Type case | Informations utiles |
|---------|--------|
| Client | Texte libre | Sensible à la casse |
| Site | Texte libre | Sensible à la casse |
| Nom interne | Texte libre | Le nom que vous utilisez pour l'asset dans vos logiciels ex:'Switch Local 2B' |
| Type d'équipement | Menu déroulant | Les propositions existantes dépendent de la page 'ui/parametres' catégorie 'types d'équipements' |
| Criticité | Menu déroulant | faible / moyen / eleve / critique |
| Fabricant | Menu déroulant | Choisir parmis les propositions |
| Modèle | Texte libre | Sensible à la casse |
| OS | Menu déroulant | Choisir parmis les propositions |
| OS ( version normalisée) | Menu déroulant | Cette colonne est utile UNIQUEMENT pour les équipements Windows |
| Version OS libre | Texte libre | Cette colonne est à renseigner pour tout ce qui a un OS à proprement parler ( PC, NAS, Serveur,... ) |
| Firmware | Menu déroulant | Cette colonne est à renseigner pour tout ce qui est IoT, qui n'a ps d'OS à proprement parler ( Imprimante, caméra,... ) |
| Statut opérationnel | Menu déroulant | Choisir parmis les propositions |
| Adresse IP | Texte libre | L'adresse IP de l'asset concerné |
| Adresse MAC | Texte libre | L'adresse MAC de l'asset concerné |
| Hostname | Texte libre | Le hostname ( nom déclaré sur le réseau LAN ) de l'asset |
| Numéro de série | Texte libre | Le numéro de série de l'asset |
| Date installation | Texte libre | La date d'installation de l'asset |
| Fin de garantie | Texte libre | La date de fin de garantie de l'asset |
| Notes | Texte libre | Une case permettant de renseigner des commentaires sur l'asset |