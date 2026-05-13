---
title: Clients & Sites
parent: Référentiels métier
nav_order: 1
---

# Clients & Sites
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Hiérarchie

```
Clients
  └── Sites
        └── Assets
              └── Corrélations CVE
```

- Un client peut avoir plusieurs sites. 
- Chaque site peut avoir plusieurs assets. 
- Les corrélations CVE sont rattachées aux assets, donc indirectement aux sites et aux clients.

La suppression est **en cascade** : supprimer un client supprime ses sites, leurs assets et toutes les corrélations associées.

---

## Clients

Les clients sont les organisations dont le prestataire gère les équipements. 
Chaque client correspond à une entité distincte (entreprise, administration, collectivité…).

### Champs

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Nom | ✅ | Nom de l'organisation |
| Contact nom | | Nom du contact principal chez le client |
| Contact email | | Email du contact principal |
| Contact téléphone | | Téléphone du contact |
| Adresse | | Adresse postale du siège |
| Notes | | Informations libres |
| Actif | | 1 = actif, 0 = archivé (masqué dans les filtres) |

### Filtrage dans les vulnérabilités

Le filtre Client dans la page Vulnérabilités permet de restreindre l'affichage aux CVE détectées sur les assets d'un client donné. C'est le point d'entrée naturel pour les rapports par client.

---

## Sites

Les sites sont les localisations physiques des équipements. 
Un site correspond à un bâtiment, une salle serveur ou une installation géographique.

### Champs

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Client | ✅ | Client propriétaire du site |
| Nom | ✅ | Nom du site (ex: "Siège Paris", "Datacenter Lyon") |
| Adresse | | Adresse postale |
| Ville | | Ville |
| Code postal | | Code postal |
| Pays | | Pays (défaut : France) |
| Contact local nom | | Personne à contacter lors d'une intervention |
| Contact local email | | Email du contact local |
| Contact local téléphone | | Téléphone du contact local |
| Notes | | Informations libres |
| Actif | | 1 = actif, 0 = archivé |

### Importance du contact local

Le contact local est la personne joignable sur place lors d'une intervention. 
Dans le contexte air-gap, ce contact est particulièrement important pour coordonner les accès physiques nécessaires aux patchs.

---

## Suppression en cascade

{: .warning }
La suppression d'un client ou d'un site est irréversible et entraîne la suppression en cascade de toutes les données associées.

| Suppression de | Entraîne la suppression de |
|----------------|---------------------------|
| Client | Tous ses sites + tous leurs assets + toutes leurs corrélations |
| Site | Tous ses assets + toutes leurs corrélations |

Un client avec des assets ne peut pas être supprimé accidentellement depuis l'interface — une confirmation est demandée.

---

## Cas d'usage : client avec plusieurs sites

```
Administration Pénitentiaire
  ├── MA-Metz
  │     ├── Serveur-Windows (serveur)
  │     ├── NAS (nas)
  │     └── PC Greffe (pc)
  └── MA-Nancy
        ├── Serveur-AD (serveur)
        └── Switch-Core (switch)
```
