---
title: Assets
parent: Référentiels métier
nav_order: 2
---

# Assets
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Définition

Un asset est un équipement informatique inventorié pour le compte d'un client. Il peut s'agir d'un serveur, d'un PC, d'un NAS, d'un switch, d'une caméra IP, d'un lecteur biométrique, etc.

Le moteur de corrélation CVE analyse les assets **actifs** disposant d'un **fabricant renseigné**.

---

## Champs principaux

### Identification

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Client | ✅ | Client propriétaire |
| Site | ✅ | Site de localisation physique |
| Nom interne | ✅ | Nom d'inventaire (ex: `SRV-DC01`, `NAS-METZ-01`) |
| Type d'équipement | ✅ | Sélection depuis le référentiel `equipment_types` |
| Numéro de série | | Numéro de série constructeur |
| Adresse IP | | IPv4 ou IPv6 |
| Adresse MAC | | Format `AA:BB:CC:DD:EE:FF` |
| Hostname | | Nom DNS/NetBIOS |

### Fabricant et modèle

| Champ | Description |
|-------|-------------|
| Fabricant | FK → `product_vendors` — vendor NVD utilisé pour la corrélation |
| Modèle | FK → `product_models` — optionnel, affine la corrélation |

{: .warning }
Un asset **sans fabricant** ne sera pas analysé par le moteur de corrélation. C'est le champ le plus critique à renseigner.

### OS et versions

La gestion des versions est à deux niveaux selon la disponibilité dans le référentiel :

#### Niveau 1 — OS normalisé (recommandé)

| Champ | Description |
|-------|-------------|
| Système d'exploitation | Sélection du nom OS depuis `os_versions` (typeahead niveau 1) |
| Version OS | Sélection de la version normalisée depuis `os_versions` (typeahead niveau 2) → remplit `os_version_id` |

Quand `os_version_id` est renseigné, la corrélation utilise `nvd_vendor` et `nvd_product` exacts → corrélation en mode **affirme**.

#### Niveau 2 — Version libre (fallback)

Si la version exacte n'existe pas dans le référentiel `os_versions`, un champ texte libre apparaît :

| Champ | Description |
|-------|-------------|
| Version exacte | Texte libre stocké dans `version_os` (ex: `DSM 7.2.2-72806 Update 3`) |

La valeur saisie est concaténée avec le nom OS : `"DSM (DiskStation Manager) 7.2.2-72806 Update 3"`.

Dans ce cas, la corrélation utilise le matching flou de version → corrélation en mode **informatif**.

{: .note }
Le lien ❓ à côté du champ version OS renvoie vers la page OS & Versions qui documente le format attendu pour chaque fabricant.

#### Firmware et BIOS

| Champ | Description |
|-------|-------------|
| Firmware | FK → `os_versions` (type_produit = firmware) |
| BIOS / UEFI | FK → `os_versions` (type_produit = bios) |

Ces champs sont utilisés par le moteur pour les équipements réseau (switches, pare-feux) et les serveurs avec BIOS versionné.

### Statut et criticité

| Champ | Valeurs | Impact |
|-------|---------|--------|
| Criticité | faible / moyen / eleve / critique | Influence le score de pré-triage (+1.0 pour eleve/critique) |
| Statut opérationnel | actif / inactif / maintenance / hors_service | Seuls les assets **actif** et **maintenance** sont analysés |

{: .note }
Les assets en `hors_service` ou `inactif` sont exclus du moteur de corrélation.

---

## Impact sur la corrélation CVE

La qualité des données saisies sur l'asset détermine directement la précision de la corrélation :

| Données renseignées | Type de corrélation | Précision |
|--------------------|---------------------|-----------|
| Fabricant + `os_version_id` normalisé | `affirme` | ⭐⭐⭐ Excellente |
| Fabricant + `version_os` texte libre | `informatif` | ⭐⭐ Bonne |
| Fabricant seul (pas de version) | `informatif` | ⭐ Basique |
| Pas de fabricant | Aucune corrélation | ❌ |

---

## Propriétés spécifiques (JSON)

Le champ `proprietes_specifiques` permet de stocker des données arbitraires au format JSON, spécifiques à un type d'équipement. Ce champ est validé par MariaDB (`CHECK (json_valid(...))`).

Non exposé dans l'interface actuelle — réservé pour des extensions futures.
