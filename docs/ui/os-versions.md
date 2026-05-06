---
title: Page OS & Versions
parent: Interface utilisateur
nav_order: 4
---

# Page OS & Versions
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Accès

`/ui/os-versions` — menu **Référentiels → 🖥️ OS & Versions**.

---

## Rôle de la page

Cette page gère le référentiel des OS, firmwares et BIOS normalisés selon la nomenclature NVD. C'est ici qu'on ajoute les nouvelles versions d'OS au fur et à mesure des mises à jour des équipements clients.

Chaque entrée correspond à un produit NVD unique `(nvd_vendor, nvd_product)`.

---

## Filtres

Un filtre par type de produit permet d'afficher uniquement les OS, les firmwares ou les BIOS.

---

## Tableau

### Colonnes principales

| Colonne | Description |
|---------|-------------|
| Nom OS | Nom affiché (ex: `Windows Server`, `DSM`) |
| Version | Version affichée (ex: `2022`, `7.1.1`) |
| nvd_vendor | Identifiant vendor NVD exact |
| nvd_product | Identifiant produit NVD exact |
| Type | os / firmware / bios |

### À venir — Bloc F

Deux colonnes seront ajoutées prochainement :

| Colonne | Description |
|---------|-------------|
| Format version | Format attendu pour la saisie (ex: `X.X.X-XXXXX`) |
| Où trouver | Localisation de la version sur l'équipement (ex: `Panneau de config → Informations`) |

Ces colonnes alimenteront le lien ❓ dans la page Assets qui guide l'opérateur lors de la saisie d'une version libre.

---

## Ajout d'une entrée

Pour ajouter un nouvel OS ou firmware :

1. Trouver le `nvd_vendor` et `nvd_product` exacts sur [nvd.nist.gov](https://nvd.nist.gov)
2. Cliquer sur **＋ Nouveau** dans l'interface
3. Renseigner :
   - **Nom OS** : nom lisible pour l'interface (ex: `FortiOS`)
   - **Version** : version affichée (ex: `7.4.3`)
   - **nvd_vendor** : identifiant NVD exact (ex: `fortinet`)
   - **nvd_product** : identifiant NVD exact (ex: `fortios`)
   - **Type** : `os`, `firmware` ou `bios`

{: .warning }
La contrainte d'unicité `(nvd_vendor, nvd_product)` interdit les doublons. Si un produit existe déjà avec une version différente, il faut modifier l'entrée existante ou créer une nouvelle entrée avec un `nvd_product` légèrement différent si le NVD le justifie.

---

## Lien avec les assets

Une fois une entrée créée, elle devient disponible dans le typeahead de la page Assets :
- Typeahead niveau 1 (Système d'exploitation) : filtre par `os_nom`
- Typeahead niveau 2 (Version OS) : filtre par `os_nom` sélectionné

L'asset lié à cette entrée via `os_version_id` bénéficiera d'une corrélation CVE en mode **affirme**.

---

## Volume de données

Le référentiel `os_versions` contient ~20 000 entrées importées depuis le NVD. La recherche est optimisée par des index sur `os_nom`, `nvd_vendor` et `type_produit`.
