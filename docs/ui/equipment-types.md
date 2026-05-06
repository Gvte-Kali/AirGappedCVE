---
title: Page Types d'équipements
parent: Interface utilisateur
nav_order: 3
---

# Page Types d'équipements
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Accès

`/ui/equipment-types` — menu **Référentiels → ⚙️ Types d'équipements**.

---

## Rôle de la page

Cette page configure le comportement du moteur de corrélation CVE pour chaque catégorie d'équipement. C'est une page de configuration avancée — les modifications impactent directement les corrélations au prochain lancement du pipeline.

---

## Tableau

Le tableau affiche tous les types d'équipements avec leurs paramètres de corrélation.

### En-tête sticky

L'en-tête du tableau reste visible en permanence lors du scroll — utile quand le tableau est long et qu'on édite une ligne en bas de page.

### Colonnes

| Colonne | Description |
|---------|-------------|
| Code | Identifiant technique unique (ex: `serveur`, `nas`) |
| Label | Nom affiché dans l'interface |
| OS (FK) | ✓ si `use_os_version = 1` |
| Version OS | ✓ si `use_version_os = 1` |
| Firmware | ✓ si `use_version_firmware = 1` |
| BIOS | ✓ si `use_version_bios = 1` |
| Source vendor | Badge coloré : OS (FK) / Firmware (FK) / Matériel / Auto |
| Assets | Nombre d'assets utilisant ce type |
| Actions | Bouton 🗑️ (désactivé si assets > 0) |

---

## Édition inline

Cliquer sur une ligne la passe en mode édition directement dans le tableau. Les champs éditables sont :

- **Label** — texte libre
- **OS (FK)** — checkbox
- **Version OS** — checkbox
- **Firmware** — checkbox
- **BIOS** — checkbox
- **Source vendor** — select (os_fk / fw_fk / materiel / detection_auto)

Deux boutons apparaissent : ✅ Sauv. et ✖ (annuler). La touche `Échap` annule également l'édition.

---

## Création d'un nouveau type

Le bouton **＋ Nouveau type** insère une nouvelle ligne en haut du tableau en mode édition. Le champ **Code** est alors éditable (il ne l'est plus après création).

Le code doit être unique — une erreur est retournée si le code existe déjà.

---

## Suppression

Le bouton 🗑️ est **désactivé** si le type est utilisé par au moins un asset. Il faut d'abord réaffecter ou supprimer les assets concernés.

---

## Badges Source vendor

| Badge | Couleur | Signification |
|-------|---------|---------------|
| OS (FK) | Bleu | Vendor depuis l'OS normalisé |
| Firmware (FK) | Orange | Vendor depuis le firmware normalisé |
| Matériel | Vert | Vendor du fabricant matériel |
| Auto | Jaune | Détection automatique (fallback) |

---

## Impact des modifications

Les modifications apportées dans cette page prennent effet au **prochain lancement de la corrélation**. Les corrélations déjà en base ne sont pas rétroactivement modifiées.

Pour réappliquer une configuration modifiée sur les corrélations existantes :
1. Supprimer les corrélations concernées en base
2. Relancer la corrélation depuis l'interface
