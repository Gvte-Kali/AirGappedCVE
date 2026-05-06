---
title: Interpréter une corrélation CVE
parent: Guides opérationnels
nav_order: 4
---

# Interpréter une corrélation CVE
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Ce guide explique comment lire et interpréter les informations d'une corrélation CVE dans le détail.

---

## Ouvrir le détail

Depuis la page `/ui/vulns`, cliquer sur le bouton 🔍 d'une ligne pour ouvrir le modal de détail.

---

## Bloc Asset

```
Nom         : NAS
Type        : nas
OS          : N/A  DSM (DiskStation Manager) 7.2.2-72806 Update 3
Firmware    : N/A
Criticité   : moyen
```

| Champ | Interprétation |
|-------|---------------|
| OS | `N/A` = pas d'`os_version_id` FK / la valeur après = `version_os` texte libre |
| Criticité | Influence le score — `eleve`/`critique` = +1.0 au pré-triage |

---

## Bloc CVE

```
CVSS v3 : 8.2 (HIGH)
Vecteur : CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
Fabricant : synology
Produit : diskstation_manager
```

### Lire le vecteur CVSS

| Composant | Valeur | Signification en air-gap |
|-----------|--------|--------------------------|
| `AV:L` | Local | ✅ Exploitable même sans réseau |
| `AV:N` | Network | ⬇ Moins critique (pas d'Internet) |
| `AV:P` | Physical | ✅ Exploitable avec accès physique |
| `AC:L` | Low complexity | Facilement exploitable |
| `PR:H` | High privileges | Nécessite des droits admin |
| `S:C` | Changed scope | Impact au-delà du composant vulnérable |
| `C:H/I:H/A:H` | High CIA | Impact maximal sur confidentialité/intégrité/disponibilité |

---

## Bloc Scores

```
Score contextuel : 8.8
Air-gap          : ⚠️ Exploitable
Type             : Affirmé
```

### Score contextuel

```
score_pre_triage (calculé localement) + ajustement Mistral = score_contextuel
```

Exemple :
- CVSS de base : 8.2
- AV:L → +0.5 (local, exploitable en air-gap)
- Version affirme → +1.0
- CWE-269 (privilèges) → +0.5
- LPE priorité 4 → +1.5
- **Score pré-triage : 10.0** (clampé)
- Ajustement Mistral : -1.0 (contexte prison, accès physique contrôlé)
- **Score final : 9.0 → critique**

### Type de corrélation

| Valeur | Signification |
|--------|---------------|
| `Affirmé` | La version de l'asset est dans le range vulnérable CVE — corrélation certaine |
| `Informatif` | La version n'a pas pu être confirmée — à valider manuellement |

### Air-gap

| Valeur | Signification |
|--------|---------------|
| ⚠️ Exploitable | Mistral estime que la CVE est exploitable malgré l'isolation réseau |
| ✓ Non exploitable | Mistral estime que l'isolation rend la CVE non exploitable |
| ? | Pas encore analysé par Mistral |

---

## Bloc Analyse Mistral

```
[Verdict Mistral: patcher] [Ajustement: -1.0]

La CVE affecte directement le DSM avec un vecteur local (AV:L)
exploitable même en air-gap.

Recommandation: Mettre à jour le DSM vers une version ≥ 6.2.4-25553
```

| Champ | Interprétation |
|-------|---------------|
| Verdict | `patcher` = patch nécessaire / `informatif` = à surveiller / `faux_positif` = non applicable |
| Ajustement | Entre -2.0 et +2.0 — modifie le score pré-triage |
| Justification | Raisonnement de Mistral en 1-2 phrases |
| Recommandation | Action concrète à réaliser |

---

## Champs éditables par l'opérateur

### Statut

| Statut | Quand l'utiliser |
|--------|-----------------|
| `nouveau` | En attente de revue |
| `en_analyse` | En cours d'investigation |
| `confirme` | Vulnérabilité confirmée, patch planifié |
| `mitige` | Risque atténué par une mesure compensatoire |
| `faux_positif` | Ne s'applique pas à cet asset |
| `patche` | Patch appliqué |

### Override utilisateur

L'override permet de forcer une décision qui prime sur le statut automatique. Il est visible dans la vue `v_vulnerabilites_tableau` via `COALESCE(override_utilisateur, statut)`.

| Override | Quand l'utiliser |
|----------|-----------------|
| `a_patcher` | Forcer le traitement en priorité malgré un verdict Mistral douteux |
| `informatif` | Dégrader une corrélation `confirme` jugée non critique |
| `faux_positif` | Invalider définitivement une corrélation |

### Notes

Champ libre pour documenter les décisions, les actions entreprises, les dates d'intervention planifiées.

---

## Workflow opérateur recommandé

```
1. Filtrer sur statut = "nouveau" et priorité = "critique"/"haute"
2. Pour chaque corrélation :
   a. Lire le type (affirme/informatif) → fiabilité du match
   b. Lire le vecteur CVSS → exploitabilité en air-gap
   c. Lire l'analyse Mistral → verdict et recommandation
   d. Décider :
      - Patch nécessaire → statut = "confirme" + noter la date planifiée
      - À surveiller → statut = "en_analyse"
      - Faux positif → statut = "faux_positif"
      - Déjà patché → statut = "patche"
3. Filtrer sur statut = "confirme" pour voir les actions à entreprendre
```
