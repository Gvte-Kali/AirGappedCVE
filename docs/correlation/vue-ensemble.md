---
title: Vue d'ensemble
parent: Moteur de corrélation
nav_order: 1
---

# Vue d'ensemble — Flux bout en bout
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Flux complet

```
[Base de données]
  assets (actifs, avec vendor_id)
  cve (importées depuis NVD)
        │
        ▼
[Phase 1 — correlate()]
  Pour chaque asset :
    ├── get_correlation_vendor()      → vendor NVD à cibler
    ├── build_cve_cache()            → charge CVE en mémoire par vendor
    ├── filtre produit (FK ou fuzzy) → réduit les candidats
    ├── is_version_affected()        → vérifie le range de version
    └── insert_correlation()         → INSERT idempotent en base
        │
        ▼ correlations (statut=nouveau, score_pre_triage calculé)
        │
[Phase 2 — calc_pre_triage_score()]
  Incluse dans Phase 1, calculée à l'insertion :
    ├── base = cvss_v3_score
    ├── ± ajustements air-gap (AV:N / AV:L / AV:P)
    ├── ± criticité asset
    ├── ± type d'attaque (vuln_types.yml)
    └── → score_pre_triage + priorite_pre_triage
        │
        ▼ correlations (score_pre_triage, priorite_pre_triage renseignés)
        │
[Phase 3 — analyze()]
  Pour chaque corrélation (statut=nouveau, passer_mistral=1) :
    ├── Construire prompt (asset + CVE + pré-triage)
    ├── Appel API Mistral
    ├── Parser JSON (verdict + ajustement + air-gap + justification)
    └── UPDATE correlations (statut, score_contextuel, analyse_mistral)
        │
        ▼ correlations (statut=confirme|nouveau|faux_positif)
        │
[Opérateur]
  Revue manuelle via l'interface web :
    ├── Valider / infirmer le verdict Mistral
    ├── override_utilisateur (a_patcher / informatif / faux_positif)
    └── Marquer comme patché
```

---

## Idempotence

Le moteur est conçu pour être **relancé sans risque** :

- `insert_correlation()` vérifie l'existence de `(asset_id, cve_id)` avant d'insérer
- Si une corrélation existe déjà avec une meilleure passe de corrélation, elle n'est pas écrasée
- Si une corrélation existe avec une moins bonne passe, elle est mise à jour

Les passes sont ordonnées par précision : `cpe_full` > `vendor_product` > `os_textuel`.

---

## Ce que le moteur ne fait pas

- Il ne déploie **aucun agent** chez les clients
- Il ne scanne **pas les réseaux**
- Il ne récupère **pas les CVE en temps réel** (la sync NVD est un script séparé)
- Il ne prend **pas de décision définitive** — Mistral propose, l'opérateur valide

---

## Contraintes de performance

La table `cve` contient ~932 000 entrées. Pour éviter de charger toute la table à chaque run, le moteur utilise :

- Un **cache par vendor** : seules les CVE du vendor de l'asset sont chargées en mémoire
- Un **filtre CVSS minimum** (`cvss_min`, défaut 4.0)
- Un **filtre réseau** : les CVE `AV:N` sous `cvss_network_min` (défaut 7.0) sont ignorées
- Une **limite par vendor** (`vendor_cve_limit`, défaut 2000 — mettre à 0 pour illimité)

Pour Microsoft qui a ~13 000 CVE éligibles, augmenter `vendor_cve_limit` ou le mettre à 0 est nécessaire pour ne manquer aucune CVE.
