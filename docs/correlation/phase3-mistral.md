---
title: Phase 3 — Analyse Mistral
parent: Moteur de corrélation
nav_order: 4
---

# Phase 3 — Analyse Mistral AI
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe

La Phase 3 envoie chaque corrélation `nouveau` à Mistral AI pour validation contextuelle. Mistral ne recalcule pas le score — il **ajuste** le `score_pre_triage` et rend un **verdict** sur la pertinence réelle de la CVE pour cet asset.

---

## Sélection des corrélations à analyser

```sql
SELECT co.*, a.*, cv.*, pv.nvd_vendor, ...
FROM correlations co
JOIN assets a ON a.id = co.asset_id
JOIN cve cv ON cv.cve_id = co.cve_id
...
WHERE co.statut = 'nouveau'
  AND co.date_analyse IS NULL
  AND co.passer_mistral = 1
ORDER BY co.score_pre_triage DESC, cv.cvss_v3_score DESC
```

Les corrélations sont traitées par **ordre de score décroissant** — les plus critiques en premier.

Le champ `passer_mistral = 0` permet d'exclure certaines CVE de l'analyse (configuré automatiquement par `vuln_types.yml` pour les types non pertinents en air-gap comme XSS, CSRF).

---

## Prompt système

```
Tu es un expert PATCH MANAGEMENT pour environnements air-gapped (isolés d'Internet).
Ces systèmes sont dans des prisons, donc les accès physiques sont très contrôlés.

Une corrélation CVE↔asset t'est soumise. Elle a déjà un score de pré-triage
calculé par des règles déterministes. Ta mission est de TRIER, pas de scorer.

Verdicts possibles :
- "patcher"      : asset vulnérable, patch nécessaire
- "informatif"   : pertinent mais pas urgent (à surveiller)
- "faux_positif" : ne concerne pas vraiment cet asset
```

---

## Prompt utilisateur

Le prompt contient :

- **Contexte asset** : nom, type, fabricant, modèle, OS, versions (OS/FW/BIOS), criticité
- **Données CVE** : ID, description (tronquée à 600 chars), score CVSS, vecteur, produit, versions affectées (JSON, tronqué à 400 chars)
- **Pré-triage** : score calculé, priorité, méthode de match, type de corrélation

---

## Format de réponse attendu

Mistral doit répondre **uniquement en JSON valide**, sans markdown :

```json
{
  "verdict": "patcher | informatif | faux_positif",
  "ajustement_score": -2.0,
  "exploitable_air_gap": true,
  "justification": "1-2 phrases max",
  "recommandation": "Action concrète"
}
```

| Champ | Type | Description |
|-------|------|-------------|
| `verdict` | string | Décision finale : `patcher`, `informatif`, `faux_positif` |
| `ajustement_score` | float | Ajustement entre -2.0 et +2.0 appliqué au score_pre_triage |
| `exploitable_air_gap` | bool/null | La CVE est-elle exploitable malgré l'isolation réseau ? |
| `justification` | string | Raisonnement en 1-2 phrases |
| `recommandation` | string | Action concrète recommandée |

---

## Règles données à Mistral

```
- Si la CVE concerne clairement l'OS/firmware → "patcher"
- Si la CVE concerne un composant non vérifiable sur cet asset → "informatif"
- Si la CVE ne s'applique pas du tout (mauvais produit, version OK) → "faux_positif"
- ajustement_score : -2 si air-gap rend ça moins exploitable, +2 si plus dangereux
```

---

## Calcul du score final

```python
score_final = score_pre_triage + ajustement_score
score_final = max(0.0, min(10.0, score_final))  # clamp 0-10

# Recalcul de la priorité depuis le score final
if score_final >= 9.0:  priorite_finale = "critique"
elif score_final >= 7.0: priorite_finale = "haute"
elif score_final >= 4.0: priorite_finale = "moyenne"
else:                    priorite_finale = "basse"
```

---

## Mapping verdict → statut

| Verdict Mistral | Statut en base | Explication |
|-----------------|----------------|-------------|
| `patcher` | `confirme` | Mistral confirme la vulnérabilité |
| `informatif` | `nouveau` | Reste en file pour revue opérateur |
| `faux_positif` | `faux_positif` | Écarté automatiquement |

{: .note }
Le verdict `informatif` ne clôt pas la corrélation — elle reste en `statut=nouveau` pour que l'opérateur la valide manuellement. Mistral laisse sa trace dans `analyse_mistral` et `type_correlation`.

---

## Gestion des erreurs et rate limiting

En cas d'erreur API ou de rate limit (HTTP 429) :

```python
# Backoff progressif : 20s, 40s, 60s
wait = (attempt + 1) * 20
time.sleep(wait)
```

Après `max_retries` tentatives échouées, la corrélation est **remise en `statut=nouveau`** pour être retraitée au prochain run.

---

## Résultat en base

```sql
UPDATE correlations SET
    statut = 'confirme',          -- ou 'nouveau' / 'faux_positif'
    priorite = 'haute',
    score_contextuel = 8.5,
    exploitable_air_gap = 1,
    analyse_mistral = '[Verdict Mistral: patcher] [Ajustement: -1.0]\n\nLa CVE...',
    risque_reel = 'Mettre à jour vers FortiOS 7.4.x',
    date_analyse = NOW()
WHERE id = X;
```

Le champ `analyse_mistral` contient le verdict, l'ajustement, la justification et la recommandation concaténés pour affichage dans l'interface.
