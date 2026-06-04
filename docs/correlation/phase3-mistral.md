---
title: Phase 3 — Analyse Mistral
parent: Moteur de corrélation
nav_order: 4
---

# 🤖 Phase 3 — Analyse Mistral AI

**Validation contextuelle** - Mistral ajuste le score et rend un verdict sur la pertinence réelle de la CVE.

---

## 🎯 **Principe**

- Ne **recalcule pas** le score from scratch
- **Ajuste** le `score_pre_triage` (Phase 2)
- Rend un **verdict** sur la pertinence
- Traite les corrélations par **ordre de score décroissant** (les plus critiques en premier)

---

## 📋 **Sélection des corrélations**

```sql
SELECT co.*, a.*, cv.*
FROM correlations co
JOIN assets a ON a.id = co.asset_id
JOIN cve cv ON cv.cve_id = co.cve_id
WHERE co.statut = 'nouveau'
  AND co.date_analyse IS NULL
  AND co.passer_mistral = 1
ORDER BY co.score_pre_triage DESC
```

**Exclusion** : `passer_mistral = 0` pour les types non pertinents (XSS, CSRF depuis `vuln_types.yml`)

---

## 💬 **Prompt système**

```
Tu es un expert PATCH MANAGEMENT pour environnements air-gapped.
Ces systèmes sont isolés d'Internet - accès physiques contrôlés.

Mission : TRIER, pas scorer.

Verdicts possibles :
- "patcher"      : asset vulnérable, patch nécessaire
- "informatif"   : pertinent mais pas urgent (à surveiller)
- "faux_positif" : ne concerne pas cet asset
```

---

## 📝 **Prompt utilisateur**

Contient :
- **Contexte asset** : nom, type, fabricant, modèle, OS, versions, criticité
- **Données CVE** : ID, description, score CVSS, vecteur, produit, versions affectées
- **Pré-triage** : score calculé, priorité, méthode de match

---

## 📤 **Format de réponse**

**JSON valide uniquement** (pas de markdown) :

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
| `verdict` | string | Décision finale |
| `ajustement_score` | float | Ajustement (-2.0 à +2.0) |
| `exploitable_air_gap` | bool | Exploitable malgré l'isolation ? |
| `justification` | string | Raisonnement |
| `recommandation` | string | Action recommandée |

---

## 🎯 **Règles données à Mistral**

```
- Si la CVE concerne clairement l'OS/firmware → "patcher"
- Si la CVE concerne un composant non vérifiable → "informatif"
- Si la CVE ne concerne pas cet asset → "faux_positif"
- Ajustement_score : -2.0 à +2.0 (rarement > +1.0)
- exploitable_air_gap : vrai si exploitable localement/physiquement
```

---

## ⚙️ **Paramètres**

| Paramètre | Défaut | Description |
|-----------|--------|-------------|
| `model` | mistral-large-latest | Modèle Mistral |
| `delay_seconds` | 15.0 | Délai entre appels API |
| `max_retries` | 3 | Tentatives en cas d'erreur |
| `batch_max` | 0 | 0 = illimité |
| `max_tokens` | 512 | Tokens max par réponse |
