---
title: Contrainte Air-Gap
parent: Moteur de corrélation
nav_order: 6
---

# Contrainte Air-Gap — Impact sur le scoring
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe fondamental

Tous les environnements clients sont **physiquement isolés d'Internet** (air-gap). Cette contrainte est prise en compte à deux niveaux :

1. **Pré-triage déterministe** (Phase 2) — ajustement automatique du score selon le vecteur d'attaque CVSS
2. **Analyse Mistral** (Phase 3) — Mistral ajuste le score et indique si la CVE est exploitable malgré l'isolation

---

## Vecteur d'attaque CVSS et Air-Gap

Le vecteur CVSS v3 contient le champ `AV:` (Attack Vector) qui indique comment l'attaquant doit accéder à l'asset :

| Valeur | Signification | Impact Air-Gap |
|--------|---------------|----------------|
| `AV:N` | Network — accessible depuis le réseau | ⬇ **Moins critique** — Internet inaccessible |
| `AV:A` | Adjacent — réseau local uniquement | ⚠ Partiellement applicable |
| `AV:L` | Local — accès physique/session locale | ⬆ **Pleinement applicable** |
| `AV:P` | Physical — accès physique direct | ⬆ **Pleinement applicable** |

---

## Ajustements dans le pré-triage

```python
vector = cve.get("cvss_v3_vector") or ""

if "AV:N" in vector:
    score -= 3.0   # Pénalité réseau

if "AV:L" in vector or "AV:P" in vector:
    score += 0.5   # Bonus local/physique
```

### Exemple

| CVE | CVSS | Vecteur | Score brut | Ajustement | Score final |
|-----|------|---------|------------|------------|-------------|
| CVE-A | 9.8 | AV:N | 9.8 | -3.0 | 6.8 |
| CVE-B | 7.8 | AV:L | 7.8 | +0.5 | 8.3 |
| CVE-C | 8.8 | AV:A | 8.8 | 0 | 8.8 |

CVE-A est CRITICAL (9.8) mais exploitable uniquement via Internet → elle descend à HIGH. CVE-B est HIGH (7.8) mais exploitable localement → elle monte.

---

## Filtre CVE réseau basse sévérité

En plus de l'ajustement de score, les CVE réseau sous un seuil minimal sont **exclues du cache** dès le chargement :

```sql
WHERE NOT (cvss_v3_vector LIKE '%AV:N%' AND cvss_v3_score < 7.0)
```

Paramètre : `cvss_network_min` dans `config.yml` (défaut : 7.0).

Les CVE réseau de sévérité MEDIUM (4.0-6.9) sont donc ignorées — elles sont quasi-inexploitables en air-gap et généreraient trop de bruit.

---

## CWE pertinents en air-gap

Certains types de failles restent dangereux même sans accès réseau. Le pré-triage bonifie les CVE associées à ces CWE :

| CWE | Nom | Pourquoi pertinent en air-gap |
|-----|-----|-------------------------------|
| CWE-78 | OS Command Injection | Exécutable par un utilisateur local |
| CWE-77 | Command Injection | Idem |
| CWE-269 | Improper Privilege Management | Escalade de privilèges locale |
| CWE-264 | Permissions, Privileges | Idem |
| CWE-732 | Incorrect Permission Assignment | Idem |
| CWE-426 | Untrusted Search Path | Exploitable localement |
| CWE-427 | Uncontrolled Search Path | Idem |
| CWE-787 | Out-of-bounds Write | Corruption mémoire locale |
| CWE-119 | Buffer Overflow | Idem |

Bonus : **+0.5** au score si la CVE est associée à l'un de ces CWE.

---

## Rôle de Mistral pour l'air-gap

En Phase 3, Mistral reçoit le contexte explicite que les systèmes sont dans des **prisons** avec accès physique très contrôlé. Il ajuste en conséquence :

- `ajustement_score = -2.0` si la CVE nécessite un accès réseau externe impossible en air-gap
- `ajustement_score = +2.0` si la CVE est particulièrement dangereuse dans ce contexte (ex: exécution de code locale sur un système critique)
- `exploitable_air_gap = true/false` — indication explicite de l'exploitabilité

---

## Lecture du champ `exploitable_air_gap`

| Valeur | Signification dans l'interface |
|--------|-------------------------------|
| `1` (true) | ⚠️ Exploitable — badge rouge |
| `0` (false) | ✓ Non exploitable — badge vert |
| `NULL` | ? — Non évalué (corrélation non analysée par Mistral) |
