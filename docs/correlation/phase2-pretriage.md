---
title: Phase 2 — Pré-classification
parent: Moteur de corrélation
nav_order: 3
---

# Phase 2 — Pré-classification déterministe
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe

La Phase 2 est calculée **à l'insertion**, dans la Phase 1. Elle produit un `score_pre_triage` (0-10) et une `priorite_pre_triage` pour chaque corrélation, sans aucune IA.

Ce score sert de base à Mistral en Phase 3 : Mistral ajuste ce score plutôt que de le recalculer from scratch.

---

## Fonction `calc_pre_triage_score`

```python
def calc_pre_triage_score(cve, asset, version_match, cwe_list, priorite_type):
    score = float(cve["cvss_v3_score"])  # base
    ...
    return round(score, 1), priorite
```

---

## Règles de scoring

### 1. Base — Score CVSS v3

```
score = cvss_v3_score  (0.0 à 10.0)
```

### 2. Ajustement Air-Gap — Vecteur d'attaque

| Condition | Ajustement | Raison |
|-----------|------------|--------|
| `AV:N` (réseau) dans le vecteur | **-3.0** | Moins exploitable en environnement isolé |
| `AV:L` (local) ou `AV:P` (physique) | **+0.5** | Pleinement exploitable même en air-gap |

### 3. Confirmation de version

| Condition | Ajustement |
|-----------|------------|
| `version_match = "affirme"` (version confirmée vulnérable) | **+1.0** |
| `version_match = "informatif"` (version inconnue ou range absent) | 0 |

### 4. Type de produit CVE

| Condition | Ajustement |
|-----------|------------|
| Produit contient : `os`, `firmware`, `bios`, `kernel`, `system`… | **+0.5** |
| Produit contient : `library`, `lib`, `plugin`, `module`, `driver` | **-1.0** |

### 5. Criticité opérationnelle de l'asset

| Niveau | Ajustement |
|--------|------------|
| `critique` ou `eleve` | **+1.0** |
| `moyen` ou `faible` | 0 |

### 6. CWE pertinents en Air-Gap

Si la CVE est associée à un CWE de la liste suivante, bonus de **+0.5** :

| CWE | Description |
|-----|-------------|
| CWE-269 | Improper Privilege Management |
| CWE-78 | OS Command Injection |
| CWE-264 | Permissions, Privileges |
| CWE-732 | Incorrect Permission Assignment |
| CWE-426 | Untrusted Search Path |
| CWE-77 | Command Injection |
| CWE-787 | Out-of-bounds Write |
| CWE-119 | Buffer Overflow |

### 7. Type d'attaque (`vuln_types.yml`)

| `priorite_type` | Catégories | Ajustement |
|-----------------|-----------|------------|
| 4 | RCE, MemCorrupt, CmdInjection, FirmwareBIOS | **+1.5** |
| 3 | LPE, DoS, AuthBypass, FileWrite | **+0.5** |
| 2 | Défaut (Unknown) | 0 |
| 1 | InfoDisc, WeakCrypto, Misconfiguration | **-1.0** |
| 0 | XSS, CSRF, SSRF, OpenRedirect | **-5.0** |

### 8. Bonus produit (optionnel)

Si le produit CVE partage 6+ caractères avec `nvd_product` ou `version_os` de l'asset :

```
score = min(10.0, score + 0.5)
```

---

## Calcul de la priorité

```python
if score >= 9.0:  priorite = "critique"
elif score >= 7.0: priorite = "haute"
elif score >= 4.0: priorite = "moyenne"
else:              priorite = "basse"
```

---

## Exemple de calcul

**CVE-2021-26563** sur un NAS Synology DSM 7.1.1, criticité `moyen` :

| Étape | Valeur | Explication |
|-------|--------|-------------|
| Base CVSS | 8.2 | Score NVD |
| AV:L dans vecteur | +0.5 | Local → exploitable en air-gap |
| version_match = affirme | +1.0 | Version confirmée vulnérable |
| Produit = OS (DSM) | +0.5 | Firmware/OS → bonus |
| Criticité = moyen | 0 | Pas de bonus |
| CWE-269 (Privilege) | +0.5 | CWE pertinent air-gap |
| priorite_type = 4 (LPE) | +1.5 | Escalade de privilèges |
| **Total** | **12.2 → 10.0** | Clampé à 10.0 |
| **Priorité** | **critique** | ≥ 9.0 |

---

## Résultat en base

```sql
UPDATE correlations SET
    score_pre_triage = 10.0,
    priorite_pre_triage = 'critique'
WHERE asset_id = X AND cve_id = 'CVE-2021-26563';
```

Ce score est ensuite passé à Mistral en Phase 3 pour validation contextuelle.
