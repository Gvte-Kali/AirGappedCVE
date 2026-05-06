---
title: vuln_types.yml
parent: Moteur de corrélation
nav_order: 8
---

# vuln_types.yml — Classification des types d'attaque
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Rôle

Le fichier `scripts/vuln_types.yml` classifie les CVE par type d'attaque. Cette classification est utilisée dans le pré-triage (Phase 2) pour ajuster le score et dans l'analyse Mistral pour mieux contextualiser la CVE.

Elle permet aussi d'**exclure automatiquement** de l'analyse Mistral certains types de vulnérabilités non pertinents en air-gap (XSS, CSRF…), économisant des appels API.

---

## Format

```yaml
types:
  NomDuType:
    cwe_ids:
      - "CWE-XXX"
      - "CWE-YYY"
    keywords:
      - "mot-clé-dans-description"
      - "autre-mot-clé"
    priorite: 0-4        # impact sur le score pré-triage
    passer_mistral: true/false  # envoyer à Mistral ?
```

---

## Priorités et leur impact sur le score

| Valeur | Catégories typiques | Ajustement score |
|--------|--------------------|--------------------|
| `4` | RCE, corruption mémoire, injection commande, firmware | **+1.5** |
| `3` | Élévation de privilèges, DoS, bypass auth, écriture fichier | **+0.5** |
| `2` | Défaut / Unknown | 0 |
| `1` | Divulgation d'info, crypto faible, mauvaise config | **-1.0** |
| `0` | XSS, CSRF, SSRF, open redirect | **-5.0** |

---

## Classification par CWE vs keywords

Le moteur cherche d'abord une correspondance par **CWE** (plus précis), puis par **keywords** dans la description de la CVE (fallback).

```python
# Priorité : CWE > keywords > Unknown
for cwe in cwes:
    if cwe in CWE_TO_TYPE:
        return CWE_TO_TYPE[cwe]  # match CWE

for keyword, type_id in KEYWORDS_TO_TYPE:
    if keyword in description.lower():
        return type_id  # match keyword

return "Unknown"  # fallback
```

---

## Types standards et leurs CWE

### RCE — Remote Code Execution (priorité 4)
```yaml
RCE:
  cwe_ids: ["CWE-94", "CWE-78", "CWE-77", "CWE-502", "CWE-913"]
  keywords: ["remote code execution", "arbitrary code", "rce"]
  priorite: 4
  passer_mistral: true
```

### MemCorrupt — Corruption mémoire (priorité 4)
```yaml
MemCorrupt:
  cwe_ids: ["CWE-787", "CWE-119", "CWE-125", "CWE-416", "CWE-122"]
  keywords: ["buffer overflow", "out-of-bounds", "heap overflow", "use after free"]
  priorite: 4
  passer_mistral: true
```

### FirmwareBIOS — Firmware/BIOS (priorité 4)
```yaml
FirmwareBIOS:
  cwe_ids: ["CWE-1277", "CWE-276"]
  keywords: ["firmware", "bios", "uefi", "bootloader"]
  priorite: 4
  passer_mistral: true
```

### LPE — Local Privilege Escalation (priorité 3)
```yaml
LPE:
  cwe_ids: ["CWE-269", "CWE-264", "CWE-732", "CWE-426", "CWE-427"]
  keywords: ["privilege escalation", "local privilege", "elevation of privilege"]
  priorite: 3
  passer_mistral: true
```

### AuthBypass — Bypass authentification (priorité 3)
```yaml
AuthBypass:
  cwe_ids: ["CWE-287", "CWE-306", "CWE-798", "CWE-259"]
  keywords: ["authentication bypass", "unauthorized access", "improper authentication"]
  priorite: 3
  passer_mistral: true
```

### DoS — Déni de service (priorité 3)
```yaml
DoS:
  cwe_ids: ["CWE-400", "CWE-770", "CWE-703"]
  keywords: ["denial of service", "dos", "crash", "unavailable"]
  priorite: 3
  passer_mistral: true
```

### InfoDisc — Divulgation d'information (priorité 1)
```yaml
InfoDisc:
  cwe_ids: ["CWE-200", "CWE-201", "CWE-203", "CWE-359"]
  keywords: ["information disclosure", "sensitive information", "data leak"]
  priorite: 1
  passer_mistral: true
```

### XSS — Cross-Site Scripting (priorité 0)
```yaml
XSS:
  cwe_ids: ["CWE-79", "CWE-80"]
  keywords: ["cross-site scripting", "xss"]
  priorite: 0
  passer_mistral: false  # Non pertinent en air-gap
```

### CSRF — Cross-Site Request Forgery (priorité 0)
```yaml
CSRF:
  cwe_ids: ["CWE-352"]
  keywords: ["cross-site request forgery", "csrf"]
  priorite: 0
  passer_mistral: false  # Non pertinent en air-gap
```

---

## Ajouter un nouveau type

1. Identifier le CWE correspondant sur [cwe.mitre.org](https://cwe.mitre.org)
2. Choisir les keywords présents dans les descriptions CVE typiques
3. Définir la priorité selon l'impact en contexte air-gap
4. Décider si Mistral doit analyser ce type (`passer_mistral`)

```yaml
NouveauType:
  cwe_ids:
    - "CWE-XXX"
  keywords:
    - "mot-clé-typique"
  priorite: 3
  passer_mistral: true
```

{: .note }
Le fichier est chargé au **démarrage du script**. Toute modification est prise en compte au prochain run de corrélation.

---

## Impact sur `passer_mistral`

Le champ `passer_mistral` dans la table `correlations` est défini à l'insertion selon la classification :

- `passer_mistral = 1` → la corrélation sera envoyée à Mistral en Phase 3
- `passer_mistral = 0` → la corrélation reste en `statut=nouveau` sans analyse Mistral

Les types avec `passer_mistral: false` (XSS, CSRF, SSRF, OpenRedirect) sont des vulnérabilités web qui ne s'appliquent pas aux systèmes air-gappés. Les exclure de Mistral évite des appels API inutiles et du bruit dans les résultats.
