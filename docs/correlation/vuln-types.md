---
title: vuln_types.yml
parent: Moteur de corrélation
nav_order: 8
---

# 🏷️ vuln_types.yml — Classification des types d'attaque

**Classifie les CVE par type** - Utilisé pour ajuster le score (Phase 2) et exclure certains types de l'analyse Mistral.

---

## 🎯 **Rôle**

- Ajustement du score en **Phase 2**
- Exclusion automatique de l'analyse Mistral pour les types non pertinents en air-gap (XSS, CSRF…)
- Meilleure contextualisation pour Mistral

---

## 📝 **Format**

```yaml
types:
  NomDuType:
    cwe_ids:
      - "CWE-XXX"
      - "CWE-YYY"
    keywords:
      - "mot-clé-dans-description"
      - "autre-mot-clé"
    priorite: 0-4        # Impact sur le score
    passer_mistral: true/false  # Envoyer à Mistral ?
```

---

## ⚖️ **Priorités et ajustements**

| Priorité | Catégories typiques | Ajustement score |
|----------|--------------------|-----------------|
| 4 | RCE, corruption mémoire, injection commande, firmware | **+1.5** |
| 3 | Élévation de privilèges, DoS, bypass auth, écriture fichier | **+0.5** |
| 2 | Défaut / Unknown | 0 |
| 1 | Divulgation d'info, crypto faible, mauvaise config | **-1.0** |
| 0 | XSS, CSRF, SSRF, open redirect | **-5.0** |

---

## 🔍 **Matching**

1. **Par CWE** (prioritaire) : Correspondance exacte avec les CWE de la CVE
2. **Par keywords** (fallback) : Recherche dans la description de la CVE
3. **Unknown** (défaut) : Si aucun match

---

## 📊 **Types standards**

### Priorité 4 (Ajustement +1.5)

| Type | CWE principaux | Keywords |
|------|----------------|----------|
| **RCE** | CWE-94, CWE-78, CWE-77, CWE-502 | remote code execution, arbitrary code |
| **MemCorrupt** | CWE-787, CWE-119, CWE-125 | buffer overflow, out-of-bounds, use after free |
| **FirmwareBIOS** | CWE-1277, CWE-276 | firmware, bios, uefi, bootloader |
| **CmdInjection** | CWE-78, CWE-77 | command injection, shell injection |

### Priorité 3 (Ajustement +0.5)

| Type | CWE principaux | Keywords |
|------|----------------|----------|
| **LPE** | CWE-269, CWE-264 | privilege escalation, elevation |
| **DoS** | CWE-400, CWE-770 | denial of service, crash |
| **AuthBypass** | CWE-287, CWE-290 | authentication bypass, auth bypass |
| **FileWrite** | CWE-269, CWE-732 | arbitrary file write, file upload |

### Priorité 1 (Ajustement -1.0)

| Type | CWE principaux | Keywords |
|------|----------------|----------|
| **InfoDisc** | CWE-200, CWE-530 | information disclosure, data leak |
| **WeakCrypto** | CWE-327, CWE-326 | weak encryption, hardcoded password |
| **Misconfiguration** | CWE-16, CWE-639 | misconfiguration, default config |

### Priorité 0 (Ajustement -5.0, `passer_mistral: false`)

| Type | CWE principaux | Keywords |
|------|----------------|----------|
| **XSS** | CWE-79 | cross-site scripting |
| **CSRF** | CWE-352 | cross-site request forgery |
| **SSRF** | CWE-918 | server-side request forgery |
| **OpenRedirect** | CWE-601 | open redirect |

---

## 💡 **Personnalisation**

Pour ajouter un nouveau type :

```yaml
types:
  MonNouveauType:
    cwe_ids: ["CWE-XXX"]
    keywords: ["mon-mot-clé"]
    priorite: 3
    passer_mistral: true
```
