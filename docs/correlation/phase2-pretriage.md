---
title: Phase 2 — Pré-classification
parent: Moteur de corrélation
nav_order: 3
---

# ⚖️ Phase 2 — Pré-classification

**Scoring déterministe** - Calculé à l'insertion (Phase 1). Produit `score_pre_triage` (0-10) et `priorite_pre_triage` **sans IA**.

---

## 🎯 **Principe**

- Score de **base** = CVSS v3 (0.0 à 10.0)
- **Ajustements** basés sur le contexte air-gap et l'asset
- Mistral en Phase 3 **ajuste** ce score (ne le recalcule pas)

---

## 📊 **Règles de scoring**

### 1️⃣ **Base**
```
score = cvss_v3_score
```

---

### 2️⃣ **Ajustement Air-Gap** (Vecteur d'attaque)

| Vecteur | Ajustement | Raison |
|---------|------------|--------|
| `AV:N` (réseau) | **-3.0** | Moins exploitable en air-gap |
| `AV:L` (local) | **+0.5** | Exploitable en local |
| `AV:P` (physique) | **+0.5** | Exploitable physiquement |

---

### 3️⃣ **Confirmation de version**

| Match | Ajustement |
|-------|------------|
| `affirme` (version confirmée vulnérable) | **+1.0** |
| `informatif` (version inconnue) | 0 |

---

### 4️⃣ **Type de produit CVE**

| Type | Ajustement |
|------|------------|
| OS, firmware, BIOS, kernel, system... | **+0.5** |
| library, lib, plugin, module, driver | **-1.0** |

---

### 5️⃣ **Criticité de l'asset**

| Niveau | Ajustement |
|--------|------------|
| critique / élevé | **+1.0** |
| moyen / faible | 0 |

---

### 6️⃣ **CWE pertinents en Air-Gap**

Bonus **+0.5** pour les CWE critiques :

- CWE-269 (Privilege Management)
- CWE-78 (OS Command Injection)
- CWE-264 (Permissions, Privileges)
- CWE-732 (Permission Assignment)
- CWE-426 (Untrusted Search Path)
- CWE-77 (Command Injection)
- CWE-787 (Out-of-bounds Write)
- CWE-119 (Buffer Overflow)

---

### 7️⃣ **Type d'attaque** (depuis `vuln_types.yml`)

| Priorité | Catégories | Ajustement |
|----------|------------|------------|
| 4 | RCE, MemCorrupt, CmdInjection, FirmwareBIOS | **+1.5** |
| 3 | LPE, DoS, AuthBypass, FileWrite | **+0.5** |
| 2 | Unknown | 0 |
| 1 | InfoDisc, WeakCrypto, Misconfiguration | **-1.0** |
| 0 | XSS, CSRF, SSRF, OpenRedirect | **-5.0** |

---

## 📈 **Résultat**

```python
score_final = base + ajustements
priorite = calculer_priorite(score_final)
```

**Plage** : 0.0 à 10.0+ (peut dépasser 10 avec les bonus)
