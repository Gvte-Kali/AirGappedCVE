---
title: Contrainte Air-Gap
parent: Moteur de corrélation
nav_order: 6
---

# 🔒 Contrainte Air-Gap — Impact sur le scoring

**Environnements clients physiquement isolés d'Internet** - Impact à 2 niveaux.

---

## 🎯 **Principe**

1. **Phase 2** : Ajustement automatique du score selon le vecteur d'attaque CVSS
2. **Phase 3** : Mistral indique si la CVE est exploitable malgré l'isolation

---

## 📊 **Vecteur d'attaque CVSS**

| Vecteur | Signification | Impact Air-Gap |
|--------|---------------|----------------|
| `AV:N` | Network (réseau) | ⬇ **Moins critique** — Internet inaccessible |
| `AV:A` | Adjacent (réseau local) | ⚠ Partiellement applicable |
| `AV:L` | Local (session locale) | ⬆ **Pleinement applicable** |
| `AV:P` | Physical (accès physique) | ⬆ **Pleinement applicable** |

---

## ⚖️ **Ajustements Phase 2**

```python
if "AV:N" in vector:
    score -= 3.0   # Pénalité réseau

if "AV:L" in vector or "AV:P" in vector:
    score += 0.5   # Bonus local/physique
```

### Exemple

| CVE | CVSS | Vecteur | Score brut | Ajustement | Score final |
|-----|------|---------|------------|------------|-------------|
| CVE-A | 9.8 | AV:N | 9.8 | -3.0 | **6.8** |
| CVE-B | 7.8 | AV:L | 7.8 | +0.5 | **8.3** |
| CVE-C | 8.8 | AV:A | 8.8 | 0 | **8.8** |

---

## 🗑️ **Filtre CVE réseau basse sévérité**

Les CVE réseau sous `cvss_network_min` (défaut: 7.0) sont **exclues du cache** :

```sql
WHERE NOT (cvss_v3_vector LIKE '%AV:N%' AND cvss_v3_score < 7.0)
```

**Résultat** : Les CVE réseau MEDIUM (4.0-6.9) sont ignorées (quasi-inexploitables en air-gap).

---

## 🎯 **CWE pertinents en Air-Gap**

Bonus **+0.5** pour les CWE critiques en environnement isolé :

- CWE-269 (Privilege Management)
- CWE-78 (OS Command Injection)
- CWE-264 (Permissions, Privileges)
- CWE-732 (Permission Assignment)
- CWE-426 (Untrusted Search Path)
- CWE-77 (Command Injection)
- CWE-787 (Out-of-bounds Write)
- CWE-119 (Buffer Overflow)
