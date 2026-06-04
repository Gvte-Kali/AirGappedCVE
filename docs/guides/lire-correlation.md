---
title: Interpréter une corrélation CVE
parent: Guides opérationnels
nav_order: 4
---

# 🔍 Interpréter une corrélation CVE

**Lire et comprendre les informations d'une corrélation**

---

## 📱 **Ouvrir le détail**

Depuis `/ui/vulns`, cliquer sur 🔍 d'une ligne pour ouvrir le modal de détail.

---

## 💻 **Bloc Asset**

```
Nom         : NAS-Synology-01
Type        : nas
OS          : N/A  DSM (DiskStation Manager) 7.2.2-72806 Update 3
Firmware    : N/A
Criticité   : moyen
```

| Champ | Interprétation |
|-------|---------------|
| OS | `N/A` = pas d'`os_version_id` FK / valeur après = `version_os` texte libre |
| Criticité | Influence le score — `élevé`/`critique` = **+1.0** au pré-triage |

---

## 🔬 **Bloc CVE**

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
| `S:C` | Changed scope | Impact au-delà du composant |
| `C:H/I:H/A:H` | High CIA | Impact maximal sur CIA |

---

## 📊 **Bloc Scores**

```
Score contextuel : 8.8
Air-gap          : ⚠️ Exploitable
Type             : Affirmé
Verdict          : patcher
```

### Score contextuel

```
score_pre_triage (calculé localement) + ajustement Mistral = score_contextuel
```

**Exemple** :
- CVSS de base : 8.2
- AV:L → **+0.5** (local, exploitable en air-gap)
- Version affirmée → **+1.0**
- CWE-269 (privilèges) → **+0.5**
- LPE priorité 4 → **+1.5**
- **Score pré-triage : 10.0** (clampé)
- Ajustement Mistral : **-1.0** (contexte prison, accès physique contrôlé)
- **Score final : 9.0 → critique**

### Type de corrélation

| Valeur | Signification |
|--------|---------------|
| `Affirmé` | Version de l'asset dans le range vulnérable → corrélation certaine |
| `Informatif` | Version non confirmée → à valider manuellement |

### Air-gap

| Valeur | Signification |
|--------|---------------|
| ✅ Exploitable | Exploitable malgré l'isolation |
| ❌ Non exploitable | Nécessite Internet |
| ⚠️ Partiellement | Dépend du contexte |

---

## 🎯 **Bloc Verdict**

```
Verdict : patcher
Justification : CVE critique affectant DSM 7.2.2, exploitable localement
Recommandation : Appliquer le patch Synology DSM 7.2.2-72806 Update 4
```

| Verdict | Signification | Action |
|---------|---------------|--------|
| `patcher` | Asset vulnérable, patch nécessaire | **Action immédiate** |
| `informatif` | Pertinent mais pas urgent | Surveiller |
| `faux_positif` | Ne concerne pas cet asset | Ignorer |
| `mitige` | Risque atténué | Valider le contexte |

---

## 📅 **Bloc Historique**

```
Date détection : 2024-06-01 10:30:00
Date analyse : 2024-06-01 10:35:00
Dernière modification : 2024-06-01 14:20:00 (par admin)
```

---

## 🔧 **Bloc Override** (si applicable)

```
Override opérateur : faux_positif
Raison : Équipement en DMZ isolée, pas exposé
Date : 2024-06-01 14:20:00
Utilisateur : admin
```

L'override **prime** sur le verdict automatique.
