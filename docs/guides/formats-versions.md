---
title: Formats de versions
parent: Guides opérationnels
nav_order: 6
---

# 📊 Formats de versions par fabricant

**Format à utiliser pour la saisie des versions dans le champ `Version exacte` (texte libre)**

---

## 🎯 **Principe de comparaison**

Le moteur extrait les composants numériques avec `normalize_version()` :

```python
"7.2.2-72806 Update 3"  →  [7, 2, 2, 72806, 3]
"6.2.4-25553"           →  [6, 2, 4, 25553]
```

**Plus la version est précise, moins il y aura de faux positifs.**

---

## 📋 **Référence par fabricant**

### Synology — DiskStation Manager (DSM)

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `X.X.X-XXXXX` | `7.2.2-72806` | Panneau de configuration → Informations |
| `X.X.X-XXXXX Update X` | `7.2.2-72806 Update 3` | Panneau de configuration → Informations |

⚠️ **Le numéro de build (5 chiffres) est important** pour la comparaison avec les CVE NVD.

---

### Microsoft — Windows Server

| Format | Exemple | Où trouver | Note |
|--------|---------|------------|------|
| `XXXX` | `2022`, `2019`, `2016` | `winver.exe` → ligne "Version" | ⚠️ Comparaison de version **désactivée** (`use_version_os = 0`). Corrélation par produit NVD uniquement (`windows_server_2022`). Saisir l'année pour l'affichage. |

---

### Microsoft — Windows 10 / 11

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `XXHX Build XXXXX` | `24H2 Build 26100` | `winver.exe` → ligne complète |

Le moteur extrait `[24, 2, 26100]` pour la comparaison.

---

### Fortinet — FortiOS

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `X.X.X` | `7.4.3` | CLI : `get system status` → ligne "Version" |

---

### Axis — AXIS OS (caméras)

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `X.XX.X` | `11.11.7` | Interface web → Setup → About → Server → Firmware version |

---

### Hikvision — Firmware caméra

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `VX.X.X build XXXXXX` | `V5.7.15 build 230220` | Interface web → Configuration → System → Device Information → Firmware Version |

---

### ZKTeco — Lecteurs biométriques

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `X.X.X` | `9.5.3` | Interface web → System → Device Info → Firmware Version |

---

### Ubuntu / Debian

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `XX.XX` | `22.04`, `20.04` | `lsb_release -a` → Distrib Description |
| `XX.XX.X` | `22.04.3` | `lsb_release -a` → Distrib Release |

---

### Cisco — IOS / NX-OS

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `XX.X(X)X` | `15.2(4)E6` | CLI : `show version` → Cisco IOS Software |
| `X.X(X)X` | `9.3(9)A` | CLI : `show version` → NX-OS |

---

### VMware — ESXi

| Format | Exemple | Où trouver |
|--------|---------|------------|
| `X.X.X-XXXXX` | `7.0.3-20328358` | CLI : `vmware -vl` → Version |
| `X.X.X XXXXX` | `7.0.3 20328358` | Interface web → Host → Summary |

---

## 💡 **Bonnes pratiques**

- ✅ **Saisir la version complète** (inclure build numbers si disponibles)
- ✅ **Utiliser le format du fabricant** (ne pas modifier)
- ✅ **Vérifier sur le site du fabricant** si incertain
- ❌ **Ne pas inventer de format**
- ❌ **Ne pas omettre les numéros de build** (sauf pour Windows Server)
