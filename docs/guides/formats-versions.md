---
title: Formats de versions
parent: Guides opérationnels
nav_order: 6
---

# Formats de versions par fabricant
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

Ce guide documente le format à utiliser pour la saisie des versions dans le champ **Version exacte** (texte libre) de la page Assets.

## Principe de la comparaison

Le moteur extrait les composants numériques d'une chaîne de version avec `normalize_version()` :

```python
"7.2.2-72806 Update 3"  →  [7, 2, 2, 72806, 3]
"6.2.4-25553"           →  [6, 2, 4, 25553]
```

La comparaison se fait composant par composant. **Plus la version est précise, moins il y aura de faux positifs.**

---

## Référence par fabricant

### Synology — DiskStation Manager (DSM)

| Format | `X.X.X-XXXXX` ou `X.X.X-XXXXX Update X` |
|--------|------------------------------------------|
| Exemple sans update | `7.2.2-72806` |
| Exemple avec update | `7.2.2-72806 Update 3` |
| Où trouver | Panneau de configuration → Informations → Version DSM |
| Note | Le numéro de build (5 chiffres après le tiret) est important pour la comparaison avec les CVE NVD |

### Microsoft — Windows Server

| Format | `XXXX` (année de la version) |
|--------|------------------------------|
| Exemple | `2022`, `2019`, `2016` |
| Où trouver | `winver.exe` → ligne "Version" |
| Note | ⚠️ La comparaison de version est **désactivée** pour les serveurs Windows (`use_version_os = 0`). La corrélation se fait uniquement par produit NVD (`windows_server_2022`). Saisir l'année pour l'affichage uniquement. |

### Microsoft — Windows 10 / 11

| Format | `XXHX Build XXXXX` |
|--------|---------------------|
| Exemple | `24H2 Build 26100` |
| Où trouver | `winver.exe` → ligne complète |
| Note | Le moteur extrait `[24, 2, 26100]` pour la comparaison |

### Fortinet — FortiOS

| Format | `X.X.X` |
|--------|---------|
| Exemple | `7.4.3` |
| Où trouver | CLI : `get system status` → ligne "Version" |

### Axis — AXIS OS (caméras)

| Format | `X.XX.X` |
|--------|---------|
| Exemple | `11.11.7` |
| Où trouver | Interface web → Setup → About → Server → Firmware version |

### Hikvision — Firmware caméra

| Format | `VX.X.X build XXXXXX` |
|--------|------------------------|
| Exemple | `V5.7.15 build 230220` |
| Où trouver | Interface web → Configuration → System → Device Information → Firmware Version |
| Note | Le moteur extrait `[5, 7, 15, 230220]` |

### Raspberry Pi — Raspberry Pi OS

| Format | Numéro de version Debian |
|--------|--------------------------|
| Exemple | `12` (Bookworm), `11` (Bullseye) |
| Où trouver | `cat /etc/os-release` → `VERSION_ID` |

### Cisco — IOS / IOS XE

| Format | `XX.X(X)` ou `XX.X.X` |
|--------|------------------------|
| Exemple IOS | `15.2(7)` |
| Exemple IOS XE | `17.9.3` |
| Où trouver | `show version` → première ligne |

### Linux — Ubuntu Server

| Format | `XX.XX` (LTS) ou `XX.XX.X` |
|--------|---------------------------|
| Exemple | `22.04`, `24.04` |
| Où trouver | `lsb_release -r` ou `cat /etc/os-release` |
| nvd_vendor | `canonical` |
| nvd_product | `ubuntu_linux` |

### Linux — Debian

| Format | Numéro de version majeure |
|--------|--------------------------|
| Exemple | `12` (Bookworm), `11` (Bullseye) |
| Où trouver | `cat /etc/debian_version` |
| nvd_vendor | `debian` |
| nvd_product | `debian_linux` |

---

## Cas particuliers

### Version avec suffixe texte

Si la version contient du texte avant les chiffres (ex: `DSM (DiskStation Manager) 7.2.2-72806`), le moteur ignore le préfixe et extrait uniquement les composants numériques. La saisie `7.2.2-72806` dans le champ libre est donc équivalente — le préfixe du nom OS est ajouté automatiquement.

### Asset sans version connue

Si la version n'est pas disponible lors de l'intervention, laisser le champ vide. La corrélation se fera en mode `informatif` — toutes les CVE du produit remonteront. Compléter la version lors de la prochaine intervention.

### Version inconnue du NVD

Si le moteur compare une version asset avec une plage CVE et que le format est incompatible (ex: version `Custom Build 2024-01-15`), `normalize_version()` extraira `[2024, 1, 15]` — ce qui peut donner des résultats inattendus. Dans ce cas, il est préférable de laisser le champ vide.
