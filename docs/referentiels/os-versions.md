---
title: OS & Versions
parent: Référentiels métier
nav_order: 5
---

# OS & Versions
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Rôle

Le référentiel `os_versions` contient les OS, firmwares et BIOS normalisés selon la nomenclature NVD. C'est la source la plus précise pour la corrélation CVE — quand un asset y est lié, le moteur connaît exactement le `nvd_vendor` et le `nvd_product` à utiliser.

Un asset lié à une entrée de ce référentiel bénéficie d'une corrélation en mode **affirme** (version confirmée).

---

## Champs

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Nom OS | ✅ | Nom affiché dans l'interface (ex: `Windows Server`, `DSM (DiskStation Manager)`) |
| Version | | Version affichée (ex: `2022`, `7.1.1`, `24H2`) |
| nvd_vendor | ✅ | Vendor NVD exact (ex: `microsoft`, `synology`) |
| nvd_product | ✅ | Produit NVD exact (ex: `windows_server_2022`, `diskstation_manager`) |
| Type produit | | `os` / `firmware` / `bios` |

Contrainte d'unicité : `(nvd_vendor, nvd_product)` — un produit NVD ne peut avoir qu'une seule entrée.

{: .note }
**Bloc F (à venir)** — deux colonnes seront ajoutées : `format_version` (format attendu de la version, ex: `X.X.X-XXXXX`) et `ou_trouver` (où trouver la version sur l'équipement, ex: `Panneau de configuration → Informations`). Ces colonnes alimenteront un guide de saisie contextuel dans la page Assets.

---

## Types produit

| Type | Usage | FK dans assets |
|------|-------|----------------|
| `os` | Système d'exploitation principal | `os_version_id` |
| `firmware` | Firmware d'équipement réseau | `fw_version_id` |
| `bios` | BIOS/UEFI de serveur ou PC | `bios_version_id` |

---

## Entrées existantes — Exemples

### OS (type = os)

| Nom OS | Version | nvd_vendor | nvd_product |
|--------|---------|------------|-------------|
| Windows Server | 2022 | `microsoft` | `windows_server_2022` |
| Windows Server | 2019 | `microsoft` | `windows_server_2019` |
| Windows Server | 2016 | `microsoft` | `windows_server_2016` |
| Windows 11 | 24H2 | `microsoft` | `windows_11_24h2` |
| DSM (DiskStation Manager) | 7.1.1 | `synology` | `diskstation_manager` |
| DSM (DiskStation Manager) | 7.2.2 | `synology` | `diskstation_manager` |

{: .note }
Pour Synology DSM, plusieurs versions peuvent pointer vers le même `nvd_product` (`diskstation_manager`) car le NVD identifie le produit sans la version dans le champ `produit`. La version est dans `versions_affectees`.

### Firmware (type = firmware)

| Nom OS | Version | nvd_vendor | nvd_product |
|--------|---------|------------|-------------|
| FortiOS | 7.4.3 | `fortinet` | `fortios` |
| AXIS OS | 11.11.7 | `axis` | `axis_os` |

### BIOS (type = bios)

| Nom OS | Version | nvd_vendor | nvd_product |
|--------|---------|------------|-------------|
| AMI BIOS | 5.x | `ami` | `aptio_v` |

---

## Formats de versions par fabricant

Le moteur extrait les composants numériques de la version pour les comparer avec les plages CVE. Il est important de saisir la version dans un format que `normalize_version()` peut interpréter correctement.

| Fabricant | OS/Produit | Format recommandé | Exemple | Où trouver |
|-----------|-----------|-------------------|---------|------------|
| Synology | DSM | `X.X.X-XXXXX` | `7.2.2-72806` | Panneau de config → Informations |
| Synology | DSM (avec update) | `X.X.X-XXXXX Update X` | `7.2.2-72806 Update 3` | Panneau de config → Informations |
| Microsoft | Windows Server | `XXXX` (année) | `2022` | `winver.exe` |
| Microsoft | Windows 10/11 | `XXHX Build XXXXX` | `24H2 Build 26100` | `winver.exe` |
| Fortinet | FortiOS | `X.X.X` | `7.4.3` | CLI : `get system status` |
| Axis | AXIS OS | `X.XX.X` | `11.11.7` | Interface web → About |
| Hikvision | Firmware | `VX.X.X build XXXXXX` | `V5.7.15 build 230220` | Interface web → System |
| Raspberry Pi | Raspberry Pi OS | Numéro de version Debian | `12` | `cat /etc/os-release` |

{: .warning }
Pour Windows Server, le moteur de corrélation n'utilise **pas** la version texte pour comparer avec les builds NVD (`10.0.14393.xxxx`). La corrélation se fait uniquement par produit NVD (`windows_server_2022`). La colonne `use_version_os` est désactivée pour le type `serveur` dans `equipment_types`.

---

## Version libre vs version normalisée

Si la version exacte de l'équipement n'est pas dans ce référentiel, deux options :

**Option 1 — Ajouter l'entrée au référentiel** (recommandé pour les équipements récurrents)
Créer une nouvelle entrée avec la version exacte. Le moteur pourra faire une corrélation `affirme`.

**Option 2 — Saisie en version libre** (pour les équipements ponctuels)
Dans la page Assets, si aucune version normalisée n'est sélectionnée, un champ texte libre apparaît. La valeur est stockée dans `version_os`. La corrélation sera en mode `informatif`.
