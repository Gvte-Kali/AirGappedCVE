---
title: Comparaison de versions
parent: Moteur de corrélation
nav_order: 5
---

# Comparaison de versions NVD
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Problématique

Les CVE NVD décrivent les versions vulnérables sous forme de plages (`before X.X.X`, `from A to B`…). Le moteur doit comparer la version installée sur l'asset avec ces plages pour déterminer si l'asset est réellement affecté.

La difficulté : les formats de versions sont hétérogènes selon les fabricants.

---

## Fonction `normalize_version`

Extrait les composants numériques d'une chaîne de version :

```python
normalize_version("7.2.2-72806")           → [7, 2, 2, 72806]
normalize_version("24H2 Build 26100")       → [24, 2, 26100]
normalize_version("DSM 7.2.2-72806 Update 3") → [7, 2, 2, 72806, 3]
normalize_version("*")                      → []
normalize_version(None)                     → []
```

La comparaison se fait composant par composant. Si un composant est absent, il vaut 0.

---

## Fonction `compare_versions`

```python
compare_versions("7.2.2", "6.2.4")  → 1   (7.2.2 > 6.2.4)
compare_versions("6.2.4", "7.2.2")  → -1  (6.2.4 < 7.2.2)
compare_versions("7.2.2", "7.2.2")  → 0   (égal)
```

---

## Fonction `is_version_affected`

Vérifie si la version asset est dans le range vulnérable d'une CVE.

```python
def is_version_affected(asset_version, cve_version_ranges):
    ...
```

### Cas de prudence → retourne `True`

| Cas | Raison |
|-----|--------|
| `asset_version` est `None` ou `"*"` | Version inconnue → prudence |
| `cve_version_ranges` est vide | Pas de range défini → prudence |

### Traitement de `version_exact = "-"`

La notation `"-"` est utilisée par Microsoft et d'autres éditeurs pour indiquer "version de base" (sans patch spécifique). Son traitement dépend du contexte :

```python
if exact == "-":
    has_real_bounds = any(
        r.get("version_end_excluding") or r.get("version_end_including") or
        r.get("version_start_including") or r.get("version_start_excluding")
        for r in cve_version_ranges
    )
    if has_real_bounds:
        continue   # D'autres ranges ont des bornes → ignorer ce range
    return True    # Aucun autre range → considérer affecté (prudence)
```

**Exemple** — CVE avec plusieurs entrées :
```json
[
  {"product": "diskstation_manager", "version_end_excluding": "6.2.4-25553"},
  {"product": "vs960hd_firmware", "version_exact": "-"},
  {"product": "skynas_firmware", "version_exact": "-"}
]
```
Après filtrage par produit de l'asset (`diskstation_manager`), seul le premier range est évalué — les ranges `-` des autres produits sont ignorés.

### Évaluation d'un range

```python
in_range = True

if version_start_including:
    if asset < start_including: in_range = False   # asset trop ancien

if version_start_excluding:
    if asset <= start_excluding: in_range = False  # asset trop ancien (exclu)

if version_end_including:
    if asset > end_including: in_range = False     # asset plus récent (patché)

if version_end_excluding:
    if asset >= end_excluding: in_range = False    # asset = version fixée (patché)
```

---

## Filtrage par produit avant évaluation

Avant d'appeler `is_version_affected()`, le moteur filtre les ranges par produit de l'asset :

```python
asset_product = asset.get("os_nvd_product") or asset.get("fw_nvd_product") or ""
if asset_product:
    filtered = [r for r in versions_data if r.get("product") == asset_product]
    if filtered:
        versions_data = filtered
```

Cela évite qu'un range `"-"` d'un produit différent (ex: `vs960hd_firmware`) ne fasse matcher une CVE sur un asset DSM.

---

## Formats de versions par fabricant

| Fabricant | Format NVD | Exemple | Notes |
|-----------|-----------|---------|-------|
| Synology DSM | `X.X.X-XXXXX` | `7.2.2-72806` | Le build number est important |
| Synology DSM (avec update) | `X.X.X-XXXXX Update X` | `7.2.2-72806 Update 3` | L'update est un composant numérique |
| Microsoft Windows Server | `XXXX` (année) | `2022` | Comparaison basée sur l'année |
| Microsoft Windows 10/11 | `XXHX Build XXXXX` | `24H2 Build 26100` | H devient un chiffre |
| Fortinet FortiOS | `X.X.X` | `7.4.3` | Format standard |
| Axis AXIS OS | `X.XX.X` | `11.11.7` | Format standard |

{: .warning }
Pour Windows Server, les CVE NVD utilisent souvent des builds `10.0.14393.xxxx` que `normalize_version("2022")` → `[2022]` ne peut pas comparer correctement. C'est pourquoi `use_version_os` est **désactivé** pour le type `serveur` — le filtre produit NVD (`windows_server_2022` vs `windows_server_2016`) suffit.

---

## Cas particuliers

### Version asset contenant le nom de l'OS

```
version_os = "DSM (DiskStation Manager) 7.2.2-72806 Update 3"
normalize_version(...)  → [7, 2, 2, 72806, 3]
```

Le préfixe textuel est ignoré, seuls les chiffres sont extraits. La comparaison fonctionne correctement.

### Asset sans version connue

Si `version_os`, `version_firmware` et `version_bios` sont tous NULL, `is_version_affected()` retourne `True` par prudence — la CVE est retenue en mode `informatif`.

### CVE sans range de versions

Si `versions_affectees` est `[]` ou NULL, `is_version_affected()` retourne `True` — la CVE est retenue.
