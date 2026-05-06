---
title: Modèles
parent: Référentiels métier
nav_order: 4
---

# Modèles
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Rôle

Les modèles (`product_models`) précisent le produit NVD associé à un asset. Ils permettent au moteur de corrélation de filtrer les CVE par produit exact plutôt que par vendor seul, réduisant les faux positifs.

Un modèle est toujours associé à un fabricant.

---

## Champs

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Fabricant | ✅ | FK → `product_vendors` |
| Nom | ✅ | Nom affiché (ex: `Windows Server 2022`, `DiskStation Manager`) |
| nvd_product | ✅ | Identifiant NVD exact (ex: `windows_server_2022`, `diskstation_manager`) |
| cpe_part | | Type CPE : `a`=application, `o`=OS, `h`=hardware (défaut: `a`) |
| Type produit | | os / firmware / application / hardware |
| CPE base | | CPE complet sans version (ex: `cpe:2.3:o:microsoft:windows_server_2022`) |
| Notes | | Informations libres |

---

## Le champ `nvd_product`

C'est le champ le plus critique. Il doit correspondre exactement à l'identifiant utilisé dans les CVE NVD pour ce produit.

### Règles de format

- Tout en **minuscules**
- Espaces remplacés par des **underscores**
- Caractères spéciaux supprimés ou remplacés

### Exemples

| Produit | `nvd_product` |
|---------|---------------|
| Windows Server 2022 | `windows_server_2022` |
| Windows Server 2016 | `windows_server_2016` |
| Windows 11 | `windows_11` |
| DiskStation Manager | `diskstation_manager` |
| FortiOS | `fortios` |
| AXIS OS | `axis_os` |
| iOS XE | `ios_xe` |

### Comment trouver le bon `nvd_product`

1. Rechercher une CVE connue du produit sur [nvd.nist.gov](https://nvd.nist.gov)
2. Dans la CVE, section **CPE**, lire l'entrée de la forme :
   ```
   cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
                                ↑
                          nvd_product
   ```
3. Ou via la base locale :
   ```sql
   SELECT DISTINCT produit FROM cve
   WHERE fabricant = 'microsoft'
   AND produit LIKE '%server%'
   LIMIT 20;
   ```

---

## Le champ `cpe_part`

Indique la partie CPE du produit :

| Valeur | Signification | Exemples |
|--------|---------------|---------|
| `a` | Application | Logiciels, middlewares |
| `o` | Operating System | Windows Server, DSM, FortiOS |
| `h` | Hardware | Matériel physique |

---

## Le champ `type_produit`

| Valeur | Usage |
|--------|-------|
| `os` | Système d'exploitation — utilisé via `os_version_id` |
| `firmware` | Firmware — utilisé via `fw_version_id` |
| `application` | Application logicielle |
| `hardware` | Matériel (rarement corrélé directement) |

---

## Relation avec `os_versions`

Les modèles (`product_models`) et le référentiel OS (`os_versions`) ont des rôles complémentaires mais distincts :

| | `product_models` | `os_versions` |
|--|-----------------|--------------|
| Rôle | Référentiel produit NVD | Référentiel version NVD |
| Lié à l'asset via | `assets.model_id` | `assets.os_version_id` |
| Contient | nvd_product du produit | nvd_vendor + nvd_product + version |
| Usage corrélation | Filtre produit (boost) | Source principale vendor+produit |

En pratique, pour un NAS Synology :
- `product_vendors` : `synology`
- `product_models` : `diskstation_manager` (optionnel)
- `os_versions` : `synology` / `diskstation_manager` / version `7.1.1` (recommandé)

---

## Création automatique depuis l'interface Assets

Dans le modal de création/édition d'un asset, si le modèle recherché n'existe pas, une option `➕ Créer le modèle "X" pour ce fabricant` apparaît dans le typeahead. Le modèle est créé avec :
- `nvd_product` = nom converti en minuscules avec underscores
- `type_produit` = `hardware` par défaut

Il est conseillé de corriger le `nvd_product` manuellement depuis la page Modèles après création automatique.
