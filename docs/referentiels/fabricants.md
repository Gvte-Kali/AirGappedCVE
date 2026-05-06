---
title: Fabricants
parent: Référentiels métier
nav_order: 3
---

# Fabricants
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Rôle

Les fabricants (`product_vendors`) sont le point d'entrée du moteur de corrélation CVE. Pour chaque asset, le moteur recherche les CVE correspondant au `nvd_vendor` du fabricant renseigné.

Un fabricant mal configuré (mauvais `nvd_vendor`) = **aucune CVE trouvée** pour ses assets.

---

## Champs

| Champ | Obligatoire | Description |
|-------|-------------|-------------|
| Nom | ✅ | Nom affiché dans l'interface (ex: `Microsoft`, `Synology`) |
| nvd_vendor | ✅ | Identifiant NVD exact, en minuscules (ex: `microsoft`, `synology`) |
| Notes | | Informations libres |

---

## Trouver le bon `nvd_vendor`

L'identifiant NVD doit correspondre exactement à ce qu'utilise le NVD dans ses CVE. La méthode la plus fiable :

### Méthode 1 — Recherche NVD directe

1. Aller sur [nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
2. Chercher une CVE connue du fabricant (ex: `Synology DSM`)
3. Ouvrir une CVE et regarder le champ `Vendor` dans la section CPE
4. Copier la valeur exacte en minuscules

### Méthode 2 — Requête en base

Si des CVE ont déjà été importées pour ce fabricant :

```sql
SELECT DISTINCT fabricant
FROM cve
WHERE fabricant LIKE '%synology%';
-- Résultat : "synology"
```

### Méthode 3 — URL NVD CPE

```
https://nvd.nist.gov/products/cpe/search?keyword=synology
```

---

## Fabricants courants et leurs identifiants NVD

| Fabricant | `nvd_vendor` |
|-----------|-------------|
| Microsoft | `microsoft` |
| Synology | `synology` |
| Fortinet | `fortinet` |
| Cisco | `cisco` |
| Dell | `dell` |
| HP / HPE | `hp` ou `hpe` |
| Lenovo | `lenovo` |
| VMware | `vmware` |
| Hikvision | `hikvision` |
| Axis | `axis` |
| ZKTeco | `zkteco` |
| Raspberry Pi Foundation | `raspberrypi` |
| Canonical (Ubuntu) | `canonical` |
| Red Hat | `redhat` |
| Debian | `debian` |

{: .warning }
Attention aux variations : `hp` vs `hewlett-packard`, `redhat` vs `red_hat`. Vérifier toujours sur le NVD avant de créer l'entrée.

---

## Relation avec les modèles

Chaque fabricant peut avoir plusieurs modèles (`product_models`). Les modèles précisent le `nvd_product` utilisé pour affiner la corrélation.

```
Microsoft (nvd_vendor: "microsoft")
  ├── Windows Server 2022 (nvd_product: "windows_server_2022")
  ├── Windows Server 2019 (nvd_product: "windows_server_2019")
  └── Windows 11 (nvd_product: "windows_11")

Synology (nvd_vendor: "synology")
  └── DiskStation Manager (nvd_product: "diskstation_manager")
```

---

## Cas particulier : détection automatique du vendor

Pour les assets dont le vendor NVD dépend de l'OS plutôt que du matériel (PC, serveurs, laptops), le moteur peut détecter automatiquement le vendor depuis le champ `systeme_exploitation` grâce au mapping `os_vendor_map` dans `config.yml` :

```yaml
os_vendor_map:
  windows: microsoft
  dsm: synology
  fortios: fortinet
```

Cela permet de corréler un serveur Windows avec les CVE Microsoft même si le fabricant matériel est Dell — ce qui serait incorrect pour la corrélation OS.

Ce comportement est configuré via `vendor_source` dans `equipment_types`.
