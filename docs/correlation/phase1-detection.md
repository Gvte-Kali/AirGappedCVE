---
title: Phase 1 — Détection brute
parent: Moteur de corrélation
nav_order: 2
---

# Phase 1 — Détection brute
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Principe

La Phase 1 est entièrement déterministe — zéro IA. Elle charge les assets actifs, détermine leur vendor NVD, charge les CVE correspondantes en cache, puis filtre et insère les corrélations.

---

## Étape 1 — Chargement des assets

```sql
SELECT a.*, pv.nvd_vendor, pm.nvd_product,
       osv.nvd_vendor AS os_nvd_vendor,
       osv.nvd_product AS os_nvd_product,
       ...
FROM assets a
JOIN product_vendors pv ON pv.id = a.vendor_id
LEFT JOIN os_versions osv ON osv.id = a.os_version_id
...
WHERE a.statut_operationnel NOT IN ('hors_service', 'inactif')
  AND a.vendor_id IS NOT NULL
```

Seuls les assets **actifs** avec un **fabricant renseigné** sont analysés.

---

## Étape 2 — Détermination du vendor NVD (`get_correlation_vendor`)

Fonction `get_correlation_vendor(asset)` — retourne `(vendor_cve, raison)`.

Le comportement dépend du champ `vendor_source` configuré dans `equipment_types` :

| `vendor_source` | Logique |
|-----------------|---------|
| `os_fk` | Utilise `os_nvd_vendor` (depuis `os_versions` FK). Fallback : détection textuelle depuis `systeme_exploitation` et `version_os` |
| `fw_fk` | Utilise `fw_nvd_vendor` (depuis firmware FK). Fallback : vendor matériel |
| `materiel` | Utilise directement `product_vendors.nvd_vendor` de l'asset |
| `detection_auto` | Essaie dans l'ordre : os_fk → fw_fk → OS textuel → vendor matériel |

Si aucun vendor n'est trouvé, l'asset est **ignoré** pour ce run.

### Détection textuelle de l'OS (`detect_os_vendor`)

Utilisée en fallback quand `os_version_id` est NULL. Elle parcourt `systeme_exploitation` et `version_os` et cherche des mots-clés définis dans `config.yml` :

```yaml
os_vendor_map:
  windows: microsoft
  dsm: synology
  fortios: fortinet
  linux: linux
  # ...
```

---

## Étape 3 — Cache CVE (`build_cve_cache`)

Pour chaque vendor unique identifié, charge les CVE en mémoire avec filtres SQL :

```sql
SELECT cve_id, cpe_affected, versions_affectees,
       cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
       produit, fabricant, date_publication
FROM cve
WHERE fabricant = %s
  AND cvss_v3_score >= 4.0          -- cvss_min
  AND date_publication >= '2015-01-01'  -- date_min
  AND NOT (cvss_v3_vector LIKE '%AV:N%' AND cvss_v3_score < 7.0)  -- cvss_network_min
ORDER BY cvss_v3_score DESC
LIMIT 2000  -- vendor_cve_limit (0 = illimité)
```

Le cache est un dict `{nvd_vendor: [liste CVE]}` chargé **une seule fois** pour tous les assets du même vendor.

---

## Étape 4 — Filtre produit

Avant la boucle CVE, un pré-filtre réduit les candidats :

**Filtre exact FK** (prioritaire) :
```python
# Si l'asset a un os_nvd_product normalisé
cves = [c for c in all_cves if c.get("produit") == asset["os_nvd_product"]]
```

**Filtre fuzzy** (fallback si pas de FK produit) :
```python
# product_matches_asset() : 6+ caractères communs entre le produit CVE
# et nvd_product ou systeme_exploitation de l'asset
cves = [c for c in all_cves if product_matches_asset(c.get("produit"), asset)]
```

---

## Étape 5 — Boucle CVE et vérification de version

Pour chaque CVE candidate, deux chemins :

### Chemin A — Match exact FK (produit NVD = produit asset)

```python
if has_fk and cve_produit in exact_products:
    # Filtrer les ranges par produit de l'asset
    versions_data_filtered = [r for r in versions_data
                               if r.get("product") == asset_product]
    # Vérifier le range
    if not is_version_affected(asset_version_exacte, versions_data_filtered):
        log_reject(...)
        continue
    # Insérer en "affirme"
    insert_correlation(..., type_corr="affirme", passe="vendor_product")
```

### Chemin B — Match fuzzy (tokens de version communs)

```python
# Extraire les tokens de version de l'asset
asset_tokens = get_asset_version_tokens(asset)

# Compter les caractères communs entre tokens asset et tokens CVE
for a_tok in asset_tokens:
    for c_tok in cve_tokens:
        if common_chars_count(a_tok, c_tok) >= version_min_chars:
            version_matched = True

# Vérifier le range de version
if asset_version_exacte and versions_data:
    if not is_version_affected(asset_version_exacte, versions_data):
        log_reject(...)
        continue

# type_corr = "affirme" si version matchée, "informatif" sinon
insert_correlation(..., type_corr=type_corr, passe="vendor_product")
```

---

## Tokens de version (`get_asset_version_tokens`)

Les tokens extraits de l'asset dépendent de la configuration `equipment_types` :

| `use_os_version = 1` | Extrait `os_nvd_product`, tokens de `os_version_label`, nombres de `version_os` |
| `use_version_firmware = 1` | Extrait `fw_nvd_product`, tokens de `fw_version_label`, `version_firmware` |
| `use_version_bios = 1` | Extrait `bios_nvd_product`, tokens de `version_bios` |

Si `equipment_type_id` est NULL, tous les champs sont utilisés par défaut.

---

## Insertion idempotente (`insert_correlation`)

```python
# Vérifie si la corrélation existe déjà
SELECT id, passe_correlation FROM correlations
WHERE asset_id = %s AND cve_id = %s

# Si elle existe avec une passe moins précise → UPDATE
# Si elle existe avec une passe égale ou meilleure → SKIP
# Si elle n'existe pas → INSERT (statut=nouveau)
```

Ordre de précision des passes : `cpe_full` > `vendor_product` > `os_textuel`.

---

## Rejet loggé (`log_reject`)

Toute CVE candidate rejetée est enregistrée dans `correlation_rejects` avec :
- La raison (`version_hors_range`, `cpe_no_match`…)
- La version de l'asset au moment du rejet
- Les plages de versions de la CVE

Cela permet de diagnostiquer pourquoi une CVE attendue n'a pas été corrélée.
