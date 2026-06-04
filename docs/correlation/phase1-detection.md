---
title: Phase 1 — Détection brute
parent: Moteur de corrélation
nav_order: 2
---

# 🔍 Phase 1 — Détection brute

**Détection déterministe** - Zéro IA. Charge les assets, détermine le vendor NVD, filtre et insère les corrélations.

---

## 🎯 **Principe**

Seuls les assets **actifs** avec un **fabricant renseigné** (`vendor_id IS NOT NULL`) sont analysés.

---

## 🔄 **5 Étapes**

### 1️⃣ **Chargement des assets**

```sql
SELECT a.*, pv.nvd_vendor, pm.nvd_product, osv.nvd_vendor AS os_nvd_vendor
FROM assets a
JOIN product_vendors pv ON pv.id = a.vendor_id
LEFT JOIN os_versions osv ON osv.id = a.os_version_id
WHERE a.statut_operationnel NOT IN ('hors_service', 'inactif')
  AND a.vendor_id IS NOT NULL
```

---

### 2️⃣ **Détermination du vendor NVD**

Dépend du champ `vendor_source` dans `equipment_types` :

| `vendor_source` | Logique |
|-----------------|---------|
| `os_fk` | Utilise `os_nvd_vendor` (depuis OS normalisé) |
| `fw_fk` | Utilise `fw_nvd_vendor` (depuis firmware) |
| `materiel` | Utilise `product_vendors.nvd_vendor` |
| `detection_auto` | Essaie : os_fk → fw_fk → OS textuel → vendor matériel |

**Fallback** : Détection textuelle via `os_vendor_map` dans `config.yml` :

```yaml
os_vendor_map:
  windows: microsoft
  dsm: synology
  fortios: fortinet
  linux: linux
```

---

### 3️⃣ **Cache CVE**

Pour chaque vendor unique, charge les CVE en mémoire avec filtres :

```sql
SELECT cve_id, cpe_affected, versions_affectees, cvss_v3_score, cvss_v3_vector
FROM cve
WHERE fabricant = %s
  AND cvss_v3_score >= 4.0          -- cvss_min
  AND date_publication >= '2015-01-01'  -- date_min
  AND NOT (cvss_v3_vector LIKE '%AV:N%' AND cvss_v3_score < 7.0)  -- cvss_network_min
LIMIT 2000  -- vendor_cve_limit
```

---

### 4️⃣ **Filtre produit**

**Match exact** (prioritaire) : `cve.produit == asset.os_nvd_product`

**Match fuzzy** (fallback) : 6+ caractères communs entre produit CVE et asset

---

### 5️⃣ **Vérification de version**

Deux chemins :

**Chemin A — Match exact FK** : Vérifie le range de versions via `is_version_affected()` → insère en `type_corr="affirme"`

**Chemin B — Match fuzzy** : Vérifie les tokens de version communs → insère en `type_corr="informatif"`

---

## 📊 **Types de corrélation**

| Type | Description |
|------|-------------|
| `affirme` | Match exact produit + version |
| `informatif` | Match fuzzy (produit ou version) |

---

## 🎛️ **Paramètres clés**

| Paramètre | Défaut | Description |
|-----------|--------|-------------|
| `cvss_min` | 4.0 | Score CVSS minimum |
| `cvss_network_min` | 7.0 | Score min pour CVE réseau (AV:N) |
| `date_min` | 2015-01-01 | Date minimale des CVE |
| `vendor_cve_limit` | 2000 | Limite CVE par vendor |
| `version_min_chars` | 6 | Caractères communs minimum pour match fuzzy |
