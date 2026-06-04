---
title: Vues SQL
parent: Base de données
nav_order: 3
---

# 👁️ Vues SQL

**Vues pour reporting et Grafana**

---

## 📊 **v_vulnerabilites_tableau**

**Vue principale** - Agrège toutes les données pour le tableau des vulnérabilités.

### Colonnes clés

| Colonne | Source | Description |
|---------|--------|-------------|
| `correlation_id` | correlations | ID de la corrélation |
| `cve_id` | cve | Identifiant CVE |
| `cvss_v3_score` | cve | Score CVSS v3 |
| `cvss_v3_severity` | cve | Sévérité (CRITICAL, HIGH…) |
| `score_final` | correlations | Score après analyse Mistral |
| `statut` | correlations | Statut opérateur |
| `asset_nom` | assets | Nom de l'asset |
| `systeme_exploitation` | assets | OS |
| `version_os` | assets | Version OS |
| `vendor_nom` | product_vendors | Fabricant |
| `model_nom` | product_models | Modèle |
| `site_nom` | sites | Site |
| `client_nom` | clients | Client |
| `date_detection` | correlations | Date de détection |

### Exemple

```sql
-- Top 10 des assets les plus exposés
SELECT asset_nom, client_nom, COUNT(*) AS nb_vulns
FROM v_vulnerabilites_tableau
WHERE statut NOT IN ('faux_positif', 'patche')
GROUP BY asset_id
ORDER BY nb_vulns DESC
LIMIT 10;
```

---

## 💻 **v_assets**

**Assets avec compteur de vulnérabilités**

| Colonne | Description |
|---------|-------------|
| `Asset` | Nom de l'asset |
| `Client` | Client |
| `Site` | Site |
| `Type` | Type d'équipement |
| `OS` | Système d'exploitation |
| `IP` | Adresse IP |
| `Criticite` | Niveau de criticité |
| `Statut` | Statut opérationnel |
| `Vulnerabilites` | Nombre de corrélations actives |

---

## 🏢 **v_clients**

**Clients avec compteurs**

| Colonne | Description |
|---------|-------------|
| `Client` | Nom |
| `Sites` | Nombre de sites |
| `Assets` | Nombre d'assets |
| `Vulnerabilites` | Total vulnérabilités |

---

## 📍 **v_sites**

**Sites avec compteurs**

| Colonne | Description |
|---------|-------------|
| `Site` | Nom |
| `Client` | Client |
| `Assets` | Nombre d'assets |
| `Vulnerabilites` | Total vulnérabilités |

---

## 🏷️ **v_fabricants & v_modeles**

**Référentiels fabricants et modèles** avec compteurs d'utilisation.
