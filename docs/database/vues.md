---
title: Vues SQL
parent: Base de données
nav_order: 3
---

# Vues SQL
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

La base contient 6 vues SQL. Elles sont principalement destinées à Grafana (à venir) et peuvent aussi être utilisées pour des requêtes de reporting rapides.

---

## v_vulnerabilites_tableau

Vue principale du système. Agrège toutes les données nécessaires à l'affichage du tableau des vulnérabilités.

### Colonnes exposées

| Colonne | Source | Description |
|---------|--------|-------------|
| `correlation_id` | `correlations.id` | Identifiant de la corrélation |
| `cve_id` | `correlations.cve_id` | Identifiant CVE |
| `cvss_v3_score` | `cve.cvss_v3_score` | Score CVSS v3 |
| `cvss_v3_severity` | `cve.cvss_v3_severity` | Sévérité CVSS (CRITICAL, HIGH…) |
| `score_pre_triage` | `correlations.score_pre_triage` | Score avant Mistral |
| `priorite_pre_triage` | `correlations.priorite_pre_triage` | Priorité avant Mistral |
| `score_final` | `correlations.score_contextuel` | Score final après Mistral |
| `priorite_finale` | `correlations.priorite` | Priorité finale |
| `statut` | `correlations.statut` | Statut opérateur |
| `type_correlation` | `correlations.type_correlation` | affirme / informatif |
| `passe_correlation` | `correlations.passe_correlation` | Méthode de match |
| `exploitable_air_gap` | `correlations.exploitable_air_gap` | Exploitable malgré l'isolation |
| `decision_patch` | `COALESCE(override_utilisateur, statut)` | Décision finale (override prime sur statut) |
| `asset_id` | `assets.id` | ID de l'asset |
| `asset_nom` | `assets.nom_interne` | Nom de l'asset |
| `type_equipement` | `assets.type_equipement` | Type d'équipement |
| `systeme_exploitation` | `assets.systeme_exploitation` | OS texte libre |
| `version_os` | `assets.version_os` | Version OS texte libre |
| `version_firmware` | `assets.version_firmware` | Version firmware texte libre |
| `niveau_criticite` | `assets.niveau_criticite` | Criticité de l'asset |
| `vendor_nom` | `product_vendors.nom` | Nom affiché du fabricant |
| `nvd_vendor` | `product_vendors.nvd_vendor` | Identifiant NVD du fabricant |
| `model_nom` | `product_models.nom` | Nom du modèle |
| `site_nom` | `sites.nom` | Nom du site |
| `client_nom` | `clients.nom` | Nom du client |
| `date_detection` | `correlations.date_detection` | Date de détection |
| `date_analyse` | `correlations.date_analyse` | Date d'analyse Mistral |
| `date_resolution` | `correlations.date_resolution` | Date de résolution |

### Logique notable

La colonne `decision_patch` utilise `COALESCE(override_utilisateur, statut)` — si l'opérateur a défini un override, c'est lui qui prime ; sinon c'est le statut automatique. Cela permet à Grafana d'afficher la décision finale sans logique applicative.

### Exemple de requête

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

## v_assets

Vue synthétique des assets avec leur nombre de vulnérabilités actives.

| Colonne | Description |
|---------|-------------|
| `Asset` | Nom interne de l'asset |
| `Client` | Nom du client |
| `Site` | Nom du site |
| `Type` | Type d'équipement |
| `OS` | Système d'exploitation |
| `VersionOS` | Version OS |
| `IP` | Adresse IP |
| `Criticite` | Niveau de criticité |
| `Statut` | Statut opérationnel |
| `Vulnerabilites` | Nombre de corrélations actives (hors faux_positif) |

---

## v_clients

Vue synthétique des clients avec compteurs.

| Colonne | Description |
|---------|-------------|
| `Client` | Nom du client |
| `Contact` | Nom du contact principal |
| `Email` | Email du contact |
| `Telephone` | Téléphone du contact |
| `Sites` | Nombre de sites |
| `Assets` | Nombre total d'assets |

---

## v_sites

Vue synthétique des sites avec compteurs.

| Colonne | Description |
|---------|-------------|
| `Site` | Nom du site |
| `Client` | Nom du client |
| `Ville` | Ville |
| `CP` | Code postal |
| `Pays` | Pays |
| `ContactLocal` | Contact sur site |
| `Email` | Email contact local |
| `Assets` | Nombre d'assets sur ce site |

---

## v_fabricants

Vue synthétique des fabricants avec compteurs.

| Colonne | Description |
|---------|-------------|
| `Fabricant` | Nom affiché |
| `IdentifiantNVD` | `nvd_vendor` exact |
| `Modeles` | Nombre de modèles enregistrés |
| `Assets` | Nombre d'assets utilisant ce fabricant |

---

## v_modeles

Vue synthétique des modèles avec leurs informations NVD.

| Colonne | Description |
|---------|-------------|
| `Modele` | Nom affiché |
| `IdentifiantNVD` | `nvd_product` exact |
| `Type` | Type produit (os, firmware, hardware…) |
| `CPEPart` | Partie CPE (a, o, h) |
| `CPEBase` | CPE de base complet |
| `Fabricant` | Nom du fabricant |
| `Assets` | Nombre d'assets utilisant ce modèle |

---

## Utilisation des vues

```sql
-- Connexion MariaDB
mariadb -u votre_utilisateur -p asset_vuln_manager

-- Lister toutes les vulnérabilités critiques non résolues
SELECT cve_id, asset_nom, client_nom, score_final
FROM v_vulnerabilites_tableau
WHERE priorite_finale = 'critique'
  AND statut NOT IN ('patche', 'faux_positif')
ORDER BY score_final DESC;

-- Résumé par client
SELECT client_nom, COUNT(*) AS vulns_actives
FROM v_vulnerabilites_tableau
WHERE statut NOT IN ('patche', 'faux_positif')
GROUP BY client_nom
ORDER BY vulns_actives DESC;
```
