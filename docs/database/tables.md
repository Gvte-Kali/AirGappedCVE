---
title: Tables
parent: Base de données
nav_order: 2
---

# 📋 Tables principales

**Description concise des tables les plus importantes**

---

## 🏢 **Clients & Sites**

### clients

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `nom` | varchar | Nom de l'organisation |
| `contact_nom` | varchar | Contact principal |
| `contact_email` | varchar | Email du contact |
| `contact_telephone` | varchar | Téléphone |
| `adresse` | text | Adresse postale |
| `notes` | text | Notes libres |
| `actif` | bool | 1 = actif, 0 = archivé |

### sites

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `client_id` | int FK | → clients.id (CASCADE) |
| `nom` | varchar | Nom du site |
| `adresse` | text | Adresse |
| `ville` | varchar | Ville |
| `code_postal` | varchar | Code postal |
| `pays` | varchar | Pays |
| `actif` | bool | 1 = actif |

---

## 💻 **Assets (Équipements)**

**Table centrale du système**

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `site_id` | int FK | → sites.id (CASCADE) |
| `vendor_id` | int FK | → product_vendors.id (SET NULL) |
| `model_id` | int FK | → product_models.id (SET NULL) |
| `os_version_id` | int FK | → os_versions.id (SET NULL) |
| `fw_version_id` | int FK | → os_versions.id (SET NULL) |
| `bios_version_id` | int FK | → os_versions.id (SET NULL) |
| `equipment_type_id` | int FK | → equipment_types.id (SET NULL) |
| `nom_interne` | varchar | Nom d'inventaire |
| `numero_serie` | varchar | Numéro de série |
| `adresse_ip` | varchar | Adresse IP |
| `adresse_mac` | varchar | Adresse MAC |
| `hostname` | varchar | Nom d'hôte |
| `systeme_exploitation` | varchar | OS (texte libre) |
| `version_os` | varchar | Version OS (texte libre) |
| `niveau_criticite` | enum | faible/moyen/eleve/critique |
| `statut_operationnel` | enum | actif/inactif/maintenance/hors_service |
| `proprietes_specifiques` | json | Propriétés spécifiques |
| `notes` | text | Notes |

---

## 🏷️ **Référentiels**

### product_vendors

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `nom` | varchar | Nom affiché |
| `nvd_vendor` | varchar | Vendor NVD (lowercase) |
| `description` | text | Description |

### product_models

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `vendor_id` | int FK | → product_vendors.id |
| `nom` | varchar | Nom affiché |
| `nvd_product` | varchar | Product NVD |
| `cpe_part` | varchar | Partie CPE |
| `type_produit` | varchar | Type de produit |
| `cpe_base` | varchar | CPE base |

### os_versions

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `vendor_id` | int FK | → product_vendors.id |
| `nom` | varchar | Nom affiché |
| `nvd_vendor` | varchar | Vendor NVD |
| `nvd_product` | varchar | Product NVD |
| `version` | varchar | Version |
| `type_os` | enum | os/firmware/bios |

### equipment_types

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `nom` | varchar | Nom du type |
| `description` | text | Description |
| `vendor_source` | enum | os_fk/fw_fk/materiel/detection_auto |
| `options` | json | Options spécifiques |

---

## 🔍 **CVE & Corrélations**

### cve

| Colonne | Type | Description |
|---------|------|-------------|
| `cve_id` | varchar PK | ID CVE (ex: CVE-2024-1234) |
| `description` | text | Description |
| `cvss_v3_score` | float | Score CVSS v3 |
| `cvss_v3_vector` | varchar | Vecteur CVSS |
| `cvss_v3_severity` | varchar | Sévérité |
| `published_date` | date | Date de publication |
| `last_modified` | date | Dernière modification |

### correlations

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `asset_id` | int FK | → assets.id (CASCADE) |
| `cve_id` | varchar FK | → cve.cve_id (CASCADE) |
| `score_pre_triage` | float | Score avant analyse |
| `score_final` | float | Score après analyse |
| `verdict` | enum | confirme/infirme/informatif/mitige |
| `raison` | text | Raison du verdict |
| `analyse_mistral` | text | Analyse Mistral AI |
| `statut` | enum | nouveau/a_analyser/analyse_en_cours/termine |
| `date_correlation` | timestamp | Date de corrélation |

**Clé unique** : `(asset_id, cve_id)` - Une CVE ne peut être corrélée qu'une fois par asset.

### correlation_rejects

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `asset_id` | int | Asset concerné |
| `cve_id` | varchar | CVE rejetée |
| `raison` | text | Raison du rejet |
| `date_rejet` | timestamp | Date du rejet |

---

## 📦 **Autres tables**

### asset_software

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `asset_id` | int FK | → assets.id (CASCADE) |
| `nom` | varchar | Nom du logiciel |
| `version` | varchar | Version |
| `editeur` | varchar | Éditeur |

### cwe

| Colonne | Type | Description |
|---------|------|-------------|
| `cwe_id` | varchar PK | ID CWE |
| `nom` | varchar | Nom |
| `description` | text | Description |

### cve_cwe

| Colonne | Type | Description |
|---------|------|-------------|
| `cve_id` | varchar FK | → cve.cve_id |
| `cwe_id` | varchar FK | → cwe.cwe_id |

### historique_analyses

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `date_debut` | timestamp | Début de l'analyse |
| `date_fin` | timestamp | Fin de l'analyse |
| `assets_analyses` | int | Nombre d'assets analysés |
| `correlations_trouvees` | int | Corrélations trouvées |
| `correlations_analysees` | int | Corrélations analysées |
| `statut` | enum | en_cours/termine/erreur |

### utilisateurs

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int PK | Identifiant |
| `nom` | varchar | Nom d'utilisateur |
| `email` | varchar | Email |
| `mot_de_passe_hash` | varchar | Mot de passe haché |
| `role` | enum | admin/operateur/lecture_seule |
| `actif` | bool | 1 = actif |
