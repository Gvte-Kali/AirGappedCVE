---
title: Tables
parent: Base de données
nav_order: 2
---

# Tables
{: .no_toc }

<details open markdown="block">
<summary>Table des matières</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## clients

Organisations dont le prestataire gère les équipements.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `nom` | varchar(255) NOT NULL | Nom de l'organisation |
| `contact_nom` | varchar(255) | Nom du contact principal |
| `contact_email` | varchar(255) | Email du contact |
| `contact_telephone` | varchar(50) | Téléphone du contact |
| `adresse` | text | Adresse postale |
| `notes` | text | Notes libres |
| `actif` | tinyint(1) | 1 = actif, 0 = archivé |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de dernière modification |

---

## sites

Localisations physiques des équipements d'un client.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `client_id` | int NOT NULL | FK → `clients.id` (CASCADE) |
| `nom` | varchar(255) NOT NULL | Nom du site |
| `adresse` | text | Adresse postale |
| `ville` | varchar(100) | Ville |
| `code_postal` | varchar(20) | Code postal |
| `pays` | varchar(100) | Pays (défaut : France) |
| `contact_local_nom` | varchar(255) | Contact sur site |
| `contact_local_email` | varchar(255) | Email contact local |
| `contact_local_telephone` | varchar(50) | Téléphone contact local |
| `notes` | text | Notes libres |
| `actif` | tinyint(1) | 1 = actif, 0 = archivé |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de modification |

---

## assets

Équipements informatiques inventoriés. Table centrale du système.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `site_id` | int NOT NULL | FK → `sites.id` (CASCADE) |
| `vendor_id` | int | FK → `product_vendors.id` (SET NULL) |
| `model_id` | int | FK → `product_models.id` (SET NULL) |
| `os_version_id` | int | FK → `os_versions.id` — OS normalisé NVD (SET NULL) |
| `fw_version_id` | int | FK → `os_versions.id` — Firmware normalisé NVD (SET NULL) |
| `bios_version_id` | int | FK → `os_versions.id` — BIOS/UEFI normalisé NVD (SET NULL) |
| `nom_interne` | varchar(255) NOT NULL | Nom d'inventaire |
| `type_equipement` | enum | Type legacy (serveur, nas, pc…) — remplacé par `equipment_type_id` |
| `equipment_type_id` | int | FK → `equipment_types.id` — type normalisé (SET NULL) |
| `numero_serie` | varchar(255) | Numéro de série |
| `adresse_ip` | varchar(45) | Adresse IP (IPv4 ou IPv6) |
| `adresse_mac` | varchar(17) | Adresse MAC (format AA:BB:CC:DD:EE:FF) |
| `hostname` | varchar(255) | Nom d'hôte réseau |
| `systeme_exploitation` | varchar(255) | Nom OS texte libre (ex: "Windows Server") |
| `version_os` | varchar(100) | Version OS texte libre ou concaténée (ex: "DSM 7.2.2-72806") |
| `version_firmware` | varchar(100) | Version firmware texte libre |
| `version_bios` | varchar(100) | Version BIOS texte libre |
| `date_installation` | date | Date de mise en service |
| `date_fin_garantie` | date | Date de fin de garantie |
| `niveau_criticite` | enum | faible / moyen / eleve / critique |
| `statut_operationnel` | enum | actif / inactif / maintenance / hors_service |
| `proprietes_specifiques` | longtext JSON | Propriétés spécifiques au type d'équipement |
| `notes` | text | Notes libres |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de modification |

{: .note }
Les champs `version_os`, `version_firmware`, `version_bios` sont des champs texte libre utilisés quand la version exacte n'existe pas dans le référentiel `os_versions`. La corrélation sera alors en mode `informatif` au lieu d'`affirme`.

---

## asset_software

Logiciels installés sur un asset (fonctionnalité prévue, non exposée dans l'UI actuelle).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `asset_id` | int NOT NULL | FK → `assets.id` (CASCADE) |
| `nom` | varchar(255) NOT NULL | Nom du logiciel |
| `version` | varchar(100) | Version installée |
| `editeur` | varchar(255) | Éditeur |
| `cpe_string` | varchar(500) | CPE 2.3 si connu |
| `date_installation` | date | Date d'installation |
| `notes` | text | Notes libres |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de modification |

---

## product_vendors

Référentiel des fabricants, aligné sur la nomenclature NVD.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `nom` | varchar(255) NOT NULL | Nom affiché (ex: "Microsoft") |
| `nvd_vendor` | varchar(255) NOT NULL UNIQUE | Identifiant NVD exact en minuscules (ex: "microsoft") |
| `notes` | text | Notes libres |
| `created_at` | datetime | Horodatage de création |
| `updated_at` | datetime | Horodatage de modification |

{: .warning }
Le champ `nvd_vendor` doit correspondre exactement à l'identifiant utilisé dans le NVD. Une erreur d'orthographe empêchera toute corrélation CVE pour ce fabricant.

---

## product_models

Référentiel des modèles produits, aligné sur la nomenclature NVD.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `vendor_id` | int NOT NULL | FK → `product_vendors.id` |
| `nom` | varchar(255) NOT NULL | Nom affiché (ex: "Windows 11") |
| `nvd_product` | varchar(255) NOT NULL | Identifiant NVD exact (ex: "windows_11") |
| `cpe_part` | char(1) | Type CPE : `a`=application, `o`=OS, `h`=hardware |
| `type_produit` | enum | os / firmware / application / hardware |
| `cpe_base` | varchar(500) | CPE de base sans version (ex: `cpe:2.3:o:microsoft:windows_11`) |
| `notes` | text | Notes libres |
| `created_at` | datetime | Horodatage de création |
| `updated_at` | datetime | Horodatage de modification |

Contrainte d'unicité : `(vendor_id, nvd_product)`.

---

## os_versions

Référentiel des OS, firmwares et BIOS normalisés NVD. Utilisé pour la corrélation CVE précise.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `os_nom` | varchar(255) NOT NULL | Nom affiché (ex: "Windows Server", "DSM") |
| `version` | varchar(100) | Version affichée (ex: "2022", "7.1.1") |
| `nvd_vendor` | varchar(255) NOT NULL | Vendor NVD exact (ex: "microsoft") |
| `nvd_product` | varchar(255) NOT NULL | Produit NVD exact (ex: "windows_server_2022") |
| `type_produit` | enum | os / firmware / bios |
| `created_at` | timestamp | Horodatage de création |

Contrainte d'unicité : `(nvd_vendor, nvd_product)`.

{: .note }
**Bloc F (à venir)** — deux colonnes seront ajoutées : `format_version VARCHAR(255)` (format attendu, ex: `X.X.X-XXXXX`) et `ou_trouver VARCHAR(500)` (où trouver la version sur l'équipement). Ces colonnes alimenteront un guide de saisie dans l'interface.

---

## equipment_types

Configure le comportement du moteur de corrélation par type d'équipement.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `code` | varchar(50) NOT NULL UNIQUE | Identifiant technique (ex: "serveur", "nas") |
| `label` | varchar(100) NOT NULL | Nom affiché (ex: "Serveur", "NAS") |
| `use_os_version` | tinyint(1) | 1 = utiliser `os_version_id` pour la corrélation |
| `use_version_os` | tinyint(1) | 1 = utiliser `version_os` texte pour affiner |
| `use_version_firmware` | tinyint(1) | 1 = utiliser `fw_version_id` pour la corrélation |
| `use_version_bios` | tinyint(1) | 1 = utiliser `bios_version_id` pour la corrélation |
| `vendor_source` | enum | Source du vendor NVD : `os_fk` / `fw_fk` / `materiel` / `detection_auto` |
| `notes` | text | Notes libres |
| `created_at` | timestamp | Horodatage de création |
| `updated_at` | timestamp | Horodatage de modification |

Voir [Types d'équipements]({{ site.baseurl }}/referentiels/equipment-types) pour le détail de chaque valeur de `vendor_source`.

---

## cve

Référentiel des CVE, alimenté depuis le NVD (National Vulnerability Database).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire interne |
| `cve_id` | varchar(20) NOT NULL UNIQUE | Identifiant CVE (ex: "CVE-2024-1234") |
| `description` | text | Description de la vulnérabilité |
| `cvss_v2_score` | decimal(3,1) | Score CVSS v2 |
| `cvss_v2_vector` | varchar(100) | Vecteur CVSS v2 |
| `cvss_v3_score` | decimal(3,1) | Score CVSS v3 (0.0 à 10.0) |
| `cvss_v3_vector` | varchar(100) | Vecteur CVSS v3 (ex: `CVSS:3.1/AV:N/AC:L/...`) |
| `cvss_v3_severity` | enum | CRITICAL / HIGH / MEDIUM / LOW / NONE |
| `fabricant` | varchar(255) | Vendor NVD (ex: "microsoft") |
| `produit` | varchar(255) | Produit NVD (ex: "windows_server_2022") |
| `versions_affectees` | longtext JSON | Plages de versions vulnérables |
| `cpe_affected` | longtext JSON | CPE affectés |
| `date_publication` | date | Date de publication NVD |
| `date_modification` | date | Date de dernière modification NVD |
| `source_url` | text | URL NVD |
| `created_at` | datetime | Horodatage d'import |
| `updated_at` | timestamp | Horodatage de mise à jour |

### Structure de `versions_affectees`

```json
[
  {
    "cpe": "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
    "vendor": "synology",
    "product": "diskstation_manager",
    "version_exact": null,
    "version_start_including": null,
    "version_start_excluding": null,
    "version_end_including": null,
    "version_end_excluding": "7.1.1-42962-2"
  }
]
```

| Champ | Signification |
|-------|---------------|
| `version_exact` | Version exacte affectée. `-` = version de base (wildcard Microsoft/NVD) |
| `version_start_including` | Début de plage inclus (≥) |
| `version_start_excluding` | Début de plage exclu (>) |
| `version_end_including` | Fin de plage inclus (≤) |
| `version_end_excluding` | Fin de plage exclu (<) |

---

## cwe

Référentiel des CWE (Common Weakness Enumeration).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `cwe_id` | varchar(20) NOT NULL UNIQUE | Identifiant CWE (ex: "CWE-79") |
| `nom` | varchar(500) | Nom court |
| `description` | text | Description |
| `description_etendue` | longtext | Description étendue |
| `consequences` | text | Conséquences possibles |
| `methodes_detection` | text | Méthodes de détection |
| `remediations` | text | Remédiations recommandées |
| `cwe_parent` | varchar(20) | CWE parent dans la hiérarchie |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de modification |

---

## cve_cwe

Table de liaison entre CVE et CWE (relation N:N).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `cve_id` | varchar(20) NOT NULL | Identifiant CVE |
| `cwe_id` | varchar(20) NOT NULL | Identifiant CWE |

Contrainte d'unicité : `(cve_id, cwe_id)`.

---

## correlations

Table centrale du moteur de corrélation. Contient toutes les associations CVE↔Asset détectées.

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `asset_id` | int NOT NULL | FK → `assets.id` (CASCADE) |
| `cve_id` | varchar(20) NOT NULL | FK → `cve.cve_id` (CASCADE) |
| `type_correlation` | enum | `affirme` = version confirmée vulnérable / `informatif` = candidat à valider |
| `override_utilisateur` | enum | Décision manuelle : `a_patcher` / `informatif` / `faux_positif` |
| `statut` | enum | nouveau / en_analyse / confirme / informatif / faux_positif / mitige / patche |
| `priorite` | enum | critique / haute / moyenne / basse (après Mistral) |
| `exploitable_air_gap` | tinyint(1) | 1 = exploitable malgré l'isolation réseau |
| `analyse_mistral` | text | Analyse textuelle de Mistral |
| `risque_reel` | text | Recommandation d'action de Mistral |
| `score_contextuel` | decimal(3,1) | Score final après ajustement Mistral (0-10) |
| `score_pre_triage` | decimal(3,1) | Score calculé avant Mistral (0-10) |
| `priorite_pre_triage` | enum | Priorité calculée avant Mistral |
| `passe_correlation` | enum | Méthode de match : `cpe_full` / `vendor_product` / `vendor_only` / `os_textuel` |
| `type_attaque` | varchar(50) | Type classifié depuis `vuln_types.yml` |
| `passer_mistral` | tinyint(1) | 1 = envoyer à Mistral, 0 = ignorer |
| `date_detection` | timestamp | Date de détection par le moteur |
| `date_analyse` | timestamp | Date d'analyse Mistral |
| `date_resolution` | timestamp | Date de résolution |
| `notes` | text | Notes opérateur |
| `date_creation` | timestamp | Horodatage de création |
| `date_modification` | timestamp | Horodatage de modification |

Contrainte d'unicité : `(asset_id, cve_id)` — une CVE ne peut être corrélée qu'une fois par asset.

### Cycle de vie d'une corrélation

```
[Moteur corrélation]
        │
        ▼
   statut = nouveau
   type_correlation = affirme | informatif
   score_pre_triage calculé
        │
        ▼
[Analyse Mistral]
        │
        ▼
   statut = confirme | faux_positif | nouveau*
   score_contextuel ajusté
   exploitable_air_gap déterminé
        │
        ▼
[Opérateur]
        │
   override_utilisateur (optionnel)
        │
        ▼
   statut = patche | mitige | faux_positif
```

*Mistral verdict `informatif` → statut reste `nouveau` pour revue opérateur.

---

## correlation_rejects

Log des CVE rejetées par le moteur (debug des faux négatifs).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `asset_id` | int NOT NULL | Asset concerné |
| `cve_id` | varchar(20) NOT NULL | CVE rejetée |
| `raison` | enum | version_hors_range / cpe_no_match / cve_sans_score / fabricant_mismatch / autre |
| `details` | text | Détail de la règle de rejet |
| `asset_version` | varchar(100) | Version de l'asset au moment du rejet |
| `cve_versions` | text | Plages de versions CVE au moment du rejet |
| `date_rejet` | timestamp | Horodatage du rejet |

{: .note }
Cette table est utile pour diagnostiquer pourquoi une CVE attendue n'a pas été corrélée sur un asset donné.

---

## historique_analyses

Journal des exécutions du pipeline (sync CVE/CWE, corrélation, analyse Mistral).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `type_analyse` | enum | sync_cve / sync_cwe / correlation / analyse_mistral |
| `statut` | enum | succes / echec / partiel |
| `nb_elements_traites` | int | Nombre d'éléments traités |
| `nb_nouveaux` | int | Nouveaux éléments créés |
| `nb_mis_a_jour` | int | Éléments mis à jour |
| `duree_secondes` | int | Durée d'exécution |
| `message_erreur` | text | Message d'erreur si applicable |
| `details_json` | longtext JSON | Détails structurés de l'exécution |
| `date_execution` | timestamp | Horodatage d'exécution |

---

## utilisateurs

Table préparée pour une future authentification (non utilisée dans la version actuelle).

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | int AUTO_INCREMENT | Clé primaire |
| `username` | varchar(100) NOT NULL UNIQUE | Identifiant de connexion |
| `nom_complet` | varchar(255) | Nom complet |
| `email` | varchar(255) | Adresse email |
| `role` | enum | admin / analyste / lecteur |
| `actif` | tinyint(1) | 1 = compte actif |
| `date_creation` | timestamp | Horodatage de création |
| `derniere_connexion` | timestamp | Dernière connexion |
