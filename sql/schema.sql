-- ═══════════════════════════════════════════════════════════════════════
-- Asset & Vulnerability Manager — Schéma de base
-- MariaDB 10.11+
-- ═══════════════════════════════════════════════════════════════════════
/*!40101 SET NAMES utf8mb4 */
;
/*!40103 SET TIME_ZONE='+00:00' */
;
/*!40014 SET UNIQUE_CHECKS=0, FOREIGN_KEY_CHECKS=0 */
;
/*!40101 SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */
;
-- ─────────────────────────────────────────────────────────────────────
-- Référentiels métier : clients → sites → assets
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `clients`;
CREATE TABLE `clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(255) NOT NULL,
  `contact_nom` varchar(255) DEFAULT NULL,
  `contact_email` varchar(255) DEFAULT NULL,
  `contact_telephone` varchar(50) DEFAULT NULL,
  `adresse` text DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `actif` tinyint(1) DEFAULT 1,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_nom` (`nom`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
DROP TABLE IF EXISTS `sites`;
CREATE TABLE `sites` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` int(11) NOT NULL,
  `nom` varchar(255) NOT NULL,
  `adresse` text DEFAULT NULL,
  `ville` varchar(100) DEFAULT NULL,
  `code_postal` varchar(20) DEFAULT NULL,
  `pays` varchar(100) DEFAULT 'France',
  `contact_local_nom` varchar(255) DEFAULT NULL,
  `contact_local_email` varchar(255) DEFAULT NULL,
  `contact_local_telephone` varchar(50) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `actif` tinyint(1) DEFAULT 1,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_client` (`client_id`),
  KEY `idx_nom` (`nom`),
  CONSTRAINT `sites_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Référentiels produits : vendors et models (alignés sur le NVD)
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `product_vendors`;
CREATE TABLE `product_vendors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(255) NOT NULL COMMENT 'Nom affiché : "Microsoft", "Synology"',
  `nvd_vendor` varchar(255) NOT NULL COMMENT 'Nom NVD lowercase : "microsoft", "synology"',
  `notes` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_nvd_vendor` (`nvd_vendor`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
DROP TABLE IF EXISTS `product_models`;
CREATE TABLE `product_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor_id` int(11) NOT NULL,
  `nom` varchar(255) NOT NULL COMMENT 'Nom affiché : "Windows 11", "DSM", "FortiOS"',
  `nvd_product` varchar(255) NOT NULL COMMENT 'Nom NVD lowercase : "windows_11", "diskstation_manager"',
  `cpe_part` char(1) DEFAULT 'a' COMMENT 'a=application, o=os, h=hardware',
  `type_produit` enum('os', 'firmware', 'application', 'hardware') DEFAULT 'os' COMMENT 'Catégorie du produit',
  `cpe_base` varchar(500) DEFAULT NULL COMMENT 'CPE de base sans version : cpe:2.3:o:microsoft:windows_11',
  `notes` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_vendor_product` (`vendor_id`, `nvd_product`),
  CONSTRAINT `product_models_ibfk_1` FOREIGN KEY (`vendor_id`) REFERENCES `product_vendors` (`id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Assets et leurs logiciels installés
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `assets`;
CREATE TABLE `assets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `site_id` int(11) NOT NULL,
  `vendor_id` int(11) DEFAULT NULL,
  `model_id` int(11) DEFAULT NULL,
  `nom_interne` varchar(255) NOT NULL,
  `type_equipement` enum(
    'serveur',
    'pc',
    'laptop',
    'switch',
    'nas',
    'raspberry_pi',
    'lecteur_biometrique',
    'camera_axis',
    'camera_hikvision',
    'ugl',
    'utl',
    'lecteur_cartes',
    'routeur',
    'pare_feu',
    'imprimante',
    'autre'
  ) NOT NULL,
  `numero_serie` varchar(255) DEFAULT NULL,
  `adresse_ip` varchar(45) DEFAULT NULL,
  `adresse_mac` varchar(17) DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `systeme_exploitation` varchar(255) DEFAULT NULL,
  `version_os` varchar(100) DEFAULT NULL,
  `version_firmware` varchar(100) DEFAULT NULL,
  `version_bios` varchar(100) DEFAULT NULL,
  `date_installation` date DEFAULT NULL,
  `date_fin_garantie` date DEFAULT NULL,
  `niveau_criticite` enum('faible', 'moyen', 'eleve', 'critique') DEFAULT 'moyen',
  `statut_operationnel` enum(
    'actif',
    'inactif',
    'maintenance',
    'hors_service'
  ) DEFAULT 'actif',
  `proprietes_specifiques` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Propriétés spécifiques au type d équipement' CHECK (json_valid(`proprietes_specifiques`)),
  `notes` text DEFAULT NULL,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_site` (`site_id`),
  KEY `idx_type` (`type_equipement`),
  KEY `idx_ip` (`adresse_ip`),
  KEY `idx_criticite` (`niveau_criticite`),
  KEY `fk_assets_vendor` (`vendor_id`),
  KEY `fk_assets_model` (`model_id`),
  CONSTRAINT `assets_ibfk_1` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_assets_model` FOREIGN KEY (`model_id`) REFERENCES `product_models` (`id`) ON DELETE
  SET NULL,
    CONSTRAINT `fk_assets_vendor` FOREIGN KEY (`vendor_id`) REFERENCES `product_vendors` (`id`) ON DELETE
  SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
DROP TABLE IF EXISTS `asset_software`;
CREATE TABLE `asset_software` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `asset_id` int(11) NOT NULL,
  `nom` varchar(255) NOT NULL COMMENT 'Nom du logiciel',
  `version` varchar(100) DEFAULT NULL COMMENT 'Version installée',
  `editeur` varchar(255) DEFAULT NULL COMMENT 'Éditeur du logiciel',
  `cpe_string` varchar(500) DEFAULT NULL COMMENT 'CPE 2.3 si connu',
  `date_installation` date DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_asset` (`asset_id`),
  KEY `idx_nom` (`nom`),
  KEY `idx_editeur` (`editeur`),
  CONSTRAINT `asset_software_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Référentiels CVE / CWE (alimentés depuis le NVD)
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `cve`;
CREATE TABLE `cve` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `description` text DEFAULT NULL,
  `cvss_v2_score` decimal(3, 1) DEFAULT NULL,
  `cvss_v2_vector` varchar(100) DEFAULT NULL,
  `cvss_v3_score` decimal(3, 1) DEFAULT NULL,
  `cvss_v3_vector` varchar(100) DEFAULT NULL,
  `cvss_v3_severity` enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE') DEFAULT NULL,
  `fabricant` varchar(255) DEFAULT NULL,
  `produit` varchar(255) DEFAULT NULL,
  `versions_affectees` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`versions_affectees`)),
  `cpe_affected` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`cpe_affected`)),
  `date_publication` date DEFAULT NULL,
  `date_modification` date DEFAULT NULL,
  `source_url` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `cve_id` (`cve_id`),
  KEY `idx_cve_id` (`cve_id`),
  KEY `idx_fabricant_produit` (`fabricant`, `produit`),
  KEY `idx_severite` (`cvss_v3_severity`),
  KEY `idx_score` (`cvss_v3_score`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
DROP TABLE IF EXISTS `cwe`;
CREATE TABLE `cwe` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cwe_id` varchar(20) NOT NULL,
  `nom` varchar(500) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `description_etendue` longtext DEFAULT NULL,
  `consequences` text DEFAULT NULL,
  `methodes_detection` text DEFAULT NULL,
  `remediations` text DEFAULT NULL,
  `cwe_parent` varchar(20) DEFAULT NULL,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `cwe_id` (`cwe_id`),
  KEY `idx_cwe_id` (`cwe_id`),
  KEY `idx_parent` (`cwe_parent`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
DROP TABLE IF EXISTS `cve_cwe`;
CREATE TABLE `cve_cwe` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `cwe_id` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_cve_cwe` (`cve_id`, `cwe_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_cwe` (`cwe_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Corrélations CVE/Asset — cœur du moteur d'analyse
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `correlations`;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `asset_id` int(11) NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `type_correlation` enum('affirme', 'informatif') NOT NULL DEFAULT 'informatif' COMMENT 'affirme = version asset confirmée vulnérable | informatif = candidat à valider',
  `passe_correlation` enum(
    'cpe_full',
    'vendor_product',
    'vendor_only',
    'os_textuel'
  ) DEFAULT NULL COMMENT 'Méthode de match qui a généré cette corrélation',
  `override_utilisateur` enum('a_patcher', 'informatif', 'faux_positif') DEFAULT NULL COMMENT 'Décision manuelle qui prime sur le statut auto',
  `statut` enum(
    'nouveau',
    'en_analyse',
    'confirme',
    'informatif',
    'faux_positif',
    'mitige',
    'patche'
  ) DEFAULT 'nouveau' COMMENT 'confirme = à patcher | informatif = à surveiller | faux_positif = à ignorer',
  `priorite` enum('critique', 'haute', 'moyenne', 'basse') DEFAULT NULL COMMENT 'Priorité finale après analyse Mistral',
  `priorite_pre_triage` enum('critique', 'haute', 'moyenne', 'basse') DEFAULT NULL COMMENT 'Priorité calculée localement avant Mistral',
  `score_pre_triage` decimal(3, 1) DEFAULT NULL COMMENT 'Score 0-10 calculé localement avant Mistral',
  `score_contextuel` decimal(3, 1) DEFAULT NULL COMMENT 'Score final après ajustement Mistral',
  `exploitable_air_gap` tinyint(1) DEFAULT NULL,
  `analyse_mistral` text DEFAULT NULL,
  `risque_reel` text DEFAULT NULL,
  `date_detection` timestamp NULL DEFAULT current_timestamp(),
  `date_analyse` timestamp NULL DEFAULT NULL,
  `date_resolution` timestamp NULL DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_asset_cve` (`asset_id`, `cve_id`),
  KEY `idx_asset` (`asset_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_statut` (`statut`),
  KEY `idx_priorite` (`priorite`),
  KEY `idx_priorite_pre_triage` (`priorite_pre_triage`),
  KEY `idx_passe_correlation` (`passe_correlation`),
  CONSTRAINT `correlations_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `correlations_ibfk_2` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Log des rejets de corrélation (debug des faux négatifs)
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `correlation_rejects`;
CREATE TABLE `correlation_rejects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `asset_id` int(11) NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `raison` enum(
    'version_hors_range',
    'cpe_no_match',
    'cve_sans_score',
    'fabricant_mismatch',
    'autre'
  ) NOT NULL,
  `details` text DEFAULT NULL COMMENT 'Détails de la règle qui a rejeté',
  `asset_version` varchar(100) DEFAULT NULL,
  `cve_versions` text DEFAULT NULL COMMENT 'Range de versions de la CVE au moment du rejet',
  `date_rejet` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_asset` (`asset_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_raison` (`raison`),
  KEY `idx_date` (`date_rejet`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Historique des analyses (sync, corrélation, Mistral)
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `historique_analyses`;
CREATE TABLE `historique_analyses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type_analyse` enum(
    'sync_cve',
    'sync_cwe',
    'correlation',
    'analyse_mistral'
  ) NOT NULL,
  `statut` enum('succes', 'echec', 'partiel') NOT NULL,
  `nb_elements_traites` int(11) DEFAULT 0,
  `nb_nouveaux` int(11) DEFAULT 0,
  `nb_mis_a_jour` int(11) DEFAULT 0,
  `duree_secondes` int(11) DEFAULT NULL,
  `message_erreur` text DEFAULT NULL,
  `details_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`details_json`)),
  `date_execution` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_type` (`type_analyse`),
  KEY `idx_date` (`date_execution`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ─────────────────────────────────────────────────────────────────────
-- Utilisateurs (auth future)
-- ─────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `utilisateurs`;
CREATE TABLE `utilisateurs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `nom_complet` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `role` enum('admin', 'analyste', 'lecteur') DEFAULT 'lecteur',
  `actif` tinyint(1) DEFAULT 1,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `derniere_connexion` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `idx_username` (`username`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ═══════════════════════════════════════════════════════════════════════
-- Vues
-- ═══════════════════════════════════════════════════════════════════════
DROP VIEW IF EXISTS `v_vulnerabilites_tableau`;
CREATE VIEW `v_vulnerabilites_tableau` AS
SELECT co.id AS correlation_id,
  co.cve_id,
  cv.cvss_v3_score,
  cv.cvss_v3_severity,
  co.score_pre_triage,
  co.priorite_pre_triage,
  co.score_contextuel AS score_final,
  co.priorite AS priorite_finale,
  co.statut,
  co.type_correlation,
  co.passe_correlation,
  co.exploitable_air_gap,
  COALESCE(co.override_utilisateur, co.statut) AS decision_patch,
  a.id AS asset_id,
  a.nom_interne AS asset_nom,
  a.type_equipement,
  a.systeme_exploitation,
  a.version_os,
  a.version_firmware,
  a.niveau_criticite,
  pv.nom AS vendor_nom,
  pv.nvd_vendor,
  pm.nom AS model_nom,
  s.nom AS site_nom,
  cl.nom AS client_nom,
  co.date_detection,
  co.date_analyse,
  co.date_resolution
FROM correlations co
  JOIN assets a ON a.id = co.asset_id
  JOIN cve cv ON cv.cve_id = co.cve_id
  JOIN product_vendors pv ON pv.id = a.vendor_id
  LEFT JOIN product_models pm ON pm.id = a.model_id
  JOIN sites s ON s.id = a.site_id
  JOIN clients cl ON cl.id = s.client_id;
/*!40014 SET FOREIGN_KEY_CHECKS=1, UNIQUE_CHECKS=1 */
;