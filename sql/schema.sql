/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.8.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: 127.0.0.1    Database: asset_vuln_manager
-- ------------------------------------------------------
-- Server version	10.11.16-MariaDB-ubu2204

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `asset_software`
--

DROP TABLE IF EXISTS `asset_software`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `assets`
--

DROP TABLE IF EXISTS `assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `assets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `site_id` int(11) NOT NULL,
  `vendor_id` int(11) DEFAULT NULL,
  `model_id` int(11) DEFAULT NULL,
  `os_version_id` int(11) DEFAULT NULL COMMENT 'FK os_versions — OS installé (nvd_product exact)',
  `fw_version_id` int(11) DEFAULT NULL COMMENT 'FK os_versions — Firmware installé (nvd_product exact)',
  `bios_version_id` int(11) DEFAULT NULL COMMENT 'FK os_versions — BIOS/UEFI (nvd_product exact)',
  `nom_interne` varchar(255) NOT NULL,
  `type_equipement` enum('serveur','pc','laptop','switch','nas','raspberry_pi','lecteur_biometrique','camera_axis','camera_hikvision','ugl','utl','lecteur_cartes','routeur','pare_feu','imprimante','autre') NOT NULL,
  `equipment_type_id` int(11) DEFAULT NULL COMMENT 'FK equipment_types — remplace type_equipement ENUM',
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
  `niveau_criticite` enum('faible','moyen','eleve','critique') DEFAULT 'moyen',
  `statut_operationnel` enum('actif','inactif','maintenance','hors_service') DEFAULT 'actif',
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
  KEY `fk_assets_os_version` (`os_version_id`),
  KEY `fk_assets_fw_version` (`fw_version_id`),
  KEY `fk_assets_bios_version` (`bios_version_id`),
  KEY `fk_assets_equipment_type` (`equipment_type_id`),
  CONSTRAINT `assets_ibfk_1` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_assets_bios_version` FOREIGN KEY (`bios_version_id`) REFERENCES `os_versions` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_equipment_type` FOREIGN KEY (`equipment_type_id`) REFERENCES `equipment_types` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_fw_version` FOREIGN KEY (`fw_version_id`) REFERENCES `os_versions` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_model` FOREIGN KEY (`model_id`) REFERENCES `product_models` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_os_version` FOREIGN KEY (`os_version_id`) REFERENCES `os_versions` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_vendor` FOREIGN KEY (`vendor_id`) REFERENCES `product_vendors` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `clients`
--

DROP TABLE IF EXISTS `clients`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlation_rejects`
--

DROP TABLE IF EXISTS `correlation_rejects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlation_rejects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `asset_id` int(11) NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `raison` enum('version_hors_range','cpe_no_match','cve_sans_score','fabricant_mismatch','autre') NOT NULL,
  `details` text DEFAULT NULL COMMENT 'Détails de la règle qui a rejeté',
  `asset_version` varchar(100) DEFAULT NULL,
  `cve_versions` text DEFAULT NULL COMMENT 'Range de versions de la CVE au moment du rejet',
  `date_rejet` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_asset` (`asset_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_raison` (`raison`),
  KEY `idx_date` (`date_rejet`)
) ENGINE=InnoDB AUTO_INCREMENT=147 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlations`
--

DROP TABLE IF EXISTS `correlations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `asset_id` int(11) NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `type_correlation` enum('affirme','informatif') NOT NULL DEFAULT 'informatif',
  `override_utilisateur` enum('a_patcher','informatif','faux_positif') DEFAULT NULL,
  `statut` enum('nouveau','en_analyse','confirme','faux_positif','patche') DEFAULT 'nouveau',
  `priorite` enum('critique','haute','moyenne','basse') DEFAULT NULL,
  `exploitable_air_gap` tinyint(1) DEFAULT NULL,
  `analyse_mistral` text DEFAULT NULL,
  `risque_reel` text DEFAULT NULL,
  `score_contextuel` decimal(3,1) DEFAULT NULL,
  `score_pre_triage` decimal(3,1) DEFAULT NULL COMMENT 'Score 0-10 calculé localement avant Mistral',
  `priorite_pre_triage` enum('critique','haute','moyenne','basse') DEFAULT NULL COMMENT 'Priorité calculée localement avant Mistral',
  `passe_correlation` enum('cpe_full','vendor_product','vendor_only','os_textuel') DEFAULT NULL COMMENT 'Méthode de match qui a généré cette corrélation',
  `type_attaque` varchar(50) DEFAULT 'Unknown' COMMENT 'Type classifié depuis vuln_types.yml',
  `passer_mistral` tinyint(1) DEFAULT 1 COMMENT '1 = envoyer à Mistral, 0 = ignorer (non pertinent air-gap)',
  `date_detection` timestamp NULL DEFAULT current_timestamp(),
  `date_analyse` timestamp NULL DEFAULT NULL,
  `date_resolution` timestamp NULL DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `date_modification` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_asset_cve` (`asset_id`,`cve_id`),
  KEY `idx_asset` (`asset_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_statut` (`statut`),
  KEY `idx_priorite` (`priorite`),
  KEY `idx_priorite_pre_triage` (`priorite_pre_triage`),
  KEY `idx_passe_correlation` (`passe_correlation`),
  KEY `idx_type_attaque` (`type_attaque`),
  KEY `idx_passer_mistral` (`passer_mistral`),
  KEY `idx_correlations_cve_id` (`cve_id`),
  CONSTRAINT `correlations_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `correlations_ibfk_2` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cve`
--

DROP TABLE IF EXISTS `cve`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cve` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `description` text DEFAULT NULL,
  `cvss_v2_score` decimal(3,1) DEFAULT NULL,
  `cvss_v2_vector` varchar(100) DEFAULT NULL,
  `cvss_v3_score` decimal(3,1) DEFAULT NULL,
  `cvss_v3_vector` varchar(100) DEFAULT NULL,
  `cvss_v3_severity` enum('CRITICAL','HIGH','MEDIUM','LOW','NONE') DEFAULT NULL,
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
  KEY `idx_fabricant_produit` (`fabricant`,`produit`),
  KEY `idx_severite` (`cvss_v3_severity`),
  KEY `idx_score` (`cvss_v3_score`),
  KEY `idx_corr_filter` (`fabricant`,`cvss_v3_score`,`date_publication`),
  KEY `idx_cve_fabricant` (`fabricant`),
  KEY `idx_cve_cve_id` (`cve_id`),
  KEY `idx_cve_date_publication` (`date_publication`)
) ENGINE=InnoDB AUTO_INCREMENT=1522142 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cve_cwe`
--

DROP TABLE IF EXISTS `cve_cwe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cve_cwe` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `cwe_id` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_cve_cwe` (`cve_id`,`cwe_id`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_cwe` (`cwe_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1578864 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cwe`
--

DROP TABLE IF EXISTS `cwe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `equipment_types`
--

DROP TABLE IF EXISTS `equipment_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `equipment_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code` varchar(50) NOT NULL COMMENT 'Identifiant technique : serveur, nas, camera_ptz...',
  `label` varchar(100) NOT NULL COMMENT 'Nom affiché : Serveur, NAS, Caméra PTZ...',
  `use_os_version` tinyint(1) DEFAULT 0 COMMENT 'Comparer os_version_id aux CVE',
  `use_version_os` tinyint(1) DEFAULT 0 COMMENT 'Comparer version_os texte aux CVE',
  `use_version_firmware` tinyint(1) DEFAULT 0 COMMENT 'Comparer fw_version_id aux CVE',
  `use_version_bios` tinyint(1) DEFAULT 0 COMMENT 'Comparer bios_version_id aux CVE',
  `vendor_source` enum('os_fk','fw_fk','materiel','detection_auto') DEFAULT 'materiel' COMMENT 'os_fk=vendor depuis os_version, fw_fk=depuis fw_version, materiel=vendor asset, detection_auto=fallback',
  `notes` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_code` (`code`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `historique_analyses`
--

DROP TABLE IF EXISTS `historique_analyses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `historique_analyses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type_analyse` enum('sync_cve','sync_cwe','correlation','analyse_mistral') NOT NULL,
  `statut` enum('succes','echec','partiel') NOT NULL,
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_versions`
--

DROP TABLE IF EXISTS `os_versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_versions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `os_nom` varchar(255) NOT NULL COMMENT 'Nom affiché : "Windows Server", "DSM", "FortiOS"',
  `version` varchar(100) DEFAULT NULL COMMENT 'Version affichée : "2022", "24H2", "9.1.2"',
  `nvd_vendor` varchar(255) NOT NULL COMMENT 'Vendor NVD exact : "microsoft", "synology"',
  `nvd_product` varchar(255) NOT NULL COMMENT 'Produit NVD exact : "windows_server_2022"',
  `type_produit` enum('os','firmware','bios') DEFAULT 'os',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `nvd_vendor` (`nvd_vendor`,`nvd_product`,`version`),
  KEY `idx_os_nom` (`os_nom`),
  KEY `idx_nvd_vendor` (`nvd_vendor`),
  KEY `idx_type_produit` (`type_produit`)
) ENGINE=InnoDB AUTO_INCREMENT=46890 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `product_models`
--

DROP TABLE IF EXISTS `product_models`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `product_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor_id` int(11) NOT NULL,
  `nom` varchar(255) NOT NULL COMMENT 'Nom affiché : "Windows 11", "DSM", "FortiOS"',
  `nvd_product` varchar(255) NOT NULL COMMENT 'Nom NVD lowercase : "windows_11", "diskstation_manager"',
  `cpe_part` char(1) DEFAULT 'a' COMMENT 'a=application, o=os, h=hardware',
  `type_produit` enum('os','firmware','application','hardware') DEFAULT 'os' COMMENT 'Catégorie du produit',
  `cpe_base` varchar(500) DEFAULT NULL COMMENT 'CPE de base sans version : cpe:2.3:o:microsoft:windows_11',
  `notes` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_vendor_product` (`vendor_id`,`nvd_product`),
  CONSTRAINT `product_models_ibfk_1` FOREIGN KEY (`vendor_id`) REFERENCES `product_vendors` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1022278 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `product_vendors`
--

DROP TABLE IF EXISTS `product_vendors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `product_vendors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(255) NOT NULL COMMENT 'Nom affiché : "Microsoft", "Synology"',
  `nvd_vendor` varchar(255) NOT NULL COMMENT 'Nom NVD lowercase : "microsoft", "synology"',
  `notes` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_nvd_vendor` (`nvd_vendor`)
) ENGINE=InnoDB AUTO_INCREMENT=363221 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sites`
--

DROP TABLE IF EXISTS `sites`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `utilisateurs`
--

DROP TABLE IF EXISTS `utilisateurs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `utilisateurs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `nom_complet` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `role` enum('admin','analyste','lecteur') DEFAULT 'lecteur',
  `actif` tinyint(1) DEFAULT 1,
  `date_creation` timestamp NULL DEFAULT current_timestamp(),
  `derniere_connexion` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `idx_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Temporary table structure for view `v_assets`
--

DROP TABLE IF EXISTS `v_assets`;
/*!50001 DROP VIEW IF EXISTS `v_assets`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_assets` AS SELECT
 1 AS `Asset`,
  1 AS `Client`,
  1 AS `Site`,
  1 AS `Type`,
  1 AS `OS`,
  1 AS `VersionOS`,
  1 AS `IP`,
  1 AS `Criticite`,
  1 AS `Statut`,
  1 AS `Vulnerabilites` */;
SET character_set_client = @saved_cs_client;

--
-- Temporary table structure for view `v_clients`
--

DROP TABLE IF EXISTS `v_clients`;
/*!50001 DROP VIEW IF EXISTS `v_clients`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_clients` AS SELECT
 1 AS `Client`,
  1 AS `Contact`,
  1 AS `Email`,
  1 AS `Telephone`,
  1 AS `Sites`,
  1 AS `Assets` */;
SET character_set_client = @saved_cs_client;

--
-- Temporary table structure for view `v_fabricants`
--

DROP TABLE IF EXISTS `v_fabricants`;
/*!50001 DROP VIEW IF EXISTS `v_fabricants`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_fabricants` AS SELECT
 1 AS `Fabricant`,
  1 AS `IdentifiantNVD`,
  1 AS `Modeles`,
  1 AS `Assets` */;
SET character_set_client = @saved_cs_client;

--
-- Temporary table structure for view `v_modeles`
--

DROP TABLE IF EXISTS `v_modeles`;
/*!50001 DROP VIEW IF EXISTS `v_modeles`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_modeles` AS SELECT
 1 AS `Modele`,
  1 AS `IdentifiantNVD`,
  1 AS `Type`,
  1 AS `CPEPart`,
  1 AS `CPEBase`,
  1 AS `Fabricant`,
  1 AS `Assets` */;
SET character_set_client = @saved_cs_client;

--
-- Temporary table structure for view `v_sites`
--

DROP TABLE IF EXISTS `v_sites`;
/*!50001 DROP VIEW IF EXISTS `v_sites`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_sites` AS SELECT
 1 AS `Site`,
  1 AS `Client`,
  1 AS `Ville`,
  1 AS `CP`,
  1 AS `Pays`,
  1 AS `ContactLocal`,
  1 AS `Email`,
  1 AS `Assets` */;
SET character_set_client = @saved_cs_client;

--
-- Temporary table structure for view `v_vulnerabilites_tableau`
--

DROP TABLE IF EXISTS `v_vulnerabilites_tableau`;
/*!50001 DROP VIEW IF EXISTS `v_vulnerabilites_tableau`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `v_vulnerabilites_tableau` AS SELECT
 1 AS `correlation_id`,
  1 AS `cve_id`,
  1 AS `cvss_v3_score`,
  1 AS `cvss_v3_severity`,
  1 AS `score_pre_triage`,
  1 AS `priorite_pre_triage`,
  1 AS `score_final`,
  1 AS `priorite_finale`,
  1 AS `statut`,
  1 AS `type_correlation`,
  1 AS `passe_correlation`,
  1 AS `exploitable_air_gap`,
  1 AS `decision_patch`,
  1 AS `asset_id`,
  1 AS `asset_nom`,
  1 AS `type_equipement`,
  1 AS `systeme_exploitation`,
  1 AS `version_os`,
  1 AS `version_firmware`,
  1 AS `niveau_criticite`,
  1 AS `vendor_nom`,
  1 AS `nvd_vendor`,
  1 AS `model_nom`,
  1 AS `site_nom`,
  1 AS `client_nom`,
  1 AS `date_detection`,
  1 AS `date_analyse`,
  1 AS `date_resolution` */;
SET character_set_client = @saved_cs_client;

--
-- Dumping routines for database 'asset_vuln_manager'
--

--
-- Final view structure for view `v_assets`
--

/*!50001 DROP VIEW IF EXISTS `v_assets`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_assets` AS select `a`.`nom_interne` AS `Asset`,`c`.`nom` AS `Client`,`s`.`nom` AS `Site`,`a`.`type_equipement` AS `Type`,`a`.`systeme_exploitation` AS `OS`,`a`.`version_os` AS `VersionOS`,`a`.`adresse_ip` AS `IP`,`a`.`niveau_criticite` AS `Criticite`,`a`.`statut_operationnel` AS `Statut`,count(distinct `co`.`id`) AS `Vulnerabilites` from (((`assets` `a` join `sites` `s` on(`s`.`id` = `a`.`site_id`)) join `clients` `c` on(`c`.`id` = `s`.`client_id`)) left join `correlations` `co` on(`co`.`asset_id` = `a`.`id` and `co`.`statut` <> 'faux_positif')) group by `a`.`id` order by `c`.`nom`,`s`.`nom`,`a`.`nom_interne` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `v_clients`
--

/*!50001 DROP VIEW IF EXISTS `v_clients`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_clients` AS select `c`.`nom` AS `Client`,`c`.`contact_nom` AS `Contact`,`c`.`contact_email` AS `Email`,`c`.`contact_telephone` AS `Telephone`,count(distinct `s`.`id`) AS `Sites`,count(distinct `a`.`id`) AS `Assets` from ((`clients` `c` left join `sites` `s` on(`s`.`client_id` = `c`.`id`)) left join `assets` `a` on(`a`.`site_id` = `s`.`id`)) group by `c`.`id` order by `c`.`nom` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `v_fabricants`
--

/*!50001 DROP VIEW IF EXISTS `v_fabricants`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_fabricants` AS select `pv`.`nom` AS `Fabricant`,`pv`.`nvd_vendor` AS `IdentifiantNVD`,count(distinct `pm`.`id`) AS `Modeles`,count(distinct `a`.`id`) AS `Assets` from ((`product_vendors` `pv` left join `product_models` `pm` on(`pm`.`vendor_id` = `pv`.`id`)) left join `assets` `a` on(`a`.`vendor_id` = `pv`.`id`)) group by `pv`.`id` order by `pv`.`nom` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `v_modeles`
--

/*!50001 DROP VIEW IF EXISTS `v_modeles`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_modeles` AS select `pm`.`nom` AS `Modele`,`pm`.`nvd_product` AS `IdentifiantNVD`,`pm`.`type_produit` AS `Type`,`pm`.`cpe_part` AS `CPEPart`,`pm`.`cpe_base` AS `CPEBase`,`pv`.`nom` AS `Fabricant`,count(distinct `a`.`id`) AS `Assets` from ((`product_models` `pm` join `product_vendors` `pv` on(`pv`.`id` = `pm`.`vendor_id`)) left join `assets` `a` on(`a`.`model_id` = `pm`.`id`)) group by `pm`.`id` order by `pv`.`nom`,`pm`.`nom` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `v_sites`
--

/*!50001 DROP VIEW IF EXISTS `v_sites`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_sites` AS select `s`.`nom` AS `Site`,`c`.`nom` AS `Client`,`s`.`ville` AS `Ville`,`s`.`code_postal` AS `CP`,`s`.`pays` AS `Pays`,`s`.`contact_local_nom` AS `ContactLocal`,`s`.`contact_local_email` AS `Email`,count(distinct `a`.`id`) AS `Assets` from ((`sites` `s` join `clients` `c` on(`c`.`id` = `s`.`client_id`)) left join `assets` `a` on(`a`.`site_id` = `s`.`id`)) group by `s`.`id` order by `c`.`nom`,`s`.`nom` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;

--
-- Final view structure for view `v_vulnerabilites_tableau`
--

/*!50001 DROP VIEW IF EXISTS `v_vulnerabilites_tableau`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avea`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_vulnerabilites_tableau` AS select `co`.`id` AS `correlation_id`,`co`.`cve_id` AS `cve_id`,`cv`.`cvss_v3_score` AS `cvss_v3_score`,`cv`.`cvss_v3_severity` AS `cvss_v3_severity`,`co`.`score_pre_triage` AS `score_pre_triage`,`co`.`priorite_pre_triage` AS `priorite_pre_triage`,`co`.`score_contextuel` AS `score_final`,`co`.`priorite` AS `priorite_finale`,`co`.`statut` AS `statut`,`co`.`type_correlation` AS `type_correlation`,`co`.`passe_correlation` AS `passe_correlation`,`co`.`exploitable_air_gap` AS `exploitable_air_gap`,coalesce(`co`.`override_utilisateur`,`co`.`statut`) AS `decision_patch`,`a`.`id` AS `asset_id`,`a`.`nom_interne` AS `asset_nom`,`a`.`type_equipement` AS `type_equipement`,`a`.`systeme_exploitation` AS `systeme_exploitation`,`a`.`version_os` AS `version_os`,`a`.`version_firmware` AS `version_firmware`,`a`.`niveau_criticite` AS `niveau_criticite`,`pv`.`nom` AS `vendor_nom`,`pv`.`nvd_vendor` AS `nvd_vendor`,`pm`.`nom` AS `model_nom`,`s`.`nom` AS `site_nom`,`cl`.`nom` AS `client_nom`,`co`.`date_detection` AS `date_detection`,`co`.`date_analyse` AS `date_analyse`,`co`.`date_resolution` AS `date_resolution` from ((((((`correlations` `co` join `assets` `a` on(`a`.`id` = `co`.`asset_id`)) join `cve` `cv` on(`cv`.`cve_id` = `co`.`cve_id`)) join `product_vendors` `pv` on(`pv`.`id` = `a`.`vendor_id`)) left join `product_models` `pm` on(`pm`.`id` = `a`.`model_id`)) join `sites` `s` on(`s`.`id` = `a`.`site_id`)) join `clients` `cl` on(`cl`.`id` = `s`.`client_id`)) */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2026-06-10 13:54:41
