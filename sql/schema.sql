/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.11.13-MariaDB, for debian-linux-gnu (aarch64)
--
-- Host: localhost    Database: asset_vuln_manager
-- ------------------------------------------------------
-- Server version	10.11.13-MariaDB-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

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
  `nom_interne` varchar(255) NOT NULL,
  `type_equipement` enum('serveur','pc','laptop','switch','nas','raspberry_pi','lecteur_biometrique','camera_axis','camera_hikvision','ugl','utl','lecteur_cartes','routeur','pare_feu','imprimante','autre') NOT NULL,
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
  CONSTRAINT `assets_ibfk_1` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_assets_model` FOREIGN KEY (`model_id`) REFERENCES `product_models` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assets_vendor` FOREIGN KEY (`vendor_id`) REFERENCES `product_vendors` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
  `statut` enum('nouveau','en_analyse','confirme','faux_positif','mitige','patche') DEFAULT 'nouveau',
  `priorite` enum('critique','haute','moyenne','basse') DEFAULT NULL,
  `exploitable_air_gap` tinyint(1) DEFAULT NULL,
  `analyse_mistral` text DEFAULT NULL,
  `risque_reel` text DEFAULT NULL,
  `score_contextuel` decimal(3,1) DEFAULT NULL,
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
  CONSTRAINT `correlations_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `correlations_ibfk_2` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=88 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
  `source_url` varchar(500) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `cve_id` (`cve_id`),
  KEY `idx_cve_id` (`cve_id`),
  KEY `idx_fabricant_produit` (`fabricant`,`produit`),
  KEY `idx_severite` (`cvss_v3_severity`),
  KEY `idx_score` (`cvss_v3_score`)
) ENGINE=InnoDB AUTO_INCREMENT=22004 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
) ENGINE=InnoDB AUTO_INCREMENT=21980 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
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
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-04-27 12:12:08
