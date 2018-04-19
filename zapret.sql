-- MySQL dump 10.13  Distrib 5.1.73, for redhat-linux-gnu (x86_64)
--
-- Host: localhost    Database: rkn1
-- ------------------------------------------------------
-- Server version	5.1.73

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `zap2_domains`
--

DROP TABLE IF EXISTS `zap2_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `domain` varchar(255) DEFAULT NULL,
  `domain_fixed` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `record_id_idx` (`record_id`)
) ENGINE=MyISAM AUTO_INCREMENT=68562 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_domains`
--

DROP TABLE IF EXISTS `zap2_ex_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_ips`
--

DROP TABLE IF EXISTS `zap2_ex_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_ips` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `ip` int(12) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_nets`
--

DROP TABLE IF EXISTS `zap2_ex_nets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_nets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `subnet` (`subnet`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ips`
--

DROP TABLE IF EXISTS `zap2_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ips` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `record_id` int(6) unsigned NOT NULL,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varbinary(16) DEFAULT NULL,
  `resolved` int(1) NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `record_id` (`record_id`)
) ENGINE=MyISAM AUTO_INCREMENT=258743 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_only_ips`
--

DROP TABLE IF EXISTS `zap2_only_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_only_ips` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `record_id` int(6) unsigned NOT NULL,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varbinary(16) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `record_id_idx` (`record_id`)
) ENGINE=MyISAM AUTO_INCREMENT=2658 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_records`
--

DROP TABLE IF EXISTS `zap2_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_records` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `decision_id` int(10) unsigned NOT NULL,
  `decision_date` varchar(50) DEFAULT NULL,
  `decision_num` varchar(50) DEFAULT NULL,
  `decision_org` varchar(50) DEFAULT NULL,
  `include_time` varchar(50) DEFAULT NULL,
  `entry_type` int(3) unsigned DEFAULT NULL,
  `hash` varchar(60) DEFAULT NULL,
  KEY `id` (`id`),
  KEY `decision_id` (`decision_id`)
) ENGINE=MyISAM AUTO_INCREMENT=124082 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_settings`
--

DROP TABLE IF EXISTS `zap2_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_settings` (
  `param` varchar(255) NOT NULL,
  `value` longtext NOT NULL,
  UNIQUE KEY `param` (`param`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_subnets`
--

DROP TABLE IF EXISTS `zap2_subnets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_subnets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `record_id_idx` (`record_id`)
) ENGINE=MyISAM AUTO_INCREMENT=68 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_urls`
--

DROP TABLE IF EXISTS `zap2_urls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_urls` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `url` text NOT NULL,
  `url_fixed` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `record_id_idx` (`record_id`)
) ENGINE=MyISAM AUTO_INCREMENT=59268 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-04-19 15:22:24
