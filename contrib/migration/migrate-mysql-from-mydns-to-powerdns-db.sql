# Migrating MariaDB/MySQL Data from MyDNS to PowerDNS 
# 2014-07-02: Markus Neubauer
# Version: 0.95
# License: GPLv2
# http://www.std-soft.com/index.php/hm-service/81-c-std-service-code/6-migration-mysql-daten-von-mydns-auf-powerdns-migrieren
# You can skip STEP 1 and STEP 2, if your database is already prepared
# or alternate use "mysql --force < migrate-mysql-from-mydns-to-powerdns-db.sql" to ignore errors that might occur
# you should check your fields in domains and records in the later case and adjust the triggers if not consistent.

# STEP 1: make MyDNS tables consistent for migration
# you should skip this step if you have used the fields in the past
ALTER IGNORE TABLE `soa` ADD `active` enum('Y','N') NOT NULL DEFAULT 'Y';
ALTER IGNORE TABLE `rr`  ADD `active` enum('Y','N') NOT NULL DEFAULT 'Y';
ALTER IGNORE TABLE `soa` ADD `modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER IGNORE TABLE `rr`  ADD `modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

# STEP 2: defines table domains
# you should skip this step if your tables were created during installation
CREATE TABLE IF NOT EXISTS `domains` ( `id` int(11) NOT NULL AUTO_INCREMENT, `name` varchar(255) NOT NULL, `master` varchar(128) DEFAULT NULL, 
 `last_check` int(11) DEFAULT NULL, `type` varchar(6) NOT NULL, `notified_serial` int(11) DEFAULT NULL, `account` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `name_index` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=1;
# defines table records
CREATE TABLE IF NOT EXISTS `records` ( `id` int(11) NOT NULL AUTO_INCREMENT, `domain_id` int(11) DEFAULT NULL, `name` varchar(255) DEFAULT NULL,
  `type` varchar(10) DEFAULT NULL, `content` varchar(64000) DEFAULT NULL, `ttl` int(11) DEFAULT NULL, `prio` int(11) DEFAULT NULL,
  `change_date` int(11) DEFAULT NULL, `disabled` tinyint(1) DEFAULT '0', `ordername` varchar(255) DEFAULT NULL, `auth` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`), KEY `nametype_index` (`name`,`type`), KEY `recordorder` (`domain_id`,`ordername`,`prio`), KEY `domain_idtypename_index` (`domain_id`,`type`,`name`)
) ENGINE=InnoDB AUTO_INCREMENT=1;

# STEP 3: create tables for "version control/revision" records
# Unfortunately the field `disabled` is not honoured within pdns, despite the field is offered.
# Thus lets make at least a simple poor mans "version control". Create log tables and trigger the actions to record changes.
DROP TABLE IF EXISTS `domains_log`;
CREATE TABLE `domains_log` LIKE domains;
ALTER  TABLE `domains_log` CHANGE  `id`  `id` INT( 11  ) NOT NULL;
ALTER  TABLE `domains_log` DROP PRIMARY KEY;
ALTER  TABLE `domains_log` DROP INDEX `name_index`;
ALTER  TABLE `domains_log` ADD  `modified` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER  TABLE `domains_log` ADD  INDEX `id_modified` (`id`,`modified`);
# no trigger on INSERT used, this is not a backup!
# trigger a delete action
DROP TRIGGER IF EXISTS `domains_delete`;
DELIMITER //
CREATE TRIGGER `domains_delete` AFTER DELETE ON `domains` FOR EACH ROW  BEGIN
 INSERT INTO domains_log (id,name,master,last_check,type,notified_serial,account) VALUES(OLD.id,OLD.name,OLD.master,OLD.last_check,OLD.type,OLD.notified_serial,OLD.account);
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `domains_update`;
# trigger some changes, not all fields will be honoured on update
DELIMITER //
CREATE TRIGGER `domains_update` AFTER UPDATE ON `domains` FOR EACH ROW  BEGIN  
 IF ( NEW.name!=OLD.name OR NEW.master!=OLD.master OR NEW.type!=OLD.type OR NEW.account!=OLD.account ) THEN
  INSERT INTO domains_log (id,name,master,last_check,type,notified_serial,account) VALUES(OLD.id,OLD.name,OLD.master,OLD.last_check,OLD.type,OLD.notified_serial,OLD.account);
 END IF;
END
//
DELIMITER ;
# accordingly for records
DROP TABLE IF EXISTS `records_log`;
CREATE TABLE `records_log` LIKE records;
ALTER  TABLE `records_log` CHANGE  `id`  `id` INT( 11  ) NOT NULL;
ALTER  TABLE `records_log` DROP PRIMARY  KEY;
ALTER  TABLE `records_log` DROP INDEX `nametype_index`;
ALTER  TABLE `records_log` DROP INDEX `recordorder`;
ALTER  TABLE `records_log` DROP INDEX `domain_idtypename_index`;
ALTER  TABLE `records_log` ADD  `modified` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER  TABLE `records_log` ADD  INDEX `id_modified` (`id`,`modified`);
ALTER  TABLE `records_log` ADD  INDEX `domain_id_modified` (`domain_id`,`modified`);
# no trigger on INSERT used, this is not a backup!
# trigger a delete action
DROP TRIGGER IF EXISTS `records_delete`;
DELIMITER //
CREATE TRIGGER `records_delete` AFTER DELETE ON `records` FOR EACH ROW  BEGIN
 INSERT INTO records_log (id,domain_id,name,type,content,ttl,prio,change_date,disabled,ordername,auth) VALUES(OLD.id,OLD.domain_id,OLD.name,OLD.type,OLD.content,OLD.ttl,OLD.prio,OLD.change_date,OLD.disabled,OLD.ordername,OLD.auth);
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `records_update`;
# trigger some changes, not all fields will be honoured on update
DELIMITER //
CREATE TRIGGER `records_update` AFTER UPDATE ON `records` FOR EACH ROW  BEGIN  
 IF ( NEW.name!=OLD.name OR NEW.type!=OLD.type OR NEW.content!=OLD.content OR NEW.ttl!=OLD.ttl OR NEW.prio!=OLD.prio OR NEW.disabled!=OLD.disabled OR NEW.ordername!=OLD.ordername OR NEW.auth!=OLD.auth ) THEN
  INSERT INTO records_log (id,domain_id,name,type,content,ttl,prio,change_date,disabled,ordername,auth) VALUES(OLD.id,OLD.domain_id,OLD.name,OLD.type,OLD.content,OLD.ttl,OLD.prio,OLD.change_date,OLD.disabled,OLD.ordername,OLD.auth);
 END IF;
END
//
DELIMITER ;

# STEP 4: clear from test data
TRUNCATE TABLE `domains`;
TRUNCATE TABLE `records`;

# STEP 5: import soa into table domains
# You may want to change 'NATIVE' to 'MASTER', depending on your current setup. Leave 'NATIVE' if your previous setup has been a Master/Slave MySQl setup.
INSERT INTO `domains` (id,name,type) (SELECT d.id, SUBSTR(d.origin,1, LENGTH(d.origin)-1), 'NATIVE' FROM `soa` as d);
# import soa records to table records
INSERT INTO `records` (domain_id,name,type,content,ttl,change_date,disabled) (select id,SUBSTR(origin,1, LENGTH(origin)-1),'SOA', CONCAT_WS(' ',SUBSTR(ns,1, LENGTH(ns)-1),SUBSTR(mbox,1, LENGTH(mbox)-1),serial,refresh,retry,expire,minimum),ttl,UNIX_TIMESTAMP(modified),REPLACE(active,'N','1') from soa);
# inactive records are not supported within pdns
DELETE FROM `records` where disabled=1;

# STEP 6: prepare rr records for import into table records
DROP TABLE IF EXISTS `temptab`;
CREATE TABLE IF NOT EXISTS `temptab` AS (SELECT zone,SUBSTR(name,1, LENGTH(name)-1) AS name,type,data,ttl,aux AS prio,UNIX_TIMESTAMP(modified) AS change_date,REPLACE(active,'N','1') AS disabled FROM rr WHERE SUBSTR(name,-1)='.' AND (data LIKE '%.%' OR type='TXT' OR type='SRV') );
ALTER TABLE `temptab` CHANGE `type` `type` VARCHAR( 12 ) NULL DEFAULT '''A''';
ALTER TABLE `temptab` CHANGE `disabled` `disabled` TINYINT( 1 ) NOT NULL DEFAULT '0';
ALTER TABLE `temptab` CHANGE `prio` `prio` INT( 10 ) UNSIGNED NULL;
INSERT INTO `temptab` (SELECT r.zone,SUBSTR(r.name,1, LENGTH(r.name)-1),r.type,CONCAT(r.data,'.',d.name),r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains as d ON r.zone=d.id WHERE SUBSTR(r.name,-1)='.' AND (r.data NOT LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
INSERT INTO `temptab` (SELECT r.zone,CONCAT(r.name,'.',d.name),r.type,r.data,r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains AS d ON r.zone=d.id WHERE SUBSTR(r.name,-1)!='.' AND (r.data LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
INSERT INTO `temptab` (SELECT r.zone,CONCAT(r.name,'.',d.name),r.type,CONCAT(r.data,'.',d.name),r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains AS d ON r.zone=d.id WHERE SUBSTR(r.name,-1)!='.' AND (r.data NOT LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
UPDATE `temptab` SET data=SUBSTR(data,1,LENGTH(data)-1) WHERE SUBSTR(data,-1)='.';
UPDATE `temptab` SET name=SUBSTR(name,2) WHERE SUBSTR(name,1,1)='.';
UPDATE `temptab` SET prio=null WHERE prio=0 AND `type`!='MX' AND `type`!='SRV';
# reformat text records
UPDATE `temptab` SET data=CONCAT('"',data,'"') WHERE `type`='SRV' OR `type`='TXT';

# STEP 7: prepare the new spf records
# you may want to skip this step if you don't want SPF records in the new way RFC4408 (additionally to TXT)
DROP TABLE IF EXISTS `tempspf`;
CREATE TABLE IF NOT EXISTS `tempspf` AS (SELECT * FROM temptab WHERE type='TXT' AND data LIKE '"v=spf%');
UPDATE `tempspf` SET `type`='SPF';
# add the new spf records to prepared table
INSERT INTO `temptab` (SELECT * FROM `tempspf`);
DROP TABLE `tempspf`;

# STEP 8: import to the records table
INSERT INTO `records` (domain_id,name,type,content,ttl,prio,change_date,disabled) (SELECT * FROM `temptab`);

# STEP 9: add contraint to delete records on domains deletion
ALTER TABLE `records` ADD CONSTRAINT `records_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

# STEP 10: final clean up
DROP TABLE `temptab`;
# inactive records are not supported within pdns. Push trigger to store these in records_log
DELETE FROM `records` where disabled=1;
# a just in case: cleanup orphaned domains/records;
DELETE d FROM `domains` d LEFT JOIN `records` r ON r.domain_id=d.id WHERE r.domain_id IS NULL;
DELETE r FROM `records` r LEFT JOIN `domains` d ON d.id=r.domain_id WHERE d.id IS NULL;

# STEP 11: shut down MyDNS, change the port to 53 on PowerDNS and restart both PowerDNS Servers - DONE with DNS Server!

# STEP 12: if you are going to use poweradmin add domains to zones table
INSERT INTO zones (domain_id,owner,zone_templ_id) (SELECT id,1,1 FROM domains);
