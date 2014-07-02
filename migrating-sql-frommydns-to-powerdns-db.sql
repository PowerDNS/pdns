# Migrating MySQL Data from MyDNS to PowerDNS 
# 2014-07-02: Markus Neubauer
# GPLv3
# http://www.std-soft.com/index.php/hm-service/81-c-std-service-code/6-migration-mysql-daten-von-mydns-auf-powerdns-migrieren

# defines table domains
CREATE TABLE IF NOT EXISTS `domains` ( `id` int(11) NOT NULL AUTO_INCREMENT, `name` varchar(255) NOT NULL, `master` varchar(128) DEFAULT NULL, 
 `last_check` int(11) DEFAULT NULL, `type` varchar(6) NOT NULL, `notified_serial` int(11) DEFAULT NULL, `account` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `name_index` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=1;
# defines table records
CREATE TABLE IF NOT EXISTS `records` ( `id` int(11) NOT NULL AUTO_INCREMENT, `domain_id` int(11) DEFAULT NULL, `name` varchar(255) DEFAULT NULL,
  `type` varchar(10) DEFAULT NULL, `content` varchar(64000) DEFAULT NULL, `ttl` int(11) DEFAULT NULL, `prio` int(11) DEFAULT NULL,
  `change_date` int(11) DEFAULT NULL, `disabled` tinyint(1) DEFAULT '0', `ordername` varchar(255) DEFAULT NULL, `auth` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`), KEY `nametype_index` (`name`,`type`), KEY `recordorder` (`domain_id`,`ordername`), KEY `typename_index` (`type`,`name`)
) ENGINE=InnoDB AUTO_INCREMENT=1;
# clear from test data
TRUNCATE TABLE `domains`;
TRUNCATE TABLE `records`;

# make MyDNS tables consistent for migration
ALTER IGNORE TABLE `soa` ADD `active` enum('Y','N') NOT NULL DEFAULT 'Y';
ALTER IGNORE TABLE `soa` ADD `modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
ALTER IGNORE TABLE `rr` ADD `active` enum('Y','N') NOT NULL DEFAULT 'Y';
ALTER IGNORE TABLE `rr` ADD `modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

# import soa into table domains
INSERT INTO `domains` (id,name,type) (SELECT d.id, SUBSTR(d.origin,1, LENGTH(d.origin)-1), 'NATIVE' FROM `soa` as d)
# import soa records to table records
INSERT INTO `records` (domain_id,name,type,content,ttl,change_date,disabled) (select id,SUBSTR(origin,1, LENGTH(origin)-1),'SOA', CONCAT_WS(' ',SUBSTR(ns,1, LENGTH(ns)-1),serial,refresh,retry,expire,minimum),ttl,UNIX_TIMESTAMP(modified),REPLACE(active,'N','1') from soa)

# import rr records into table records
DROP TABLE IF EXISTS `temptab`;
CREATE TABLE IF NOT EXISTS `temptab` AS (SELECT zone,SUBSTR(name,1, LENGTH(name)-1),type,data,ttl,aux,UNIX_TIMESTAMP(modified),REPLACE(active,'N','1') FROM rr WHERE SUBSTR(name,-1)='.' AND (data LIKE '%.%' OR type='TXT' OR type='SRV') );
ALTER TABLE `temptab` CHANGE `SUBSTR(name,1, LENGTH(name)-1)` `name` VARCHAR( 64 ) NOT NULL DEFAULT '';
ALTER TABLE `temptab` CHANGE `type` `type` VARCHAR( 12 ) NULL DEFAULT '''A''';
ALTER TABLE `temptab` CHANGE `UNIX_TIMESTAMP(modified)` `change_date` INT( 10 ) NOT NULL DEFAULT '0';
ALTER TABLE `temptab` CHANGE `REPLACE(active,'N','1')` `disabled` TINYINT( 1 ) NOT NULL DEFAULT '0';
ALTER TABLE `temptab` CHANGE `aux` `prio` INT( 10 ) UNSIGNED NULL;
INSERT INTO `temptab` (SELECT r.zone,SUBSTR(r.name,1, LENGTH(r.name)-1),r.type,CONCAT(r.data,'.',d.name),r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains as d ON r.zone=d.id WHERE SUBSTR(r.name,-1)='.' AND (r.data NOT LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
INSERT INTO `temptab` (SELECT r.zone,CONCAT(r.name,'.',d.name),r.type,r.data,r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains AS d ON r.zone=d.id WHERE SUBSTR(r.name,-1)!='.' AND (r.data LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
INSERT INTO `temptab` (SELECT r.zone,CONCAT(r.name,'.',d.name),r.type,CONCAT(r.data,'.',d.name),r.ttl,r.aux,UNIX_TIMESTAMP(r.modified),REPLACE(r.active,'N','1') FROM rr AS r JOIN domains AS d ON r.zone=d.id WHERE SUBSTR(r.name,-1)!='.' AND (r.data NOT LIKE '%.%' AND r.type!='TXT' AND r.type!='SRV') );
UPDATE `temptab` SET data=SUBSTR(data,1,LENGTH(data)-1) WHERE SUBSTR(data,-1)='.';
UPDATE `temptab` SET name=SUBSTR(name,2) WHERE SUBSTR(name,1,1)='.';
UPDATE `temptab` SET prio=null WHERE prio=0;
# create the new spf records
DROP TABLE IF EXISTS `tempspf`;
CREATE TABLE IF NOT EXISTS `tempspf` AS (SELECT * FROM temptab WHERE type='TXT' AND data LIKE 'v=spf%');
UPDATE `tempspf` SET TYPE='SPF', data=CONCAT('"',data,'"');
INSERT INTO `temptab` (SELECT * FROM `tempspf`);
# modify other text records
UPDATE `temptab` set data=CONCAT('"',data,'"') WHERE type='SRV' OR type='TXT' ;
# setup the records table
INSERT INTO `records` (domain_id,name,type,content,ttl,prio,change_date,disabled) (select * from `temptab`);
# clean up
DROP TABLE `tempspf`;
DROP TABLE `temptab`;
# restart both PowerDNS Servers - DONE!
